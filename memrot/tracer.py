"""Versioned phase journal (events.jsonl) and memory lifecycle trace (trace.jsonl).

Phase events are appended immediately; lifecycle events retain their existing
schema and buffering. Persistence failures are retained as coverage gaps.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import logging
import time
import uuid
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from memory_trace import TraceEvent as MemoryTraceEvent
from memory_trace.emitter import TraceEmitter
from memory_trace.redaction import Redactor

from . import ATTACK_SCHEMA_VERSION
from .models import plain

log = logging.getLogger(__name__)

MEMORY_TRACE_SCHEMA_VERSION = "0.1.0"
_ID_MAX_LENGTH = 128   # schema maxLength for run_id / trace_id / agent_id / component / session_id
_PREVIEW_LIMIT = 200   # leaves room for CANARY_<hash> tokens under the schema's 256


def _digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _fragment(text: str, limit: int = 300) -> str:
    s = text.replace("\r", " ").replace("\n", " / ")
    return s if len(s) <= limit else s[:limit] + "…"


def _bounded_id(value: Optional[str]) -> Optional[str]:
    if value is None or value == "":
        return None
    return str(value)[:_ID_MAX_LENGTH]


@dataclass
class TraceEvent:
    """Phase event retained in memory and persisted when a journal path is set."""

    event_id: str
    run_id: str
    trace_id: str                                    # groups events by variant (variant.id)
    schema_version: str = "phase-journal-1.0"
    attempt_id: Optional[str] = None
    parent_event_refs: List[str] = field(default_factory=list)
    component: str = "memrot.runner"
    ts: float = field(default_factory=time.time)
    config_version: str = ATTACK_SCHEMA_VERSION
    principal: Optional[str] = None
    phase: Optional[str] = None       # baseline | inject | consolidate | probe | memory_inspection | ground_truth | verdict | skip | error
    channel_id: Optional[str] = None
    session_id: Optional[str] = None
    direction: Optional[str] = None    # request | response | inspection | decision
    text_digest: Optional[str] = None
    text_fragment: Optional[str] = None
    canary: Optional[str] = None
    canary_present: Optional[bool] = None
    observation_available: Optional[bool] = None
    memory: Dict[str, Any] = field(default_factory=dict)
    tool: Dict[str, Any] = field(default_factory=dict)
    verdict: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return plain({f.name: getattr(self, f.name) for f in fields(self)})


class JSONLTracer:
    def __init__(self, path: Optional[str] = None, *, run_id: Optional[str] = None,
                 redactor: Optional[Redactor] = None, validate: bool = True) -> None:
        self.path = str(path) if path else (str(Path("runs") / run_id / "trace.jsonl") if run_id else None)
        self.events_path = str(Path(self.path).with_name("events.jsonl")) if self.path else None
        self.attempt_id: Optional[str] = None
        self.persistence_errors: List[str] = []
        self.persisted_event_ids: List[str] = []
        self._journal_failed = False
        self._lifecycle_failed = False
        self._canaries: set[str] = set()
        self.last_interrupted_result = None
        self.attempt_results = []
        self.events: List[TraceEvent] = []
        self.redactor = redactor if redactor is not None else Redactor()
        self.emitter = TraceEmitter(self.redactor, validate=validate, run_id=run_id)
        # lifecycle events that could not be emitted; tracing must never fail an attack
        self.lifecycle_errors: List[str] = []
        for destination in (self.path, self.events_path):
            if destination:
                try:
                    Path(destination).parent.mkdir(parents=True, exist_ok=True)
                    Path(destination).write_text("", encoding="utf-8")
                except OSError as exc:
                    self.persistence_errors.append(f"initialize {Path(destination).name}: {type(exc).__name__}")
                    if destination == self.events_path:
                        self._journal_failed = True
                    else:
                        self._lifecycle_failed = True

    def redact_document(self, value: Any, *, canaries=()) -> Any:
        """Sanitize full content before preview truncation or serialization."""
        if isinstance(value, str):
            for key, secret in os.environ.items():
                if key.startswith("MEMROT_CRED_") and secret:
                    value = value.replace(secret, "<REDACTED_SECRET>")
            try:
                return self.redactor.redact(value, canaries=list(canaries)).text
            except Exception as exc:
                self.persistence_errors.append(f"phase redaction: {type(exc).__name__}")
                return "<REDACTION_FAILED>"
        if isinstance(value, dict):
            return {key: self.redact_document(item, canaries=canaries) for key, item in value.items()}
        if isinstance(value, list):
            return [self.redact_document(item, canaries=canaries) for item in value]
        return value

    def coverage(self) -> Dict[str, Any]:
        errors = self.persistence_errors + self.lifecycle_errors
        return {"status": "incomplete" if errors else "complete" if self.events_path else "memory_only",
                "errors": list(errors), "phase_events": len(self.events),
                "phase_events_written": len(self.persisted_event_ids)}

    def update_report(self, report) -> None:
        if report.results:
            report.started_at = min(report.started_at, min(r.started_at for r in report.results))
        if report.finished_at is None:
            report.finished_at = time.time()
        report.events_path = self.events_path
        report.trace_coverage = self.coverage()

    def save_partial_report(self, report) -> None:
        if not self.events_path:
            return
        path = Path(self.events_path).with_name("run.partial.json")
        self.update_report(report)
        try:
            document = report.to_dict()
            # Only content is redacted: replacing a short marker in structural
            # IDs or schema versions would make evidence links unresolvable.
            document["limitations"] = self.redact_document(document["limitations"], canaries=self._canaries)
            for result in document["results"]:
                for key in ("error", "cleanup_error", "limitations", "inconclusive_reason", "canary"):
                    result[key] = self.redact_document(result[key], canaries=self._canaries)
                for key in ("baseline_detection", "post_detection", "state_detection", "ground_truth_detection"):
                    if result[key] is not None:
                        result[key]["detail"] = self.redact_document(result[key]["detail"], canaries=self._canaries)
            temporary = path.with_suffix(".tmp")
            temporary.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding="utf-8")
            temporary.replace(path)
        except OSError as exc:
            self.persistence_errors.append(f"partial report write: {type(exc).__name__}")
            self.update_report(report)

    @property
    def lifecycle_events(self) -> List[MemoryTraceEvent]:
        """Emitted lifecycle events not yet flushed to disk."""
        return self.emitter.buffer

    def log(self, *, run_id: str, trace_id: str, text: Optional[str] = None, **kwargs: Any) -> TraceEvent:
        canary = kwargs.get("canary")
        if canary:
            self._canaries.add(canary)
        # IDs and links remain stable; redact content-bearing fields only.
        for key in ("error", "memory", "tool", "canary"):
            if key in kwargs:
                kwargs[key] = self.redact_document(kwargs[key], canaries=self._canaries)
        safe_text = self.redact_document(text, canaries=self._canaries) if text is not None else None
        event = TraceEvent(
            attempt_id=self.attempt_id,
            event_id=f"evt-{uuid.uuid4().hex[:12]}",
            run_id=run_id,
            trace_id=trace_id,
            text_digest=_digest(text) if text is not None else None,
            text_fragment=_fragment(safe_text) if safe_text is not None else None,
            **kwargs,
        )
        self.events.append(event)
        if self.events_path and not self._journal_failed:
            try:
                with open(self.events_path, "a", encoding="utf-8") as stream:
                    stream.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                self.persisted_event_ids.append(event.event_id)
            except Exception as exc:
                self._journal_failed = True  # partial writes must not be retried as duplicates
                self.persistence_errors.append(f"phase journal write: {type(exc).__name__}")
        return event

    def lifecycle(self, *, run_id: str, trace_id: str, agent_id: str, stage: str, principal: str,
                  observed: bool, source: str, partial: bool = True,
                  text: Optional[str] = None, canary: Optional[str] = None,
                  parents: Iterable[MemoryTraceEvent] = (), session_id: Optional[str] = None,
                  component: str = "memrot.runner", **fields: Any) -> Optional[MemoryTraceEvent]:
        """Emit one memory-trace event; return it, or ``None`` if it was rejected.

        ``fields`` are passed straight to the memory-trace model
        (``operation``, ``memory_layer``, ``evidence_tier``, ...).
        """
        data: Dict[str, Any] = dict(
            schema_version=MEMORY_TRACE_SCHEMA_VERSION,
            event_id=uuid.uuid4(),
            run_id=_bounded_id(run_id),
            trace_id=_bounded_id(trace_id),
            agent_id=_bounded_id(agent_id) or "unknown",
            principal=principal,
            component=component,
            ts=datetime.now(timezone.utc),
            config_version=ATTACK_SCHEMA_VERSION,
            stage=stage,
            parent_event_refs=[p.event_id for p in parents if p is not None],
            coverage={"observed": observed, "source": source, "partial": partial},
            **fields,
        )
        if session_id is not None:
            data["session_id"] = _bounded_id(session_id)
        if text is not None:
            data.update(content_digest=_digest(text), content_length=len(text),
                        content_preview=_fragment(text, _PREVIEW_LIMIT))
        try:
            event = MemoryTraceEvent.model_validate(data)
            return self.emitter.emit(event, canaries=[canary] if canary else None)
        except Exception as exc:  # noqa: BLE001 -- a bad trace event must not turn a variant into ERROR
            message = f"lifecycle event dropped: {type(exc).__name__}"
            self.lifecycle_errors.append(message)
            log.warning(message)
            return None

    def flush(self) -> int:
        """Append buffered lifecycle events to ``path``; return how many were written.

        Without ``path`` (and without ``run_id`` for the emitter's default
        ``runs/<run_id>/trace.jsonl``) events stay in memory.
        """
        if self.path and not self._lifecycle_failed:
            try:
                return self.emitter.flush(self.path)
            except Exception as exc:
                self._lifecycle_failed = True
                self.persistence_errors.append(f"lifecycle flush: {type(exc).__name__}")
        return 0

    def close(self) -> None:
        self.flush()
