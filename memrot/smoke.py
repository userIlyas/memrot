"""Offline installation check: ``python -m memrot.smoke``.

Runs a bundled case against two deterministic in-memory targets. It never
discovers a live target, reads credentials, or invokes an external model.
"""
from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

import jsonschema

from mcp_audit.manifest import load_profile
from memrot_data import data_path
from memory_trace.redaction import MODE_BASIC, Redactor
from memory_trace.schema import validate_event

from .adapters.callable_adapter import CallableAdapter
from .catalog.loader import discover_catalog_files, load_catalog
from .catalog.schema import validate_catalog_file
from .detectors.literal import LiteralDetector
from .models import Channel, ChannelRole, Principal, Verdict
from .pipeline import ALL_CATALOG
from .reporting.emitter import emit_json, emit_markdown
from .reporting.html_emitter import emit_html
from .runner.engine import run_matrix
from .tracer import JSONLTracer


class _OfflineRedactor(Redactor):
    """Use built-in secret/canary redaction without discovering Presidio."""

    def _redact_pii(self, text, findings):
        return text, MODE_BASIC


class _MemoryTarget:
    """Synthetic target: optionally share consolidated text across users."""

    def __init__(self, persist: bool):
        self.persist = persist
        self.memory = ""
        self.messages: dict[str, list[str]] = {}

    def new_session(self, principal: str) -> str:
        session = f"{principal}-{len(self.messages)}"
        self.messages[session] = []
        return session

    def send(self, principal: str, session: str, message: str) -> str:
        self.messages[session].append(message)
        return self.memory or "No stored instruction."

    def consolidate(self, principal: str, session: str) -> None:
        if self.persist:
            self.memory = " ".join(self.messages[session])


def run_smoke() -> dict:
    files = discover_catalog_files([ALL_CATALOG])
    if not files:
        raise RuntimeError("installed catalog is empty")
    for path in files:
        errors = validate_catalog_file(path, require_taxonomy=True)
        if errors:
            raise RuntimeError(f"invalid catalog {path}: {errors}")
    for name in ("agent-security-audit-2.0.schema.json", "profile.schema.json",
                 "memory-trace-0.1.schema.json"):
        schema = json.loads(data_path("schemas", name).read_text(encoding="utf-8"))
        jsonschema.validators.validator_for(schema).check_schema(schema)
    for name in ("genai_invest_stand", "mempalace", "rest_native_agent"):
        load_profile(name)

    variant = next(v for v in load_catalog([ALL_CATALOG])
                   if v.id == "generic-mpi-explicit-rule")
    channels = [
        Channel(role=ChannelRole.ATTACKER, principal=Principal(principal_id="A")),
        Channel(role=ChannelRole.VICTIM, principal=Principal(principal_id="B")),
    ]
    outcomes = {}
    event_count = 0
    with TemporaryDirectory(prefix="memrot-smoke-") as directory:
        for persist, expected in ((True, Verdict.CONFIRMED), (False, Verdict.CLEAN)):
            label = "persistent" if persist else "nonpersistent"
            target = _MemoryTarget(persist)
            adapter = CallableAdapter(
                new_session_fn=target.new_session, send_fn=target.send,
                consolidate_fn=target.consolidate,
                inspect_fn=lambda _principal: target.memory,
            )
            path = Path(directory) / f"{label}.jsonl"
            tracer = JSONLTracer(str(path), redactor=_OfflineRedactor(api_url=""))
            try:
                report = run_matrix([variant], channels, adapter, LiteralDetector(), tracer)
            finally:
                tracer.close()
            result = report.results[0]
            if result.verdict != expected or tracer.lifecycle_errors:
                raise RuntimeError(f"{label}: {result.verdict.value}, "
                                   f"{result.error}, {tracer.lifecycle_errors}")
            events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            if not events:
                raise RuntimeError(f"{label}: lifecycle trace is empty")
            for event in events:
                validate_event(event)
            event_count += len(events)
            # Exercise all report renderers with the result of an actual run.
            if not json.loads(emit_json(report))["results"] or not emit_markdown(report) or not emit_html(report):
                raise RuntimeError(f"{label}: empty report")
            outcomes[label] = result.verdict.value
    return {"status": "ok", "catalog_files": len(files), "outcomes": outcomes,
            "lifecycle_events": event_count, "target": "synthetic in-memory fixture"}


def main() -> int:
    print(json.dumps(run_smoke(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
