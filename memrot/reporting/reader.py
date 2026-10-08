"""Read report documents without silently reinterpreting historical verdicts."""
from __future__ import annotations

import json
from typing import Any, Dict


def load_json_report(source: str) -> Dict[str, Any]:
    """Decode JSON, preserving results/metrics and labeling legacy semantics.

    Unversioned reports were produced by schema 1.0. Their CLEAN/path_state
    values cannot be upgraded without the original observations and a rerun.
    """
    data = json.loads(source)
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise ValueError("expected an attack report object with results")
    version = data.get("schema_version", "1.0")
    if version not in ("1.0", "2.0"):
        raise ValueError(f"unsupported attack report schema_version: {version!r}")
    if version == "1.0":
        data["schema_version"] = "1.0"
        data["verdict_semantics"] = "legacy-v1"
        notes = list(data.get("limitations", []))
        note = "Legacy v1 semantics: CLEAN may include unproven outcomes; path_state was inferred from verdict/propagation."
        if note not in notes:
            notes.append(note)
        data["limitations"] = notes
    elif data.get("verdict_semantics") != "evidence-aware-v2":
        raise ValueError("schema 2.0 requires evidence-aware-v2 verdict semantics")
    return data
