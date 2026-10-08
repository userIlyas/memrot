import json

import pytest

from memrot.adapters.callable_adapter import CallableAdapter
from memrot.cli import _exit_code
from memrot.detectors.literal import LiteralDetector
from memrot.models import AttackResult, RunReport, Verdict, path_state_for
from memrot.reporting import aggregate, emit_json, emit_markdown, emit_html, load_json_report
from memrot.runner.engine import run_variant
from memrot.runner.verdict import decide_verdict
from memrot.tracer import JSONLTracer
from tests.test_attack_verdict_tiers import CHANNELS, _variant


@pytest.mark.parametrize("baseline,post,expected", [(None, False, Verdict.INCONCLUSIVE),
    (False, None, Verdict.INCONCLUSIVE), (None, True, Verdict.INCONCLUSIVE),
    (True, None, Verdict.INVALID)])
def test_unknown_observation_is_not_negative(baseline, post, expected):
    assert decide_verdict(baseline, post) is expected


@pytest.mark.parametrize("missing", ["baseline", "post", "memory", "ground_truth"])
def test_runner_requires_observation_for_clean(missing):
    calls = []
    def send(*args):
        calls.append(args)
        if (missing == "baseline" and len(calls) == 1) or (missing == "post" and len(calls) == 3):
            return None
        return "safe"
    adapter = CallableAdapter(send_fn=send,
                              inspect_fn=(lambda principal: None) if missing == "memory" else None,
                              ground_truth_fn=(lambda *args, **kwargs: None) if missing == "ground_truth" else None)
    result = run_variant(_variant(), CHANNELS, adapter, LiteralDetector(), JSONLTracer(), "run")
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.inconclusive_reason
    assert result.path_state == "unknown"


def test_text_signal_survives_unknown_ground_truth():
    adapter = CallableAdapter(send_fn=lambda *args: "1003", ground_truth_fn=lambda *args, **kwargs: None)
    result = run_variant(_variant(propagation="single-turn", target_ref="1003"), CHANNELS,
                         adapter, LiteralDetector(), JSONLTracer(), "run")
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.post_detection.canary_present
    assert result.evidence_tier == "text"
    assert result.evidence_refs == [{"kind": "runtime_path_observed", "ref": "#/post_detection"}]
    assert result.path_state == "runtime_path_observed"


def test_observed_negative_still_clean():
    result = run_variant(_variant(), CHANNELS, CallableAdapter(send_fn=lambda *args: "safe"),
                         LiteralDetector(), JSONLTracer(), "run")
    assert result.verdict is Verdict.CLEAN
    assert result.path_state == "unknown"


def test_negative_state_does_not_hide_missing_response():
    calls = []
    def send(*args):
        calls.append(args)
        return None if len(calls) == 3 else "safe"
    adapter = CallableAdapter(send_fn=send, inspect_fn=lambda principal: "empty memory")
    result = run_variant(_variant(), CHANNELS, adapter, LiteralDetector(), JSONLTracer(), "run")
    assert result.verdict is Verdict.INCONCLUSIVE
    assert "response observation unavailable" in result.inconclusive_reason


def test_path_state_requires_specific_evidence_not_labels():
    for verdict in Verdict:
        assert path_state_for(verdict, "cross-user") == "unknown"
    assert path_state_for(Verdict.CONFIRMED, evidence_refs=[{"kind": "control_violation_observed"}]) == "unknown"
    assert path_state_for(Verdict.CLEAN, evidence_refs=[{"kind": "static_path_supported", "ref": "audit.json#/facts/1"}]) == "static_path_supported"
    assert path_state_for(Verdict.CONFIRMED, evidence_refs=[{"kind": "control_violation_observed", "ref": "evidence.json#/policy_violation"}]) == "control_violation_observed"


def test_inconclusive_excluded_from_metrics_visible_in_all_formats():
    report = aggregate(RunReport(run_id="r", target_id="t", results=[
        AttackResult("unknown", Verdict.INCONCLUSIVE, inconclusive_reason="missing evidence <unsafe>"),
        AttackResult("yes", Verdict.CONFIRMED), AttackResult("no", Verdict.CLEAN)]))
    assert report.overall_asr.total == 2 and report.overall_asr.ratio == 0.5
    assert report.counts_by_verdict["INCONCLUSIVE"] == 1
    for rendered in (emit_json(report), emit_markdown(report), emit_html(report)):
        assert "INCONCLUSIVE" in rendered and "missing evidence" in rendered
    assert "missing evidence &lt;unsafe&gt;" in emit_html(report)
    decoded = load_json_report(emit_json(report))
    assert decoded["schema_version"] == "2.0"
    assert decoded["results"][0]["inconclusive_reason"] == "missing evidence <unsafe>"


@pytest.mark.parametrize("explicit_version", [False, True])
def test_legacy_read_preserves_verdict_metrics_and_labels_old_semantics(explicit_version):
    old = {"results": [{"variant_id": "old", "verdict": "CLEAN", "path_state": "static_path_supported"}],
           "overall_asr": {"total": 1, "confirmed": 0}}
    if explicit_version:
        old["schema_version"] = "1.0"
    read = load_json_report(json.dumps(old))
    assert read["verdict_semantics"] == "legacy-v1"
    assert read["results"] == old["results"] and read["overall_asr"] == old["overall_asr"]
    assert "Legacy v1 semantics" in read["limitations"][0]
    assert load_json_report(json.dumps(read)) == read


@pytest.mark.parametrize("data", [{"results": [], "schema_version": "3.0"},
    {"results": [], "schema_version": "2.0"}, []])
def test_reader_rejects_unknown_or_unlabeled_semantics(data):
    with pytest.raises(ValueError):
        load_json_report(json.dumps(data))


def test_gate_incomplete_without_masking_confirmed():
    assert _exit_code({"INCONCLUSIVE": 1}, True) == 2
    assert _exit_code({"INCONCLUSIVE": 1, "CONFIRMED": 1}, True) == 1
    assert _exit_code({"INCONCLUSIVE": 1}, False) == 0
