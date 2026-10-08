import dataclasses
import json

import pytest

from memrot.adapters.callable_adapter import CallableAdapter
from memrot.catalog.loader import load_catalog
from memrot.catalog.schema import validate_variant_dict
from memrot.cli import _emit_and_status
from memrot.detectors.literal import LiteralDetector
from memrot.models import AttackResult, AttackVariant, Channel, ChannelRole, Principal, RunReport, Verdict
from memrot.reporting import aggregate, emit_html, emit_markdown, emit_json, load_json_report
from memrot.runner.adaptive import run_adaptive
from memrot.runner.engine import run_matrix, run_variant
from memrot.tracer import JSONLTracer


def variant(**kwargs):
    args = dict(id="control", title="test", framing="none", payload="none", layer="none",
                propagation="single-turn", probe="help", case_kind="benign_control")
    args.update(kwargs)
    return AttackVariant(**args)


CHANNELS = [Channel(ChannelRole.ATTACKER, Principal("attacker")),
            Channel(ChannelRole.BENIGN_CONTROL, Principal("control"))]


def test_nine_controls_never_dilute_attack_asr():
    results = [AttackResult("attack", Verdict.CONFIRMED)] + [
        AttackResult(str(i), Verdict.CLEAN, case_kind="benign_control", control_utility=True) for i in range(9)]
    results.append(AttackResult("diag", Verdict.CONFIRMED, case_kind="diagnostic"))
    report = aggregate(RunReport("r", "t", results=results))
    assert report.overall_asr.display == "1/1 (100.0%)"
    assert report.controls["utility_evaluated"] == 9
    assert report.controls["utility_rate"] == 1
    assert report.controls["false_positive_rate"] is None
    assert sum(c["selected"] for c in report.coverage_by_case_kind.values()) == 11
    assert sum(report.counts_by_verdict.values()) == 11


def test_missing_selected_and_unsupported_groups_remain_visible():
    inventory = [variant(id="missing", case_kind="attack", rule_ids=["MEM-01"],
                         owasp_amg_category="memory_prompt_injection"),
                 variant(id="unsupported", case_kind="attack", rule_ids=["MEM-02"])]
    report = aggregate(RunReport("r", "t", selected_variants=inventory,
                                 results=[AttackResult("unsupported", Verdict.NOT_EVALUATED, rule_ids=["MEM-02"])]))
    assert report.overall_asr.selected == 2
    assert report.overall_asr.eligible == report.overall_asr.evaluated == 0
    assert report.overall_asr.excluded == 2
    assert report.asr_by_rule_id["MEM-01"].display == "n/a (0/0)"
    assert report.asr_by_taxonomy_category["memory_prompt_injection"].selected == 1
    assert sum(report.counts_by_verdict.values()) == len(inventory)
    aggregate(report)
    assert len(report.results) == 2


@pytest.mark.parametrize("verdict", list(Verdict))
def test_coverage_conservation(verdict):
    report = aggregate(RunReport("r", "t", results=[AttackResult("v", verdict)]))
    metric = report.overall_asr
    assert metric.selected == metric.evaluated + metric.excluded == 1
    assert metric.eligible == (verdict is not Verdict.NOT_EVALUATED)
    assert sum(metric.counts_by_verdict.values()) == 1


def test_memory_and_jailbreak_have_distinct_denominators():
    report = aggregate(RunReport("r", "t", results=[
        AttackResult("m", Verdict.CONFIRMED, threat_model="memory_poisoning"),
        AttackResult("j", Verdict.CLEAN, threat_model="llm_jailbreak_susceptibility")]))
    assert report.asr_by_threat_model["memory_poisoning"].ratio == 1
    assert report.asr_by_threat_model["llm_jailbreak_susceptibility"].ratio == 0
    for rendering in (emit_markdown(report), emit_html(report)):
        assert "Attack ASR" in rendering
    assert load_json_report(emit_json(report))["metrics_semantics"] == "attack-only-v1"


@pytest.mark.parametrize("domain", ["invest_bank", "mempalace"])
def test_shipped_controls_have_explicit_kind_and_channel(domain):
    variants = load_catalog([f"memrot/catalog/prompts/domain/{domain}/benign_control"])
    assert all(v.case_kind == "benign_control" and v.attacker_role == "benign_control" for v in variants)


def test_control_uses_control_principal_and_empty_marker_is_not_fpr():
    calls = []
    adapter = CallableAdapter(send_fn=lambda pid, sid, text: calls.append(pid) or "helpful reply")
    report = run_matrix([variant()], CHANNELS, adapter, LiteralDetector(), JSONLTracer())
    assert calls == ["control"]
    assert report.selected_variants[0].case_kind == "benign_control"
    assert report.results[0].control_response_received
    assert report.results[0].post_detection is None
    assert report.controls["false_positive_evaluated"] == 0
    assert report.controls["utility_evaluated"] == 0
    assert report.overall_asr.total == 0


def test_missing_control_channel_skips_without_touching_attacker():
    adapter = CallableAdapter(send_fn=lambda *args: pytest.fail("wrong channel"))
    result = run_variant(variant(), CHANNELS[:1], adapter, LiteralDetector(), JSONLTracer(), "r")
    assert result.verdict is Verdict.NOT_EVALUATED


@pytest.mark.parametrize("response,utility,fpr", [("OK", True, False), ("no", False, False), ("FLAG", False, True)])
def test_utility_and_false_positive_oracles_are_independent(response, utility, fpr):
    report = run_matrix([variant(expected_response="OK", canary_template="FLAG")], CHANNELS,
                        CallableAdapter(send_fn=lambda *args: response), LiteralDetector(), JSONLTracer())
    assert report.results[0].control_utility is utility
    assert report.results[0].control_false_positive is fpr
    assert report.controls["utility_evaluated"] == report.controls["false_positive_evaluated"] == 1
    assert report.overall_asr.total == 0


def test_control_transport_failure_recorded_separately():
    def send(*args):
        raise OSError("broken")
    report = run_matrix([variant()], CHANNELS, CallableAdapter(send_fn=send), LiteralDetector(), JSONLTracer())
    assert report.controls["errors"] == 1
    assert report.controls["false_positive_rate"] is None
    assert report.overall_asr.selected == 0


def test_controls_are_never_adaptively_rewritten():
    class NoLLM:
        def complete(self, **kwargs):
            pytest.fail("rewrote benign traffic")
    results = run_adaptive(variant(), CHANNELS, CallableAdapter(send_fn=lambda *args: "OK"),
                           LiteralDetector(), JSONLTracer(), "r", attacker_llm=NoLLM())
    assert len(results) == 1 and results[0].case_kind == "benign_control"


def test_false_positive_control_is_not_reported_as_attack_gate_failure(tmp_path):
    from argparse import Namespace
    report = aggregate(RunReport("r", "t", results=[AttackResult("control", Verdict.CONFIRMED,
                                        case_kind="benign_control", control_false_positive=True)]))
    assert _emit_and_status(report, Namespace(out=str(tmp_path), gate=True)) == 2
    assert "No CONFIRMED attacks" in emit_html(report)


@pytest.mark.parametrize("updates", [{"case_kind": "typo"}, {"expected_response": ""},
                                     {"case_kind": "benign_control", "propagation": "cross-user"}])
def test_catalog_rejects_invalid_control_contract(updates):
    data = variant().to_dict()
    data.pop("expected_response")
    data.update(updates)
    assert validate_variant_dict(data)


@pytest.mark.parametrize("keep_seeds", [True, False])
def test_mutation_keeps_controls_unchanged(keep_seeds):
    from memrot.catalog.generator import LLMMutationGenerator
    seed = variant()
    generated = LLMMutationGenerator([seed], techniques=["prefix_injection"], keep_seeds=keep_seeds).generate()
    assert generated == [seed]


@pytest.mark.parametrize("response", [None, ""])
def test_missing_control_response_does_not_measure_false_positive_or_utility(response):
    report = run_matrix([variant(expected_response="OK", canary_template="FLAG")], CHANNELS,
                        CallableAdapter(send_fn=lambda *args: response), LiteralDetector(), JSONLTracer())
    assert report.results[0].verdict is Verdict.INCONCLUSIVE
    assert report.controls["utility_evaluated"] == report.controls["false_positive_evaluated"] == 0


def test_schema_20_metrics_are_explicitly_labeled_legacy():
    data = load_json_report(json.dumps({"schema_version": "2.0", "verdict_semantics": "evidence-aware-v2", "results": []}))
    assert data["metrics_semantics"] == "legacy-mixed-cases"


def test_case_kind_survives_adaptive_inventory():
    from tests.test_attack_verdict_tiers import _variant, CHANNELS as attack_channels
    class LLM:
        def complete(self, **kwargs):
            return "rewrite"
    seed = _variant()
    inventory = [seed]
    results = run_adaptive(seed, attack_channels, CallableAdapter(send_fn=lambda *args: "safe"),
                           LiteralDetector(), JSONLTracer(), "r", attacker_llm=LLM(), max_rounds=2,
                           selected_inventory=inventory)
    report = aggregate(RunReport("r", "t", results=results, selected_variants=inventory))
    assert len(inventory) == report.overall_asr.selected == len(results) == 2
