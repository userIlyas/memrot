import dataclasses
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from memrot.adapters.callable_adapter import CallableAdapter
from memrot.cli import _emit_and_status
from memrot.detectors.literal import LiteralDetector
from memrot.models import Verdict
from memrot.reporting import emit_json
from memrot.runner.engine import run_matrix, run_variant
from memrot.tracer import JSONLTracer
from tests.test_attack_tracer import CHANNELS, _variant
from tests.fixtures.fake_memory_target import FakeCleanMemoryApp, FakeVulnerableMemoryApp, RaisingApp, build_adapter


def read_events(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines()]


def assert_refs(result, events):
    ids = {e['event_id'] for e in events}
    assert result.trace_event_ids and set(result.trace_event_ids) <= ids
    assert set(result.evidence_event_refs.values()) <= ids
    for name in ('baseline_detection', 'post_detection', 'state_detection', 'ground_truth_detection'):
        detection = getattr(result, name)
        if detection and detection.evidence_ref:
            assert detection.evidence_ref in ids
    assert all(e['attempt_id'] == result.attempt_id for e in events if e['event_id'] in result.trace_event_ids)


@pytest.mark.parametrize('verdict', list(Verdict))
def test_journal_persists_every_verdict_and_resolvable_refs(tmp_path, verdict):
    variant = _variant()
    app = FakeCleanMemoryApp()
    if verdict == Verdict.CONFIRMED:
        app = FakeVulnerableMemoryApp()
    elif verdict == Verdict.ERROR:
        app = RaisingApp()
    elif verdict == Verdict.INVALID:
        app = FakeVulnerableMemoryApp()
        app.global_policy = 'CANARY-fixed'
        variant = dataclasses.replace(variant, canary_template='CANARY-fixed')
    elif verdict == Verdict.NOT_EVALUATED:
        variant = dataclasses.replace(variant, access_profile_required='white_box')
    adapter = build_adapter(app)
    if verdict == Verdict.INCONCLUSIVE:
        adapter = CallableAdapter(send_fn=lambda *args: None)
    tracer = JSONLTracer(str(tmp_path / 'trace.jsonl'))
    before = time.time()
    result = run_variant(variant, CHANNELS, adapter, LiteralDetector(), tracer, 'run')
    tracer.close()
    assert result.verdict == verdict
    assert before <= result.started_at <= result.finished_at <= time.time()
    events = read_events(tracer.events_path)
    assert all(e['schema_version'] == 'phase-journal-1.0' for e in events)
    assert events[-1]['phase'] == 'verdict' and events[-1]['verdict'] == verdict.value
    assert_refs(result, events)
    if verdict not in (Verdict.NOT_EVALUATED, Verdict.ERROR):
        assert any(e['direction'] == 'request' for e in events)
        assert any(e['direction'] == 'response' for e in events)


def test_repeated_variant_gets_unique_attempt_ids(tmp_path):
    tracer = JSONLTracer(str(tmp_path / 'trace.jsonl'))
    adapter = build_adapter(FakeCleanMemoryApp())
    results = [run_variant(_variant(), CHANNELS, adapter, LiteralDetector(), tracer, 'run') for _ in range(2)]
    assert results[0].attempt_id != results[1].attempt_id
    assert set(results[0].trace_event_ids).isdisjoint(results[1].trace_event_ids)
    for result in results:
        assert_refs(result, read_events(tracer.events_path))


def test_phase_text_redacted_before_truncation(tmp_path, monkeypatch):
    secret = 'short-private-token'
    monkeypatch.setenv('MEMROT_CRED_JOURNAL', secret)
    tracer = JSONLTracer(str(tmp_path / 'trace.jsonl'))
    tracer.log(run_id='r', trace_id='v', text='x' * 280 + secret + ' CANARY-fixed', canary='CANARY-fixed',
               error=secret, tool={'nested': secret})
    tracer.close()
    raw = Path(tracer.events_path).read_text()
    assert secret not in raw and 'CANARY-fixed' not in raw
    assert 'short-private' not in raw
    assert '<REDACTED_SECRET>' in raw


@pytest.mark.parametrize('failure', ['journal', 'lifecycle', 'initialization', 'emission'])
def test_persistence_failure_marks_report_incomplete_and_gate(tmp_path, monkeypatch, failure):
    destination = tmp_path / 'trace.jsonl'
    if failure == 'initialization':
        blocked = tmp_path / 'blocked'
        blocked.write_text('file, not directory')
        destination = blocked / 'trace.jsonl'
    tracer = JSONLTracer(str(destination))
    if failure == 'journal':
        import builtins
        original = builtins.open
        def fail(path, *args, **kwargs):
            if str(path) == tracer.events_path:
                raise OSError('disk full SECRET')
            return original(path, *args, **kwargs)
        monkeypatch.setattr(builtins, 'open', fail)
    elif failure == 'lifecycle':
        monkeypatch.setattr(tracer.emitter, 'flush', lambda *args: (_ for _ in ()).throw(OSError('disk full SECRET')))
    elif failure == 'emission':
        monkeypatch.setattr(tracer.emitter, 'emit', lambda *args, **kwargs: (_ for _ in ()).throw(ValueError('bad SECRET')))
    report = run_matrix([_variant()], CHANNELS, build_adapter(FakeCleanMemoryApp()), LiteralDetector(), tracer)
    tracer.close()
    tracer.update_report(report)
    assert report.trace_coverage['status'] == 'incomplete'
    assert report.to_dict()['report_status'] == 'incomplete'
    assert 'SECRET' not in json.dumps(report.trace_coverage)
    from argparse import Namespace
    assert _emit_and_status(report, Namespace(out=None, gate=True)) == 2


def test_interrupted_matrix_keeps_completed_current_and_unrun_cases(tmp_path):
    variants = [dataclasses.replace(_variant(), id=str(i), propagation='single-turn', target_ref='FLAG') for i in range(3)]
    calls = []
    def send(*args):
        calls.append(args)
        if len(calls) == 2:
            raise KeyboardInterrupt('stop')
        return 'safe'
    tracer = JSONLTracer(str(tmp_path / 'trace.jsonl'))
    with pytest.raises(KeyboardInterrupt) as caught:
        run_matrix(variants, CHANNELS, CallableAdapter(send_fn=send), LiteralDetector(), tracer, 'run')
    report = caught.value.partial_report
    assert len(calls) == 2
    assert [r.verdict for r in report.results] == [Verdict.CLEAN, Verdict.ERROR, Verdict.NOT_EVALUATED]
    assert report.run_status == 'interrupted'
    saved = json.loads((tmp_path / 'run.partial.json').read_text())
    assert saved['report_status'] == 'incomplete'
    assert len(saved['results']) == 3
    events = read_events(tracer.events_path)
    for result in report.results:
        assert_refs(result, events)


def test_later_evidence_error_does_not_erase_observed_text(tmp_path):
    def ground_truth(*args, **kwargs):
        raise OSError('evidence source down')
    tracer = JSONLTracer(str(tmp_path / 'trace.jsonl'))
    variant = dataclasses.replace(_variant(), propagation='single-turn', target_ref='FLAG')
    result = run_variant(variant, CHANNELS, CallableAdapter(send_fn=lambda *args: 'FLAG', ground_truth_fn=ground_truth),
                         LiteralDetector(), tracer, 'r')
    assert result.verdict == Verdict.ERROR
    assert result.post_detection.canary_present
    assert set(result.evidence_event_refs) >= {'post', 'error'}
    assert_refs(result, read_events(tracer.events_path))


def test_journal_and_refs_survive_process_exit(tmp_path):
    script = '''
import sys
from pathlib import Path
from memrot.tracer import JSONLTracer
from memrot.runner.engine import run_matrix
from memrot.detectors.literal import LiteralDetector
from memrot.reporting import emit_json
from tests.test_attack_tracer import CHANNELS, _variant
from tests.fixtures.fake_memory_target import build_adapter, FakeCleanMemoryApp
root = Path(sys.argv[1])
tracer = JSONLTracer(str(root / "trace.jsonl"))
report = run_matrix([_variant()], CHANNELS, build_adapter(FakeCleanMemoryApp()), LiteralDetector(), tracer)
tracer.close()
(root / "run.json").write_text(emit_json(report))
'''
    subprocess.run([sys.executable, '-c', script, str(tmp_path)], check=True)
    report = json.loads((tmp_path / 'run.json').read_text())
    events = read_events(tmp_path / 'events.jsonl')
    ids = {e['event_id'] for e in events}
    assert set(report['results'][0]['trace_event_ids']) <= ids
    assert {e['direction'] for e in events} >= {'request', 'response'}
    assert any(e['phase'] == 'verdict' for e in events)


def test_cli_interrupt_emits_partial_and_final_report(tmp_path, monkeypatch):
    import memrot.cli as cli
    catalog = tmp_path / 'catalog.json'
    item = dataclasses.replace(_variant(), propagation='single-turn', inject_turns=[], target_ref='FLAG')
    catalog.write_text(json.dumps({'variants': [item.to_dict()]}))
    config = tmp_path / 'config.json'
    config.write_text(json.dumps({'target': {'kind': 'openai_compat', 'binding': {'base_url': 'http://unused', 'model': 'test'}},
                                  'channels': [c.to_dict() for c in CHANNELS], 'catalog_paths': [str(catalog)]}))
    def stop(*args):
        raise KeyboardInterrupt()
    monkeypatch.setattr(cli, 'build_adapter', lambda *args: CallableAdapter(send_fn=stop))
    monkeypatch.setattr(cli, '_check_target_adapter', lambda *args: (True, 'ok'))
    output = tmp_path / 'out'
    assert cli.main(['run', '--config', str(config), '--out', str(output), '--no-fancy']) == 130
    assert json.loads((output / 'run.json').read_text())['run_status'] == 'interrupted'
    assert (output / 'run.partial.json').exists()


def test_state_detection_ref_resolves_to_inspected_content_digest(tmp_path):
    tracer = JSONLTracer(str(tmp_path / 'trace.jsonl'))
    result = run_variant(_variant(), CHANNELS, build_adapter(FakeVulnerableMemoryApp(), with_memory=True),
                         LiteralDetector(), tracer, 'r')
    events = {e['event_id']: e for e in read_events(tracer.events_path)}
    assert result.state_detection.evidence_ref == result.evidence_event_refs['state']
    assert events[result.evidence_event_refs['state']]['text_digest'].startswith('sha256:')


def test_adaptive_interruption_retains_previous_rounds(tmp_path):
    from memrot.runner.adaptive import run_adaptive
    from memrot.runner.engine import interrupted_report
    class LLM:
        def complete(self, **kwargs):
            return 'rewritten'
    calls = []
    def send(*args):
        calls.append(args)
        if len(calls) == 2:
            raise KeyboardInterrupt()
        return 'safe'
    tracer = JSONLTracer(str(tmp_path / 'trace.jsonl'))
    seed = dataclasses.replace(_variant(), propagation='single-turn', inject_turns=[], target_ref='FLAG')
    inventory = [seed]
    adapter = CallableAdapter(send_fn=send)
    with pytest.raises(KeyboardInterrupt):
        run_adaptive(seed, CHANNELS, adapter, LiteralDetector(), tracer, 'r',
                     attacker_llm=LLM(), selected_inventory=inventory)
    report = interrupted_report(inventory, CHANNELS, adapter, tracer, 'r')
    assert len(report.results) == 2
    assert [r.verdict for r in report.results] == [Verdict.CLEAN, Verdict.ERROR]
    assert (tmp_path / 'run.partial.json').exists()


def test_partial_redaction_does_not_rewrite_short_marker_in_refs(tmp_path):
    tracer = JSONLTracer(str(tmp_path / 'trace.jsonl'))
    def stop(*args):
        raise KeyboardInterrupt()
    variant = dataclasses.replace(_variant(), propagation='single-turn', target_ref='a')
    with pytest.raises(KeyboardInterrupt):
        run_matrix([variant], CHANNELS, CallableAdapter(send_fn=stop), LiteralDetector(), tracer, 'run-a')
    report = json.loads((tmp_path / 'run.partial.json').read_text())
    events = read_events(tracer.events_path)
    assert report['schema_version'] == '2.1'
    assert report['run_id'] == 'run-a'
    assert set(report['results'][0]['trace_event_ids']) <= {e['event_id'] for e in events}
