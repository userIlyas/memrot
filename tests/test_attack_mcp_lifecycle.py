from __future__ import annotations

import json
import os
import signal
from pathlib import Path
import sys
import time

import pytest

from memrot import cli, pipeline
from memrot.adapters import mcp_client as mcp
from memrot.config import TargetBinding
from memrot.models import Channel, ChannelRole, Principal, Verdict


SERVER = Path(__file__).parent / "fixtures" / "mcp_lifecycle_server.py"
USER = Principal(principal_id="fixture-user")
CHANNELS = [Channel(role=ChannelRole.ATTACKER, principal=USER)]


@pytest.fixture
def transports(monkeypatch):
    made = []
    original = mcp._StdioTransport

    class TrackedTransport(original):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            made.append(self)

    monkeypatch.setattr(mcp, "_StdioTransport", TrackedTransport)
    yield made
    for transport in made:
        transport.close()


def adapter(mode="normal", **kwargs):
    return mcp.MCPClientAdapter(command=sys.executable, args=[str(SERVER)], timeout=0.5,
                                env={"MCP_TEST_MODE": mode}, **kwargs)


def send(target):
    return target.send(USER, target.new_session(USER), "hello")


def assert_reaped(transport):
    assert transport.proc.poll() is not None
    assert not transport._reader.is_alive()
    assert not transport._stderr_reader.is_alive()
    assert not transport._writer.is_alive()
    assert all(stream.closed for stream in (transport.proc.stdin, transport.proc.stdout, transport.proc.stderr))


def test_child_env_only_contains_allowlisted_and_explicit_bindings(monkeypatch, transports):
    unrelated = {"HARNESS_SECRET", "AWS_SESSION_TOKEN", "MEMROT_CRED_UNUSED", "PYTHONPATH", "LD_PRELOAD"}
    for name in unrelated:
        monkeypatch.setenv(name, "synthetic-unrelated-value")
    monkeypatch.setenv("MEMROT_CRED_SELECTED", "fixture-token")
    monkeypatch.setenv("LC_ALL", "C")
    with mcp.MCPClientAdapter(
        command=sys.executable, args=[str(SERVER)], timeout=2,
        env={"MCP_TEST_MODE": "env", "EXPLICIT_SETTING": "local"},
        credential_refs={"TARGET_KEY": "SELECTED"},
    ) as target:
        observed = json.loads(send(target))
    assert not unrelated.intersection(observed["names"])
    assert "MEMROT_CRED_SELECTED" not in observed["names"]
    assert "LC_ALL" in observed["names"]
    assert observed["credential_ok"] is True
    assert observed["setting"] == "local"
    assert_reaped(transports[0])


def test_missing_explicit_child_credential_fails_before_spawn(monkeypatch, transports):
    monkeypatch.delenv("MEMROT_CRED_F003_MISSING", raising=False)
    with adapter(credential_refs={"TARGET_KEY": "F003_MISSING"}) as target:
        with pytest.raises(RuntimeError, match="missing credential"):
            send(target)
    assert not transports


def test_env_cannot_override_a_credential_binding(transports):
    with adapter(credential_refs={"MCP_TEST_MODE": "SELECTED"}) as target:
        with pytest.raises(ValueError, match="must not set the same variable"):
            send(target)
    assert not transports


def test_large_stderr_is_drained_with_bounded_retention(transports):
    with adapter("stderr") as target:
        assert send(target) == "hello"
        assert len(transports[0].stderr_tail) <= mcp.MAX_STDERR_BYTES
    assert_reaped(transports[0])


@pytest.mark.parametrize("mode", ["hang_initialize", "hang_call", "ignore_term"])
def test_timeout_terminates_and_reaps_process(mode, transports):
    if mode == "ignore_term" and os.name != "posix":
        pytest.skip("POSIX signal escalation")
    with adapter(mode) as target:
        with pytest.raises(TimeoutError):
            send(target)
        assert not target._connections
        assert_reaped(transports[0])


@pytest.mark.parametrize("mode,match", [("oversize", "size limit"), ("invalid_json", "invalid JSON"),
                                        ("array", "JSON object")])
def test_invalid_or_oversized_stdout_fails_and_closes(mode, match, monkeypatch, transports):
    monkeypatch.setattr(mcp, "MAX_RESPONSE_BYTES", 1024)
    with adapter(mode) as target:
        with pytest.raises(RuntimeError, match=match):
            send(target)
        assert_reaped(transports[0])


def test_stdout_queue_overflow_is_bounded_and_fails(transports):
    transport = mcp._StdioTransport(sys.executable, ["-c", (
        "import json, threading\n"
        "for i in range(100): print(json.dumps({'id': i, 'result': {}}), flush=True)\n"
        "threading.Event().wait()\n"
    )], timeout=0.5)
    transport._reader.join(timeout=3)  # exits on overflow without a consumer
    assert transport._q.qsize() <= mcp.MAX_PENDING_MESSAGES
    with pytest.raises(RuntimeError, match="pending message limit"):
        transport.recv(0.5)
    assert_reaped(transport)


def test_blocked_stdin_write_times_out_and_reaps(transports):
    transport = mcp._StdioTransport(sys.executable, ["-c", "import threading; threading.Event().wait()"], timeout=0.2)
    started = time.monotonic()
    with pytest.raises(TimeoutError, match="writing"):
        transport.send({"payload": "x" * (1024 * 1024)})
    assert time.monotonic() - started < 5
    assert_reaped(transport)


def test_response_before_eof_is_not_discarded(transports):
    transport = mcp._StdioTransport(sys.executable, ["-c", "print('{\"id\": 1, \"result\": {}}')"])
    transport._reader.join(timeout=3)
    assert transport.recv(0.5) == {"id": 1, "result": {}}
    transport.close()
    assert_reaped(transport)


def test_context_manager_closes_on_exception_and_close_is_idempotent(transports):
    target = adapter()
    with pytest.raises(ValueError, match="caller failure"):
        with target:
            assert send(target) == "hello"
            raise ValueError("caller failure")
    target.close()
    assert_reaped(transports[0])
    with pytest.raises(RuntimeError, match="closed"):
        target.new_session(USER)


@pytest.mark.parametrize("mode,explicit", [("ambiguous", None), ("write_tool", None),
                                           ("wrong_shape", None), ("empty", None),
                                           ("normal", "missing"), ("duplicate", "chat"),
                                           ("mixed_duplicate", None), ("paginated", None)])
def test_invalid_tool_binding_never_calls_a_tool(mode, explicit, transports, tmp_path):
    log = tmp_path / "calls.jsonl"
    with adapter(mode, chat_tool=explicit) as target:
        target.env["MCP_TEST_LOG"] = str(log)
        with pytest.raises(RuntimeError, match="chat_tool"):
            send(target)
        assert_reaped(transports[0])
    methods = [json.loads(line)["method"] for line in log.read_text().splitlines()]
    assert "tools/list" in methods and "tools/call" not in methods


def test_explicit_tool_can_select_a_stateful_chat(transports):
    with adapter("write_tool", chat_tool="chat") as target:
        assert send(target) == "hello"
    assert_reaped(transports[0])


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group cleanup")
def test_close_signals_descendants_that_hold_transport_pipes(transports, tmp_path):
    pid_path = tmp_path / "child.pid"
    child_pid = None
    try:
        with adapter("descendant") as target:
            target.env["MCP_TEST_CHILD_PID"] = str(pid_path)
            assert send(target) == "hello"
            child_pid = int(pid_path.read_text())
        assert_reaped(transports[0])
        with pytest.raises(ProcessLookupError):
            os.kill(child_pid, 0)
    finally:
        if child_pid is not None:
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def test_http_close_clears_all_principal_connections():
    target = mcp.MCPClientAdapter(base_url="http://example.invalid")
    transports = [mcp._HttpTransport(target.base_url, {"Authorization": "Bearer fixture"}) for _ in range(2)]
    for i, transport in enumerate(transports):
        transport.session_id = f"session-{i}"
        transport._pending.put({"id": i})
        target._connections[(str(i), str(i))] = mcp._Connection(transport)
    target.close()
    target.close()
    assert not target._connections
    for transport in transports:
        assert transport.session_id is None and not transport.headers
        assert transport._pending.empty()
        with pytest.raises(RuntimeError, match="closed"):
            transport.send({})


def test_http_rejects_oversize_responses(monkeypatch):
    from io import BytesIO
    response = BytesIO(b"x" * 1025)
    response.headers = {}
    monkeypatch.setattr(mcp, "MAX_RESPONSE_BYTES", 1024)
    monkeypatch.setattr(mcp.urllib.request, "urlopen", lambda *a, **kw: response)
    target = mcp.MCPClientAdapter(base_url="http://example.invalid")
    connection = mcp._Connection(mcp._HttpTransport(target.base_url))
    with pytest.raises(RuntimeError, match="size limit"):
        target._request(connection, "initialize")
    assert connection.transport._closed


def test_sse_message_flood_is_bounded():
    raw = 'data: {"id": 1}\n\n' * (mcp.MAX_PENDING_MESSAGES + 1)
    with pytest.raises(RuntimeError, match="pending message limit"):
        mcp._parse_sse(raw)


def test_http_error_response_is_closed(monkeypatch):
    from io import BytesIO
    body = BytesIO(b"server error")
    error = mcp.urllib.error.HTTPError("http://example.invalid", 503, "unavailable", {}, body)
    def fail(*args, **kwargs):
        raise error
    monkeypatch.setattr(mcp.urllib.request, "urlopen", fail)
    with pytest.raises(RuntimeError, match="HTTP 503"):
        mcp._HttpTransport("http://example.invalid").send({})
    assert body.closed


@pytest.fixture
def run_config(tmp_path):
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps({"schema_version": "1.0", "variants": [{
        "id": "lifecycle-fixture", "title": "fixture", "framing": "explicit_rule",
        "payload": "formatting_marker", "layer": "policy_global", "propagation": "cross-session-same-user",
        "probe": "status", "inject_turns": ["remember {canary}"], "canary_template": "CANARY-{canary}",
        "rule_ids": [],
    }]}))
    config = {"schema_version": "1.0", "target": {"kind": "mcp_client", "binding": {
        "command": sys.executable, "args": [str(SERVER)], "timeout": 0.5,
    }}, "catalog_paths": [str(catalog)], "channels": [c.to_dict() for c in CHANNELS]}
    path = tmp_path / "run.json"
    path.write_text(json.dumps(config))
    return path, config, catalog


@pytest.mark.parametrize("failure", [None, "health", "generation", "audit", "report", "interrupt"])
def test_cli_closes_on_success_and_every_post_handshake_exit(failure, run_config, transports, monkeypatch, tmp_path):
    path, config, catalog = run_config
    args = ["run", "--config", str(path), "--out", str(tmp_path / "out"), "--no-fancy"]
    if failure == "health":
        config["target"]["binding"]["env"] = {"MCP_TEST_MODE": "hang_call"}
        path.write_text(json.dumps(config))
    if failure == "generation":
        args += ["--mutate", "not-a-technique"]
    if failure == "audit":
        args += ["--audit", str(tmp_path / "missing-audit.json")]
    if failure in ("report", "interrupt"):
        def fail(*args, **kwargs):
            raise (OSError("report failure") if failure == "report" else KeyboardInterrupt())
        monkeypatch.setattr(cli, "_emit_and_status" if failure == "report" else "run_matrix", fail)
    if failure == "interrupt":
        assert cli.main(args) == 130
        assert (tmp_path / "out" / "run.partial.json").exists()
    elif failure in ("audit", "report"):
        with pytest.raises((FileNotFoundError, OSError, KeyboardInterrupt)):
            cli.main(args)
    else:
        assert cli.main(args) == (cli.EXIT_ERROR if failure else cli.EXIT_OK)
    assert len(transports) == 1
    assert_reaped(transports[0])


@pytest.mark.parametrize("failure", [False, True])
def test_pipeline_closes_owned_adapter(failure, run_config, transports, monkeypatch):
    _, config, catalog = run_config
    if failure:
        def fail(*args, **kwargs):
            raise KeyboardInterrupt()
        monkeypatch.setattr(pipeline, "run_matrix", fail)
        # Start at construction so the error path owns a real running child.
        original = pipeline.build_adapter
        def build(target):
            bound = original(target)
            send(bound)
            return bound
        monkeypatch.setattr(pipeline, "build_adapter", build)
    kwargs = dict(target=TargetBinding(**config["target"]), channels=CHANNELS, pool=str(catalog))
    if failure:
        with pytest.raises(KeyboardInterrupt):
            pipeline.audit_then_attack(None, **kwargs)
    else:
        report = pipeline.audit_then_attack(None, **kwargs)
        assert report.results[0].verdict is Verdict.CLEAN
    assert len(transports) == 1
    assert_reaped(transports[0])


def test_pipeline_does_not_close_borrowed_adapter(run_config, transports):
    _, config, catalog = run_config
    with adapter() as target:
        pipeline.audit_then_attack(None, TargetBinding(**config["target"]), CHANNELS,
                                   pool=str(catalog), adapter=target)
        assert transports[0].proc.poll() is None
        assert send(target) == "hello"
    assert_reaped(transports[0])


def test_quickstart_mcp_binding_and_cleanup(run_config, transports, monkeypatch, tmp_path):
    _, config, catalog = run_config
    def build(target):
        assert target.kind == "mcp_client"
        assert target.binding == {"base_url": "http://example.invalid", "chat_tool": "chat"}
        return adapter(chat_tool=target.binding["chat_tool"])
    monkeypatch.setattr(pipeline, "build_adapter", build)
    assert cli.main(["quickstart", "--adapter", "mcp_client", "--url", "http://example.invalid",
                     "--chat-tool", "chat", "--pool", str(catalog), "--out", str(tmp_path / "out")]) == 0
    assert len(transports) == 1
    assert_reaped(transports[0])


@pytest.mark.parametrize("failure", ["audit", "tracer_close"])
def test_pipeline_cleanup_covers_setup_and_trace_errors(failure, run_config, transports, monkeypatch, tmp_path):
    _, config, catalog = run_config
    original = pipeline.build_adapter
    def build(target):
        bound = original(target)
        send(bound)
        return bound
    monkeypatch.setattr(pipeline, "build_adapter", build)
    if failure == "tracer_close":
        original_tracer = pipeline.JSONLTracer
        class FailingCloseTracer(original_tracer):
            def close(self):
                super().close()
                raise OSError("trace close failure")
        monkeypatch.setattr(pipeline, "JSONLTracer", FailingCloseTracer)
    with pytest.raises(OSError):
        pipeline.audit_then_attack(
            str(tmp_path / "missing-audit.json") if failure == "audit" else None,
            TargetBinding(**config["target"]), CHANNELS, pool=str(catalog),
        )
    assert len(transports) == 1
    assert_reaped(transports[0])
