"""MCP authentication/session isolation using a real local HTTP transport."""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

import pytest

from memrot.adapters import mcp_client
from memrot.adapters.mcp_client import MCPClientAdapter
from memrot.config import TargetBinding
from memrot.detectors.literal import LiteralDetector
from memrot.models import AttackVariant, Channel, ChannelRole, Principal, Verdict
from memrot.pipeline import audit_then_attack
from memrot.runner.engine import run_variant
from memrot.tracer import JSONLTracer


A = Principal(principal_id="A", credential_ref="F002_A")
B = Principal(principal_id="B", credential_ref="F002_B")
CHANNELS = [Channel(role=ChannelRole.ATTACKER, principal=A),
            Channel(role=ChannelRole.VICTIM, principal=B)]


@pytest.fixture
def http_mcp(monkeypatch):
    monkeypatch.setenv("MEMROT_CRED_F002_A", "token-A")
    monkeypatch.setenv("MEMROT_CRED_F002_B", "token-B")
    records = []
    sessions = {}
    fail_list = set()
    identities = {"Bearer token-A": "A", "Bearer token-B": "B",
                  "Bearer rotated-A": "A", "Bearer shared": "shared"}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, status, body=None, session=None):
            payload = json.dumps(body).encode() if body is not None else b""
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            if session:
                self.send_header("Mcp-Session-Id", session)
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            auth = self.headers.get("Authorization")
            session = self.headers.get("Mcp-Session-Id")
            method = body["method"]
            records.append({"auth": auth, "session": session, "method": method,
                            "params": body.get("params", {})})
            if auth not in identities:
                self.reply(401)
                return
            if method == "initialize":
                if session is not None:
                    self.reply(400)  # never initialize using another MCP session
                    return
                session = f"mcp-{len(sessions) + 1}"
                sessions[session] = auth
                result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                          "serverInfo": {"name": "identity-fixture", "version": "1"}}
            else:
                if sessions.get(session) != auth:
                    self.reply(403)
                    return
                if method == "notifications/initialized":
                    self.reply(202)
                    return
                if method == "tools/list":
                    if auth in fail_list:
                        fail_list.remove(auth)
                        self.reply(503)
                        return
                    result = {"tools": [{"name": f"chat_{identities[auth]}", "annotations": {"readOnlyHint": True},
                                          "inputSchema": {"type": "object", "properties": {
                                              "message": {"type": "string"}, "session_id": {"type": "string"}}}}]}
                elif method == "tools/call":
                    if body["params"]["name"] != f"chat_{identities[auth]}":
                        self.reply(400)  # a tool cached for the other user is invalid
                        return
                    result = {"content": [{"type": "text", "text": f"reply for {identities[auth]}"}]}
                else:
                    self.reply(400)
                    return
            self.reply(200, {"jsonrpc": "2.0", "id": body["id"], "result": result}, session)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {"url": f"http://127.0.0.1:{server.server_port}/mcp", "records": records,
               "sessions": sessions, "fail_list": fail_list}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def _send(adapter, principal, message="hello"):
    return adapter.send(principal, adapter.new_session(principal), message)


def _calls(server):
    return [r for r in server["records"] if r["method"] == "tools/call"]


def _variant(propagation="cross-user"):
    return AttackVariant(
        id="mcp-identity", title="identity fixture", framing="explicit_rule",
        payload="formatting_marker", layer="policy_global", propagation=propagation,
        probe="status?", inject_turns=["remember {canary}"], canary_template="CANARY-{canary}",
    )


def test_http_a_b_a_keeps_authorization_sessions_and_tools_separate(http_mcp):
    adapter = MCPClientAdapter(base_url=http_mcp["url"], timeout=2)
    assert _send(adapter, A) == "reply for A"
    assert _send(adapter, B) == "reply for B"
    assert _send(adapter, A) == "reply for A"
    calls = _calls(http_mcp)
    assert [r["auth"] for r in calls] == ["Bearer token-A", "Bearer token-B", "Bearer token-A"]
    assert calls[0]["session"] == calls[2]["session"] != calls[1]["session"]
    assert [r["params"]["name"] for r in calls] == ["chat_A", "chat_B", "chat_A"]
    assert len({r["params"]["arguments"]["session_id"] for r in calls}) == 3
    assert sum(r["method"] == "initialize" for r in http_mcp["records"]) == 2


def test_shared_credential_still_has_separate_principal_connections(http_mcp, monkeypatch):
    monkeypatch.setenv("MEMROT_CRED_F002_A", "shared")
    other = Principal(principal_id="other", credential_ref="F002_A")
    adapter = MCPClientAdapter(base_url=http_mcp["url"], timeout=2)
    _send(adapter, A)
    _send(adapter, other)
    _send(adapter, A)
    calls = _calls(http_mcp)
    assert calls[0]["session"] == calls[2]["session"] != calls[1]["session"]


def test_same_principal_with_another_credential_ref_has_its_own_connection(http_mcp):
    adapter = MCPClientAdapter(base_url=http_mcp["url"], timeout=2)
    alternate = Principal(principal_id="A", credential_ref="F002_B")
    _send(adapter, A)
    _send(adapter, alternate)
    _send(adapter, A)
    calls = _calls(http_mcp)
    assert calls[0]["session"] == calls[2]["session"] != calls[1]["session"]
    assert [r["auth"] for r in calls] == ["Bearer token-A", "Bearer token-B", "Bearer token-A"]


def test_credential_rotation_reinitializes_only_that_binding(http_mcp, monkeypatch):
    adapter = MCPClientAdapter(base_url=http_mcp["url"], timeout=2)
    _send(adapter, A)
    _send(adapter, B)
    monkeypatch.setenv("MEMROT_CRED_F002_A", "rotated-A")
    _send(adapter, A)
    _send(adapter, B)
    calls = _calls(http_mcp)
    assert calls[0]["session"] != calls[2]["session"]
    assert calls[2]["auth"] == "Bearer rotated-A"
    assert calls[1]["session"] == calls[3]["session"]


@pytest.mark.parametrize("cached", [False, True])
def test_missing_credential_never_sends_anonymous_or_cached_request(http_mcp, monkeypatch, cached):
    adapter = MCPClientAdapter(base_url=http_mcp["url"], timeout=2)
    if cached:
        _send(adapter, A)
    monkeypatch.delenv("MEMROT_CRED_F002_A")
    before = len(http_mcp["records"])
    with pytest.raises(RuntimeError, match="missing credential.*MEMROT_CRED_F002_A"):
        _send(adapter, A)
    assert len(http_mcp["records"]) == before


def test_failed_handshake_does_not_reuse_partial_session_or_break_other_user(http_mcp):
    adapter = MCPClientAdapter(base_url=http_mcp["url"], timeout=2)
    _send(adapter, A)
    http_mcp["fail_list"].add("Bearer token-B")
    with pytest.raises(RuntimeError, match="HTTP 503"):
        _send(adapter, B)
    _send(adapter, B)
    _send(adapter, A)
    calls = _calls(http_mcp)
    assert len(calls) == 3
    assert calls[0]["session"] == calls[2]["session"]
    b_lists = [r for r in http_mcp["records"] if r["auth"] == "Bearer token-B" and r["method"] == "tools/list"]
    assert len(b_lists) == 2 and b_lists[0]["session"] != b_lists[1]["session"]


def test_conversation_cannot_be_reused_by_another_principal(http_mcp):
    adapter = MCPClientAdapter(base_url=http_mcp["url"], timeout=2)
    session = adapter.new_session(A)
    with pytest.raises(RuntimeError, match="session belongs to a different principal"):
        adapter.send(B, session, "hello")
    assert not http_mcp["records"]


@pytest.mark.parametrize("header", ["Authorization", "authorization", "AUTHORIZATION", "mCp-SeSsIoN-Id"])
def test_identity_headers_cannot_be_overridden(header):
    with pytest.raises(ValueError, match="managed per principal"):
        MCPClientAdapter(base_url="http://example.invalid/mcp", extra_headers={header: "fixed"})


def test_runner_uses_victim_attacker_victim_authentication(http_mcp):
    adapter = MCPClientAdapter(base_url=http_mcp["url"], timeout=2)
    result = run_variant(_variant(), CHANNELS, adapter, LiteralDetector(), JSONLTracer(), "identity-run")
    assert result.verdict is Verdict.CLEAN
    calls = _calls(http_mcp)
    assert [r["auth"] for r in calls] == ["Bearer token-B", "Bearer token-A", "Bearer token-B"]
    assert calls[0]["session"] == calls[2]["session"] != calls[1]["session"]


def test_pipeline_does_not_manufacture_mcp_credentials(http_mcp, monkeypatch):
    monkeypatch.delenv("MEMROT_CRED_F002_A")
    monkeypatch.delenv("MEMROT_CRED_F002_B")
    report = audit_then_attack(
        None, TargetBinding(kind="mcp_client", binding={"base_url": http_mcp["url"]}),
        CHANNELS, top_n=1,
    )
    assert len(report.results) == 1
    assert report.results[0].verdict is Verdict.ERROR
    assert "missing credential" in report.results[0].error
    assert "MEMROT_CRED_F002_A" not in os.environ
    assert "MEMROT_CRED_F002_B" not in os.environ
    assert not http_mcp["records"]


def test_stdio_cross_user_is_skipped_before_starting_any_process(monkeypatch):
    spawned = []

    def forbidden(*args, **kwargs):
        spawned.append(True)
        raise AssertionError("cross-user must not start stdio")

    monkeypatch.setattr(mcp_client.subprocess, "Popen", forbidden)
    adapter = MCPClientAdapter(command="unused")
    tracer = JSONLTracer()
    result = run_variant(_variant(), CHANNELS, adapter, LiteralDetector(), tracer, "stdio-run")
    assert result.verdict is Verdict.NOT_EVALUATED
    assert "cannot switch authenticated principals" in result.limitations[0]
    assert [e.phase for e in tracer.events] == ["attempt_start", "skip", "verdict"]
    assert not spawned


@pytest.mark.parametrize("other", [B, Principal(principal_id="A", credential_ref="F002_B")])
def test_stdio_allows_same_binding_but_rejects_identity_switch(monkeypatch, other):
    messages = []
    instances = []

    class StdioStub:
        def __init__(self, *args, **kwargs):
            self.pending = []
            instances.append(self)

        def send(self, msg):
            messages.append(msg)
            if "id" not in msg:
                return
            result = ({"tools": [{"name": "chat", "annotations": {"readOnlyHint": True},
                                            "inputSchema": {"type": "object", "properties": {
                                                "message": {"type": "string"}, "session_id": {"type": "string"}}}}]} if msg["method"] == "tools/list"
                      else {"text": "hello"})
            self.pending.append({"id": msg["id"], "result": result})

        def recv(self, timeout):
            return self.pending.pop(0)

        def close(self):
            pass

    monkeypatch.setattr(mcp_client, "_StdioTransport", StdioStub)
    adapter = MCPClientAdapter(command="unused")
    assert _send(adapter, A) == "hello"
    assert _send(adapter, A) == "hello"
    before = len(messages)
    with pytest.raises(RuntimeError, match="stdio cannot switch principal"):
        _send(adapter, other)
    assert len(messages) == before
    assert len(instances) == 1
