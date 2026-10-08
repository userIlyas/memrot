"""Grey-box adapter for an MCP server (streamable-HTTP or stdio).

Minimal JSON-RPC 2.0 client copied in spirit from ``mcp_audit.discovery.introspector``
but **not imported** from it -- this package must stay independent of ``mcp_audit``.
Handshake is lazy (constructor never requires a live server) so JSON config can
instantiate the adapter without a running process.

HTTP caches a separate authenticated connection for each principal/credential
binding; conversation IDs never act as authentication. Stdio has one fixed
process identity and cannot evaluate cross-user propagation.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import queue
import re
import signal
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..models import Principal
from .base import AdapterCapabilities, TargetAdapter
from .openai_compat import credential_for

PROTOCOL_VERSION = "2025-06-18"
CLIENT_INFO = {"name": "mcp-attack", "version": "1.0.0"}
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


# Only execution/locale/temp-path settings are inherited. Authentication and
# interpreter injection variables require an explicit binding instead.
STDIO_ENV_ALLOWLIST = frozenset({
    "PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR", "TMP", "TEMP",
    "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT",
})
MAX_PENDING_MESSAGES = 16
MAX_STDERR_BYTES = 16 * 1024
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _child_env(env: Dict[str, str], credential_refs: Dict[str, str]) -> Dict[str, str]:
    if env.keys() & credential_refs.keys():
        raise ValueError("stdio env and credential_refs must not set the same variable")
    for name, value in {**env, **credential_refs}.items():
        if not isinstance(name, str) or not _ENV_NAME.fullmatch(name) or not isinstance(value, str):
            raise ValueError("stdio environment bindings require valid variable names and string values")
    child = {name: value for name, value in os.environ.items()
             if name.upper() in STDIO_ENV_ALLOWLIST}
    child.update(env)
    for name, ref in credential_refs.items():
        if not _ENV_NAME.fullmatch(ref):
            raise ValueError("stdio credential_refs must name MEMROT_CRED_ references")
        child[name] = credential_for(Principal(principal_id="stdio", credential_ref=ref))
    return child


class _StdioTransport:
    def __init__(self, command: str, args: List[str], env: Optional[Dict[str, str]] = None,
                 cwd: Optional[str] = None, *, credential_refs: Optional[Dict[str, str]] = None,
                 timeout: float = 20.0) -> None:
        child = _child_env(dict(env or {}), dict(credential_refs or {}))
        exe = shutil.which(command, path=child.get("PATH", os.defpath)) or command
        self._timeout = timeout
        self._closed = False
        self._stop = threading.Event()
        self._failure: Optional[BaseException] = None
        self._q: queue.Queue = queue.Queue(maxsize=MAX_PENDING_MESSAGES)
        self._writes: queue.Queue = queue.Queue(maxsize=1)
        self.stderr_tail = bytearray()
        self.proc = subprocess.Popen(
            [exe, *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=child, cwd=cwd, start_new_session=(os.name == "posix"),
        )
        self._reader = threading.Thread(target=self._pump, daemon=True)
        self._stderr_reader = threading.Thread(target=self._drain_stderr, daemon=True)
        self._writer = threading.Thread(target=self._write_loop, daemon=True)
        try:
            for thread in (self._reader, self._stderr_reader, self._writer):
                thread.start()
        except BaseException:
            self.close()
            raise

    def _fail(self, message: str) -> None:
        if self._failure is None:
            self._failure = RuntimeError(message)
        try:
            self._q.put_nowait(None)  # wake a waiting receiver, including at EOF
        except queue.Full:
            pass

    def _pump(self) -> None:
        assert self.proc.stdout is not None
        try:
            while not self._stop.is_set():
                line = self.proc.stdout.readline(MAX_RESPONSE_BYTES + 1)
                if not line:
                    try:
                        self._q.put_nowait(None)
                    except queue.Full:
                        pass
                    return
                if len(line) > MAX_RESPONSE_BYTES:
                    self._fail("MCP stdout message exceeds size limit")
                    return
                if not line.strip():
                    continue
                try:
                    message = json.loads(line)
                except (ValueError, UnicodeError):
                    self._fail("MCP stdout contains invalid JSON")
                    return
                if not isinstance(message, dict):
                    self._fail("MCP stdout message must be a JSON object")
                    return
                try:
                    self._q.put_nowait(message)
                except queue.Full:
                    self._fail("MCP stdout pending message limit exceeded")
                    return
        except OSError:
            self._fail("MCP stdout read failed")

    def _drain_stderr(self) -> None:
        assert self.proc.stderr is not None
        try:
            while not self._stop.is_set():
                chunk = self.proc.stderr.read1(4096)
                if not chunk:
                    return
                self.stderr_tail.extend(chunk)
                del self.stderr_tail[:-MAX_STDERR_BYTES]
        except OSError:
            self._fail("MCP stderr read failed")

    def _write_loop(self) -> None:
        assert self.proc.stdin is not None
        while not self._stop.is_set():
            try:
                payload, done, errors = self._writes.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                self.proc.stdin.write(payload)
                self.proc.stdin.flush()
            except OSError:
                errors.append(RuntimeError("MCP stdin write failed"))
            finally:
                done.set()

    def send(self, msg: Dict[str, Any]) -> None:
        if self._closed:
            raise RuntimeError("MCP transport is closed")
        payload = (json.dumps(msg) + "\n").encode("utf-8")
        try:
            if self._failure:
                raise self._failure
            if len(payload) > MAX_RESPONSE_BYTES:
                raise RuntimeError("MCP request exceeds size limit")
            done, errors = threading.Event(), []
            deadline = time.monotonic() + self._timeout
            try:
                self._writes.put((payload, done, errors), timeout=self._timeout)
            except queue.Full:
                raise TimeoutError("timed out writing to MCP server") from None
            if not done.wait(max(0, deadline - time.monotonic())):
                raise TimeoutError("timed out writing to MCP server")
            if errors:
                raise errors[0]
        except BaseException:
            self.close()
            raise

    def recv(self, timeout: float) -> Optional[Dict[str, Any]]:
        if self._closed:
            raise RuntimeError("MCP transport is closed")
        try:
            if self._failure:
                raise self._failure
            try:
                message = self._q.get(timeout=timeout)
            except queue.Empty:
                raise TimeoutError("timed out waiting for MCP server response") from None
            if self._failure:
                raise self._failure
            if message is None:
                raise RuntimeError("MCP server closed stdout")
            return message
        except BaseException:
            self.close()
            raise

    def _signal(self, sig: int) -> None:
        try:
            if os.name == "posix":
                os.killpg(self.proc.pid, sig)
            elif self.proc.poll() is None:
                self.proc.terminate() if sig == signal.SIGTERM else self.proc.kill()
        except ProcessLookupError:
            pass

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._stop.set()
        # Terminate before closing buffered stdin: a writer may hold its lock
        # while the child is not reading. Reap even after escalation to kill.
        self._signal(signal.SIGTERM)
        try:
            self.proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            self._signal(signal.SIGKILL if os.name == "posix" else 9)
            self.proc.wait(timeout=1)
        if os.name == "posix":
            # Also release pipes held by descendants in the child's group.
            self._signal(signal.SIGKILL)
        for thread, stream in ((self._writer, self.proc.stdin),
                               (self._reader, self.proc.stdout),
                               (self._stderr_reader, self.proc.stderr)):
            if thread.ident is not None:
                thread.join(timeout=1)
            if not thread.is_alive() and stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        while not self._q.empty():
            self._q.get_nowait()


class _HttpTransport:
    def __init__(self, url: str, headers: Optional[Dict[str, str]] = None, timeout: float = 20.0) -> None:
        self.url = url
        self.headers = dict(headers or {})
        self.session_id: Optional[str] = None
        self._timeout = timeout
        self._pending: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=MAX_PENDING_MESSAGES)
        self._closed = False

    def send(self, msg: Dict[str, Any]) -> None:
        if self._closed:
            raise RuntimeError("MCP transport is closed")
        body = json.dumps(msg).encode("utf-8")
        if len(body) > MAX_RESPONSE_BYTES:
            raise RuntimeError("MCP request exceeds size limit")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            **self.headers,
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        req = urllib.request.Request(self.url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                sid = resp.headers.get("Mcp-Session-Id")
                if sid:
                    self.session_id = sid
                ctype = resp.headers.get("Content-Type", "")
                data = resp.read(MAX_RESPONSE_BYTES + 1)
                if len(data) > MAX_RESPONSE_BYTES:
                    raise RuntimeError("MCP HTTP response exceeds size limit")
                raw = data.decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            exc.close()
            raise RuntimeError(f"HTTP {exc.code} from {self.url}") from exc
        if not raw.strip():
            return
        if "text/event-stream" in ctype:
            for evt in _parse_sse(raw):
                self._enqueue(evt)
        else:
            self._enqueue(json.loads(raw))

    def _enqueue(self, message: Any) -> None:
        if not isinstance(message, dict):
            raise RuntimeError("MCP HTTP message must be a JSON object")
        try:
            self._pending.put_nowait(message)
        except queue.Full:
            raise RuntimeError("MCP HTTP pending message limit exceeded") from None

    def recv(self, timeout: float) -> Optional[Dict[str, Any]]:
        if self._closed:
            raise RuntimeError("MCP transport is closed")
        try:
            return self._pending.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError("timed out waiting for MCP server response")

    def close(self) -> None:
        self._closed = True
        self.session_id = None
        self.headers.clear()
        while not self._pending.empty():
            self._pending.get_nowait()


def _parse_sse(raw: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    data_lines: List[str] = []
    for line in raw.splitlines() + [""]:
        if line.startswith("data:"):
            data_lines.append(line[5:].strip())
        elif line == "":
            if data_lines:
                try:
                    out.append(json.loads("\n".join(data_lines)))
                except json.JSONDecodeError:
                    pass
                if len(out) > MAX_PENDING_MESSAGES:
                    raise RuntimeError("MCP HTTP pending message limit exceeded")
                data_lines = []
    return out


@dataclass
class _Connection:
    transport: Any = field(repr=False)
    credential_digest: str = field(default="", repr=False)
    rpc_id: int = 0
    tools: List[Dict[str, Any]] = field(default_factory=list)
    tools_complete: bool = True


class MCPClientAdapter(TargetAdapter):
    kind = "mcp_client"
    adapter_version = "1.2.0"

    def __init__(self, *, base_url: Optional[str] = None, command: Optional[str] = None,
                 args: Optional[List[str]] = None, timeout: float = 20.0,
                 chat_tool: Optional[str] = None, extra_headers: Optional[Dict[str, str]] = None,
                 env: Optional[Dict[str, str]] = None,
                 credential_refs: Optional[Dict[str, str]] = None) -> None:
        if not base_url and not command:
            raise ValueError("mcp_client adapter requires base_url (streamable-HTTP) or command (stdio)")
        if timeout <= 0 or not math.isfinite(timeout):
            raise ValueError("MCP timeout must be finite and positive")
        self.base_url = (base_url or "").rstrip("/")
        self.command = command
        self.args = list(args or [])
        self.timeout = timeout
        self.chat_tool = chat_tool
        self.extra_headers = dict(extra_headers or {})
        if any(name.lower() in ("authorization", "mcp-session-id") for name in self.extra_headers):
            raise ValueError("MCP Authorization and Mcp-Session-Id headers are managed per principal; "
                             "use credential_ref for bearer authentication")
        self.env = dict(env or {})
        self.credential_refs = dict(credential_refs or {})
        self._closed = False
        self._connections: Dict[tuple[str, str], _Connection] = {}
        self._session_owners: Dict[str, tuple[str, str]] = {}
        self._stdio_binding: Optional[tuple[str, str]] = None

    @staticmethod
    def _binding(principal: Principal) -> tuple[str, str]:
        return principal.principal_id, principal.credential_ref or principal.principal_id

    def _ensure_connected(self, principal: Principal) -> _Connection:
        if self._closed:
            raise RuntimeError("MCP adapter is closed")
        binding = self._binding(principal)
        if self.command:
            # A child process has one fixed environment/identity. Changing a
            # harness label cannot authenticate another user inside it.
            if self._stdio_binding is not None and self._stdio_binding != binding:
                raise RuntimeError("MCP stdio cannot switch principal or credential binding; "
                                   "use an HTTP endpoint with per-principal credentials")
            if binding in self._connections:
                return self._connections[binding]
            connection = _Connection(_StdioTransport(
                self.command, self.args, env=self.env,
                credential_refs=self.credential_refs, timeout=self.timeout,
            ))
        else:
            # Resolve on every send: removed/rotated credentials must never
            # silently reuse a connection authenticated with an old value.
            credential = credential_for(principal)
            digest = hashlib.sha256(credential.encode("utf-8")).hexdigest()
            existing = self._connections.get(binding)
            if existing is not None:
                if existing.credential_digest == digest:
                    return existing
                del self._connections[binding]
                existing.transport.close()
            headers = {**self.extra_headers, "Authorization": f"Bearer {credential}"}
            connection = _Connection(
                _HttpTransport(self.base_url, headers=headers, timeout=self.timeout), digest,
            )
        try:
            self._request(connection, "initialize", {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": CLIENT_INFO,
            })
            self._notify(connection, "notifications/initialized")
            listed = self._request(connection, "tools/list", {}) or {}
            connection.tools = list(listed.get("tools") or [])
            connection.tools_complete = not bool(listed.get("nextCursor"))
            self._pick_chat_tool(connection)
        except BaseException:
            # A partial handshake must not leave a reusable authenticated session.
            connection.transport.close()
            raise
        self._connections[binding] = connection
        if self.command:
            self._stdio_binding = binding
        return connection

    def _request(self, connection: _Connection, method: str,
                 params: Optional[Dict[str, Any]] = None) -> Any:
        try:
            return self._request_connected(connection, method, params)
        except BaseException:
            connection.transport.close()
            for binding, cached in list(self._connections.items()):
                if cached is connection:
                    del self._connections[binding]
            raise

    def _request_connected(self, connection: _Connection, method: str,
                           params: Optional[Dict[str, Any]] = None) -> Any:
        connection.rpc_id += 1
        rid = connection.rpc_id
        msg: Dict[str, Any] = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            msg["params"] = params
        deadline = time.monotonic() + self.timeout
        connection.transport.send(msg)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"timeout waiting for {method}")
            resp = connection.transport.recv(remaining)
            if resp is None:
                raise RuntimeError(f"MCP server closed during {method}")
            if resp.get("id") != rid:
                continue
            if "error" in resp:
                err = resp["error"] or {}
                raise RuntimeError(str(err.get("message", "rpc error")))
            return resp.get("result")

    def _notify(self, connection: _Connection, method: str,
                params: Optional[Dict[str, Any]] = None) -> None:
        msg: Dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        connection.transport.send(msg)

    def _pick_chat_tool(self, connection: _Connection) -> str:
        tools = [t for t in connection.tools if isinstance(t, dict) and isinstance(t.get("name"), str)]
        if self.chat_tool:
            if sum(t["name"] == self.chat_tool for t in tools) != 1:
                raise RuntimeError("configured MCP chat_tool must be advertised exactly once")
            return self.chat_tool
        candidates = []
        for tool in tools:
            schema = tool.get("inputSchema") or {}
            annotations = tool.get("annotations") or {}
            if not isinstance(schema, dict) or not isinstance(annotations, dict):
                continue
            props = schema.get("properties") or {}
            required = schema.get("required", [])
            if (annotations.get("readOnlyHint") is True and schema.get("type") == "object"
                    and isinstance(props, dict) and isinstance(required, list)
                    and all(name in ("message", "session_id") for name in required)
                    and all(isinstance(props.get(name), dict) and props[name].get("type") == "string"
                            for name in ("message", "session_id"))):
                candidates.append(tool["name"])
        if (connection.tools_complete and len(candidates) == 1
                and sum(t["name"] == candidates[0] for t in tools) == 1):
            return candidates[0]
        raise RuntimeError("set chat_tool explicitly: MCP requires one unambiguous read-only "
                           "tool accepting message and session_id")

    def new_session(self, principal: Principal) -> str:
        if self._closed:
            raise RuntimeError("MCP adapter is closed")
        session = f"s-{uuid.uuid4().hex[:12]}"
        self._session_owners[session] = self._binding(principal)
        return session

    def send(self, principal: Principal, session_id: str, message: str) -> str:
        binding = self._binding(principal)
        owner = self._session_owners.get(session_id)
        if owner is not None and owner != binding:
            raise RuntimeError("MCP conversation session belongs to a different principal or credential binding")
        connection = self._ensure_connected(principal)
        self._session_owners[session_id] = binding
        tool = self._pick_chat_tool(connection)
        result = self._request(connection, "tools/call", {
            "name": tool,
            "arguments": {"message": message, "session_id": session_id},
        })
        if isinstance(result, dict):
            content = result.get("content")
            if isinstance(content, list) and content:
                first = content[0]
                if isinstance(first, dict) and "text" in first:
                    return str(first["text"])
            if "text" in result:
                return str(result["text"])
            return json.dumps(result, ensure_ascii=False)
        return "" if result is None else str(result)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        connections = list(self._connections.values())
        self._connections.clear()
        self._session_owners.clear()
        self._stdio_binding = None
        first_error = None
        for connection in connections:
            try:
                connection.transport.close()
            except Exception as exc:
                if first_error is None:
                    first_error = exc
        if first_error is not None:
            raise first_error

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(
            access_profile="grey_box",
            supports_tool_staging=False,
            supports_principal_switch=not bool(self.command),
            notes=["MCP handshake is lazy; tool staging is not available unless the server exposes it",
                   "stdio uses one fixed process identity; principal labels and credential_ref do not "
                   "change its authentication" if self.command else
                   "HTTP connections and MCP sessions are isolated by principal and credential binding; "
                   "distinct sessions do not prove distinct backend identities"],
        )
