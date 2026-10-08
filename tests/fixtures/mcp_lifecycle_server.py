"""Local subprocess fixture for MCP lifecycle tests; never contacts a target."""
import json
import os
import signal
import subprocess
import sys
import threading

MODE = os.environ.get("MCP_TEST_MODE", "normal")
LOG = os.environ.get("MCP_TEST_LOG")

if MODE == "ignore_term":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)


def tool(name="chat", readonly=True):
    return {"name": name, "annotations": {"readOnlyHint": readonly},
            "inputSchema": {"type": "object", "properties": {
                "message": {"type": "string"}, "session_id": {"type": "string"}}}}


for line in sys.stdin.buffer:
    request = json.loads(line)
    method = request["method"]
    if LOG:
        with open(LOG, "a", encoding="utf-8") as output:
            output.write(json.dumps({"method": method, "pid": os.getpid()}) + "\n")
    if "id" not in request:
        continue
    if method == "initialize":
        if MODE == "hang_initialize":
            threading.Event().wait()
        result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                  "serverInfo": {"name": "fixture", "version": "1"}}
    elif method == "tools/list":
        tools = [tool()]
        if MODE == "ambiguous":
            tools.append(tool("other_chat"))
        elif MODE == "write_tool":
            tools = [tool("chat", readonly=False)]
        elif MODE == "wrong_shape":
            tools[0]["inputSchema"] = {"type": "object", "properties": {"path": {"type": "string"}}}
        elif MODE == "empty":
            tools = []
        elif MODE == "duplicate":
            tools.append(tool())
        elif MODE == "mixed_duplicate":
            tools.append(tool(readonly=False))
        result = {"tools": tools}
        if MODE == "paginated":
            result["nextCursor"] = "more-tools"
    elif method == "tools/call":
        if MODE == "descendant":
            child = subprocess.Popen([sys.executable, "-c", "import threading; threading.Event().wait()"])
            def stop(signum, frame):
                child.wait(timeout=2)  # the group signal must reach the child too
                raise SystemExit(0)
            signal.signal(signal.SIGTERM, stop)
            with open(os.environ["MCP_TEST_CHILD_PID"], "w") as output:
                output.write(str(child.pid))
        if MODE in ("hang_call", "ignore_term"):
            threading.Event().wait()
        if MODE == "stderr":
            sys.stderr.buffer.write(b"diagnostic\n" * 100_000)
            sys.stderr.buffer.flush()
        if MODE == "oversize":
            sys.stdout.buffer.write(b"x" * 2048 + b"\n")
            sys.stdout.buffer.flush()
            threading.Event().wait()
        if MODE == "invalid_json":
            print("not-json", flush=True)
            threading.Event().wait()
        if MODE == "array":
            print("[]", flush=True)
            threading.Event().wait()
        text = "hello"
        if MODE == "env":
            text = json.dumps({
                "names": sorted(os.environ),
                "credential_ok": os.environ.get("TARGET_KEY") == "fixture-token",
                "setting": os.environ.get("EXPLICIT_SETTING"),
            })
        result = {"content": [{"type": "text", "text": text}]}
    else:
        raise RuntimeError("unexpected method")
    print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)
