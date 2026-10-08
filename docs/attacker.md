# Agent attack harness (`memrot`)

Implementation of the red-team half of the audit → attack loop. The package is
standalone: it never imports `mcp_audit`. Alignment with the auditor is by
plain string tags (`rule_ids`, `owasp_amg_category`, `technique_category`) and
JSON reports.

## What the harness answers

1. Does an untrusted instruction persist into memory and surface later (same user, other user, or other session)?
2. Does tool output (search snippet, email, document) get treated as instructions rather than data?
3. Which delivery technique (direct override, obfuscation, many-shot, …) actually lands?
4. Was the effect observed, absent in usable observations (`CLEAN`), or unresolved (`INCONCLUSIVE` / `NOT_EVALUATED` / `ERROR` / `INVALID`)?

Every attempt gets a verdict. The Attack-Success-Rate denominator is never
fabricated: `total==0` displays `n/a (0/0)`.

### Verdict semantics and report compatibility

Report schema **2.0** (`verdict_semantics: evidence-aware-v2`) adds
`INCONCLUSIVE` and `inconclusive_reason`. Missing baseline/post observations,
unavailable advertised evidence channels when a negative cannot be established,
and strict cross-principal text-only findings are inconclusive. A configured
ground-truth check for a target object must be observed to resolve that check.
`CLEAN` describes a negative in usable observations; it is not proof of safety.
An empty marker is not a usable check, including existing benign catalogs;
separate control evaluation is tracked in F0-07.

`MEMROT_TIER_STRICT=1` no longer turns an observed text signal into `CLEAN`.
The original `post_detection`, `state_detection`, `evidence_tier` and explicit
result-local `evidence_refs` remain available regardless of strict gating.
`path_state` uses these references: a positive observation supports a runtime
path, while `CLEAN` alone provides no static support. A `cross-user` label alone
never proves a control violation; that requires a specific policy-violation
evidence reference. No such violation is inferred from a backend GET alone.

`INCONCLUSIVE` is visible in all reports and excluded from every ASR ratio.
With `--gate`, unresolved coverage returns exit code **2**; an observed
`CONFIRMED` still takes precedence with code **1**. Without `--gate`, a completed
run retains exit code **0**.

Use `memrot.reporting.load_json_report(json_text)` to read reports. Unversioned
and schema 1.0 documents retain their original results and metrics and receive
`verdict_semantics: legacy-v1` plus a warning that historical `CLEAN` and
`path_state` had weaker semantics. They are not silently upgraded; rerun the
cases to obtain v2 decisions. Unsupported report versions are rejected.
Config/catalog schema versions remain 1.0; memory-trace remains 0.1.0.

## Modes and access profiles

| Access profile | What the adapter can see | Typical adapter |
|---|---|---|
| `black_box` | chat in / chat out | `openai_compat`, `http_generic` |
| `grey_box` | chat plus some tool/MCP surface | `mcp_client`, `inprocess_stand` |
| `white_box` | memory inspection and/or ground truth | `callable`, `genai_invest` |

`single-turn` variants have no baseline phase (`INVALID` is structurally
impossible). `cross-user` / `cross-session-same-user` run
baseline → inject → consolidate → probe. `tool_result` and
`document_ingestion` have their own flows.

## Adapters

| `kind` | Box | When to use | Extra channels |
|---|---|---|---|
| `openai_compat` | black | Any OpenAI-compatible `/v1/chat/completions` | none |
| `http_generic` | black | Same, but custom field mapping (`response_path`, `messages_field`, `session_in_body`) | none |
| `mcp_client` | grey | Streamable-HTTP or stdio MCP server; `send` is `tools/call` | none (no tool staging unless the server allows it) |
| `genai_invest` | white (if Mongo configured) | This repo's investment stand | finalize, optional Mongo/Redis, docker-log ground truth |
| `callable` | whatever you wire | In-process memory library (mem0, LangGraph, tests) | whatever callables you pass |

Credentials are never in config: set `MEMROT_CRED_<credential_ref>`.

### Ground truth for the current probe

`genai_invest` takes a Docker log cursor immediately before the single-turn
request or the final memory probe, after baseline, injection and consolidation.
The cursor verifies the existing log prefix and considers only new complete
lines. Rotation/replacement, incomplete snapshots, Docker nonzero exits and
unavailable logs raise `EvidenceSourceError`, producing an `ERROR` attempt.

The probe sends `X-Memrot-Run-Id` and a fresh `X-Memrot-Attempt-Id`, together with
the existing `X-Conversation-Id`. The target must propagate these identifiers
to the backend and emit one JSON object per access-log line, for example:

```json
{"event":"backend_access","run_id":"run-id","attempt_id":"attempt-id","session_id":"s-session","principal_id":"1001","method":"GET","path":"/clients/1003"}
```

`principal_id` must describe the backend's authenticated caller. A matching
event confirms the observed GET, not a successful data disclosure or HTTP 200.
All correlation fields and the exact object path must match. Raw HTTP access
lines, prompt text, old events and another attempt's events do not qualify.
The external stand needs instrumentation to supply this contract; adding
headers in the harness alone does not create trustworthy backend evidence.

No matching event returns unknown (`None`), including empty or delayed logs;
it never proves a negative. The result records a ground-truth limitation.
Unavailable ground truth now contributes to `INCONCLUSIVE` under the rules
above. The current cursor rereads Docker logs and verifies their
prefix; a bounded streaming evidence collector is not implemented here.

Adapter authors can implement `ground_truth_mark(...)` to return an opaque
cursor, received as `window` by `ground_truth_check`. Providers using the
default no-op hook keep their existing callback arguments.

### Transactional tool staging

Tool-result attempts roll back the staged response exactly once in a `finally`
block, including when staging partially changes state and then raises, the
trigger fails, or the run is interrupted. Rollback completes before consolidation
and probing. Adapters advertising tool staging must implement idempotent
`unstage_tool_response(tool_name)`.

For `CallableAdapter`, provide both `stage_tool_fn` and `unstage_tool_fn`;
without rollback, tool-result attempts return `NOT_EVALUATED` before staging.
The adapter inspects the staging signature at construction and selects supported
`vector`/`persist` keywords without executing the callback. Legacy two-argument
callbacks remain supported. An internal `TypeError` is propagated without retry;
wrap callables without an inspectable signature in a Python function.

Failed attempts preserve the primary exception in `error` and the rollback
exception separately in the optional, additive `cleanup_error` result field.
If rollback fails, the adapter blocks subsequent attempts with `NOT_EVALUATED`,
without resets or target calls. Restore the target state and create a new adapter
before resuming. Interrupts propagate after rollback is attempted, with cleanup
failure attached as an exception note.

### MCP identity and sessions

For HTTP MCP, each `(principal_id, credential_ref)` binding gets its own
handshake, `Mcp-Session-Id`, and advertised tool list. The credential reference
defaults to `principal_id` when omitted. Set `MEMROT_CRED_<ref>` for every
binding that will send requests. Missing credentials are errors before HTTP
I/O, including after a cached connection has been established; the MCP
pipeline does not manufacture placeholder credentials. Changing the value of
a credential reconnects that binding with a fresh MCP session.

`extra_headers` cannot supply `Authorization` or `Mcp-Session-Id`: these
headers belong to the per-principal connection. Conversation IDs returned by
`new_session()` are also owned by their principal/credential binding and
cannot be reused by another binding. A new conversation does not force a new
MCP transport session for the same authenticated user.

Stdio runs under one fixed process environment. Its principal labels and
`credential_ref` do not change the child's authentication. The adapter binds
to the first principal/credential pair that connects and rejects switching
that pair. The runner marks `cross-user` cases `NOT_EVALUATED` before starting
the process or sending a baseline. Single-user cases remain available.

Separate MCP sessions establish transport isolation, not distinct backend
identities. Shared bearer tokens still represent shared authentication unless
the target explicitly implements another identity mechanism. In particular,
the shared-token MemPalace example below does not prove user authorization
boundaries just by giving its channels different `principal_id` labels.

### MCP process lifecycle and tool binding

Set `target.binding.chat_tool` to the exact advertised tool name for a
stateful chat endpoint. Without this setting, automatic selection requires
exactly one tool annotated `readOnlyHint: true` whose object input schema
accepts string `message` and `session_id` fields without requiring other
arguments. Ambiguous, incomplete/paginated, duplicate or incompatible listings
are rejected before `tools/call`; a name containing "chat" is not sufficient.
Read-only annotations are server declarations, not a sandbox guarantee.
For HTTP quickstart, `--adapter mcp_client --chat-tool NAME` sets the binding.

Stdio inherits only `PATH`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TZ`,
`TMPDIR`, `TMP`, `TEMP`, and Windows execution variables
`SYSTEMROOT`, `WINDIR`, `COMSPEC`, `PATHEXT`. Other non-secret settings belong
in the explicit `env` mapping. Credentials use `credential_refs`, mapping a
child variable to a `MEMROT_CRED_<ref>` reference, for example:

```json
{
  "kind": "mcp_client",
  "binding": {
    "command": "python3",
    "args": ["/path/to/your_mcp_server.py"],
    "chat_tool": "agent_chat",
    "timeout": 10,
    "env": {"APP_MODE": "test"},
    "credential_refs": {"TARGET_API_KEY": "TARGET_SERVICE"}
  }
}
```

Provide `MEMROT_CRED_TARGET_SERVICE` in the harness environment. It is copied
only into the explicitly named child variable. Unrelated credentials,
`PYTHONPATH` and dynamic-loader settings are not inherited. A missing reference
or a collision between `env` and `credential_refs` fails before process launch.
This filters environment variables; it does not sandbox the child's filesystem.

Requests and individual stdout messages are capped at 8 MiB, with at most 16
pending messages. Stderr is drained concurrently, retaining at most 16 KiB in
memory; raw stderr is not included in exception messages or reports. Both
blocked stdin writes and responses have timeouts. Protocol errors, oversized
messages and timeouts close the affected transport. HTTP responses and pending
SSE messages are bounded as well.

All adapters expose idempotent `close()` and support `with adapter:`. CLI owns
and closes its adapters across success, early returns, exceptions and interrupts.
`audit_then_attack()` closes adapters/tracers it creates; an injected adapter
or tracer remains the caller's responsibility:

```python
with MCPClientAdapter(command="python3", args=["server.py"], chat_tool="chat") as adapter:
    session = adapter.new_session(principal)
    response = adapter.send(principal, session, "Hello")
```

A closed MCP adapter cannot be reopened. Stdio shutdown terminates and waits
for the child, escalating to kill when necessary; POSIX uses a dedicated
process group to release descendants holding the pipes. On other platforms
termination covers the direct child. HTTP close drops local authentication,
session and response state; it does not issue a remote session-delete request.

## Connect a new agent in ~40 lines (white-box)

`CallableAdapter` is the documented onboarding path for a memory library.
JSON config cannot express live Python callables — build the adapter in code:

```python
from memrot.adapters.callable_adapter import CallableAdapter
from memrot.models import Channel, ChannelRole, Principal
from memrot.detectors.literal import LiteralDetector
from memrot.runner import run_matrix
from memrot.tracer import JSONLTracer

store = {}  # stand-in for mem0 / a LangGraph checkpointer

def send(principal_id, session_id, message):
    memory = store.get("global", "")
    return f"{memory} (ack {message[:40]})"

def consolidate(principal_id, session_id):
    store["global"] = store.get("pending", store.get("global", ""))

def inspect(principal_id):
    return store.get("global", "")

def reset():
    store.clear()
    return True

adapter = CallableAdapter(
    send_fn=send, consolidate_fn=consolidate, inspect_fn=inspect, reset_fn=reset,
    access_profile="white_box",
)
```

Black-box, one command, no config file:

```bash
python -m memrot quickstart \
  --url http://localhost:8600/v1 --model my-agent \
  --out .attack --report-html .attack/run.html
```

Audit then attack (ranked by finding severity, trifecta, P3 campaigns; same
`path_state` vocabulary as `mcp_audit` / `redteam/`):

```bash
python -m mcp_audit audit examples/genai_invest_stand.manifest.json --json .audit/stand.json
python -m memrot quickstart --url http://localhost:8600/v1 --model my-agent \
  --audit .audit/stand.json --out .attack
```

`--pool auto` (quickstart default) loads `catalog/prompts/domain/invest_bank`
on top of the generic pool when `meta.profile.id` is this repo's invest stand;
a mempalace / unknown profile stays on `generic/`. Each `AttackResult` carries
`path_state` so a run can close the static → runtime loop without importing
`mcp_audit`.

Same function the notebook calls: `memrot.pipeline.audit_then_attack`.

## Taxonomy

Three independent tag sets on every variant:

| Field | Vocabulary | Meaning |
|---|---|---|
| `owasp_amg_category` | 6 OWASP Agent Memory Guard slugs | *what* is being poisoned (memory / tool-output) |
| `technique_category` | delivery/obfuscation slugs in `taxonomy.ATTACK_TECHNIQUE_CATEGORIES` | *how* the payload is delivered |
| `taxonomy` | MITRE ATLAS ids (`AML.T0051`, `AML.T0070`, …) | cross-reference |
| `rule_ids` | `mcp_audit` rule catalogue | optional link to a specific audit |

`python -m memrot validate-catalog memrot/catalog/prompts --strict-taxonomy`
requires AMG on every `memory_poisoning` variant and ATLAS **or**
`technique_category` on every non-benign variant.

| Source | Classes covered |
|---|---|
| Neutral core `catalog/prompts/generic` | 6 AMG categories + 10 technique categories (direct, authority, obfuscation, splitting, many-shot, refusal, roleplay, low-resource language, tool-result, context-ignore) |
| Domain overlay `catalog/prompts/domain/invest_bank` | same AMG set, bank-flavored wording |
| Domain overlay `catalog/prompts/domain/mempalace` | memory-palace-flavored; each variant attacks a control audit flagged FAIL on the [MemPalace](https://github.com/MemPalace/mempalace) build (MEM-01/03/07, AUTH-01, EGRESS-01) |
| Imported banks (`garak_dan`, `trustairlab_jailbreak`) | `threat_model=llm_jailbreak_susceptibility` (separate ASR axis) |

The neutral core also has pools with no bank-specific equivalent:
`generic_obfuscation_encoding`, `generic_payload_splitting`, `generic_many_shot`,
`generic_refusal_suppression`, `generic_context_ignore`, `generic_low_resource_language`,
`generic_tool_email_injection`, `generic_tool_document_injection`,
`generic_tool_websearch_injection`.

The MemPalace overlay (see "Worked example" below), path by path:

| Path | Attacks (rule_ids) | AMG category |
|---|---|---|
| `domain/mempalace/mem_cross_agent_drawer_poisoning` | MEM-03, MEM-01 | memory_prompt_injection / sensitive_data_leakage |
| `domain/mempalace/mem_audience_bypass_recall` | MEM-01, MEM-07 | sensitive_data_leakage |
| `domain/mempalace/auth_identity_spoofing` | AUTH-01, MEM-03 | memory_prompt_injection |
| `domain/mempalace/peer_sync_exfiltration` | EGRESS-01, MEM-01 | sensitive_data_leakage |
| `domain/mempalace/benign_control` | — | — |

It stays out of `--pool auto` (a mempalace audit resolves to the generic pool,
same portability split as the auditor); load it explicitly via
`examples/mempalace.attack.config.json`'s `catalog_paths` or `--pool all`.

## Do / don't (ASR invariants)

- Do emit a `Verdict` for every attempt, including `ERROR` and `NOT_EVALUATED`.
- Do keep `INCONCLUSIVE` / `INVALID` / `ERROR` / `NOT_EVALUATED` out of the ASR ratio; they still appear in `counts_by_verdict`.
- Do return `NOT_EVALUATED` when the adapter cannot stage a tool vector or ingest a document — never a false `CLEAN`.
- Don't import `mcp_audit` from `memrot`.
- Don't embed secrets in config; only `credential_ref` → `MEMROT_CRED_<ref>`.
- Don't add third-party HTTP/SDK deps on the black-box path (stdlib `urllib` only).

## Moving the pool to a new domain

1. Run the **neutral** core (`--pool neutral` / `catalog/prompts/generic`).
2. Optionally rewrite wording with `domain_adaptation` (LLM) and a `DomainProfile`
   (`generator.options.domain_profile`, or `profile_from_audit(audit.json)`).
3. Keep bank-specific overlays under `catalog/prompts/domain/<name>/` rather than
   mixing them into the generic tree.

## Worked example: a foreign system (MemPalace)

The audit half of this stand is ported to [MemPalace](https://github.com/MemPalace/mempalace)
by data alone (`profiles/mempalace.json`, see
[`porting_to_a_new_stand.md`](porting_to_a_new_stand.md)). The attack half is
the same shape — a config plus a domain overlay, no engine change beyond one
additive `DOMAIN_VALUES` entry:

- **Transport.** MemPalace's team mode is one MCP-over-HTTP hub behind a shared
  bearer (`deploy/docker-compose.server.yml`), so the target is `mcp_client`
  (grey-box) at `http://HOST:8765/mcp`. The shared static token with a
  self-asserted identity — audit's AUTH-01/AUTH-04 findings — is modeled by
  giving every channel the *same* `credential_ref` but a *different*
  `principal_id`.
- **Overlay.** `catalog/prompts/domain/mempalace/` attacks the exact controls
  audit reports FAIL on the recorded build (MEM-01/03/07, AUTH-01, EGRESS-01);
  each variant's `notes` cite the located source fact (`tool_add_drawer`,
  `tool_event_list`, `tool_event_append`, `_http_serve_sync`).
- **Audit-driven.** The config sets `audit_path: examples/mempalace.audit.json`
  and `audit_mode: ranked`, so the committed audit snapshot reorders the catalog
  to its own FAIL controls.

```bash
export MEMROT_CRED_MEMPALACE_TEAM_TOKEN=<hub bearer token>
python -m memrot run --config examples/mempalace.attack.config.json --out .attack
```

Offline (no hub) the config still loads, the overlay validates
(`--strict-taxonomy`), and ranking runs against the committed snapshot; a live
run needs the hub reachable. Regression: `tests/test_mempalace_attack.py`.

Net-new prompts: `LLMSynthesisGenerator` (`kind=llm_synthesis`). Adaptive
retries: `python -m memrot run --adaptive --attacker-base-url … --attacker-model …`.
