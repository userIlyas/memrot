# Roadmap implementation progress

Branch: `feature/memory-trace-v0.1`.
The supplied [roadmap](ROADMAP_memrot.md) is retained unchanged; its audit
describes the original `26b794a` snapshot, not the current implementation.

## F0-01 — reproducible installation and full test discovery

Implemented:

- Python 3.12+ package metadata, runtime dependencies and optional/dev extras.
- Hashed development dependency lock, including the editable build backend.
- Wheels containing schemas, profiles, lexicon, catalogs and imported notices.
- Resource lookup independent of the working directory, with editable support.
- Default discovery of both `tests/` and `memory_trace/tests/`.
- `python -m memrot.smoke`: deterministic positive/negative memory fixtures,
  trace validation and JSON/Markdown/HTML rendering, without network access.
- Installation regressions that build a wheel and execute it outside the checkout.
- Linux CI for the full suite and sdist/wheel installation; separate Windows smoke job.
- Corrected installation and offline quickstart documentation.

Local Linux/Python 3.12 validation:

- Editable dev installation and `pip check` succeeded.
- `python -m pytest -ra`: **412 passed, 5 skipped**. The skips require the
  separate target stand; they are not counted as passing tests.
- Strict taxonomy validation: **26 catalog files, zero errors**.
- sdist and wheel built successfully; installation tests ran both CLIs and
  the smoke workflow outside the checkout.
- A fresh wheel-only venv with just declared runtime dependencies passed
  `pip check`, both CLI help commands and the offline smoke (six valid events).

GitHub Actions and Windows execution require a CI run; local Linux validation
does not establish their results. Fixture verdicts validate harness behavior,
not the security of a real target.

## F0-02 — MCP authorization per principal

Implemented:

- Separate HTTP transports, MCP sessions, RPC counters and tool inventories
  per `(principal_id, credential_ref)` binding.
- Credential resolution on each send: a missing value fails before HTTP I/O,
  and rotation reconnects only the affected binding.
- Conversation ownership checks and rejection of fixed identity/session headers.
- Failed handshakes are discarded without replacing another user's connection.
- MCP pipeline no longer creates placeholder credentials.
- Stdio binds to one principal/credential pair; unsupported cross-user cases
  return `NOT_EVALUATED` before starting a process or sending a baseline.
- Documented the difference between transport/session isolation and actual
  backend identity, including shared-token limitations.

Validation on Linux/Python 3.12:

- 17 new regression cases in `tests/test_attack_mcp_identity.py`, including a
  local HTTP server that checks A → B → A authentication, per-user tool lists,
  session ownership, credential rotation, missing credentials, handshake retry,
  pipeline behavior and stdio rejection.
- Full `python -m pytest -ra`: **429 passed, 5 skipped** (external stand absent).
- The full suite also passed the F0-01 wheel installation checks.

## F0-03 — managed MCP transport lifecycle

Implemented:

- Allowlisted child environment with explicit `env` and `credential_refs` mappings.
- Bounded stdout messages/queues, continuously drained stderr with a 16 KiB tail,
  and timeouts for blocked stdin writes as well as responses.
- Process termination, escalation, reaping and pipe/thread cleanup; POSIX process
  groups also release descendants holding the transport pipes.
- Idempotent adapter `close()` and context-manager support, with cleanup covering
  CLI/pipeline early returns, setup/reporting failures and interrupts.
- Explicit tool binding or unique compatible read-only selection; ambiguous,
  duplicate and incomplete lists fail before `tools/call`.
- Bounded HTTP/SSE responses and release of HTTP error response handles.
- MCP quickstart accepts `--chat-tool` and avoids passing HTTP-chat model options
  to the MCP adapter.

Validation on Linux/Python 3.12:

- 40 lifecycle regression cases, including actual child processes for environment
  isolation, stderr pressure, blocked writes, timeouts, signal escalation,
  descendant cleanup and CLI/pipeline ownership.
- Full `python -m pytest -ra`: **469 passed, 5 skipped** (external stand absent).
- No live MCP target or Windows lifecycle run was used for this validation.

## F0-04 — transactional tool staging

Implemented:

- Guaranteed, single rollback after staging/trigger, including partial staging,
  detector/tracer failures and cancellation; rollback precedes consolidation.
- Separate primary `error` and additive `cleanup_error` result fields.
- Failed rollback blocks subsequent attempts and resets on the same adapter;
  adaptive execution stops on `ERROR` or `NOT_EVALUATED`.
- Callable signature compatibility is selected by introspection at construction;
  internal `TypeError` never causes a second staging invocation.
- Callable tool staging requires an explicit rollback callback; legacy staging
  signatures remain supported.

Validation on Linux/Python 3.12:

- 24 new regression cases covering partial staging, trigger/session/detector/
  tracer failures, cleanup failure, cancellation, next-attempt isolation and
  callable signatures.
- Targeted staging/adaptive/reporting tests: **50 passed**.
- Full `python -m pytest -ra`: **493 passed, 5 skipped** (stand source/dependencies
  unavailable). `git diff --check` passed.

## F0-05 — ground truth scoped to the current probe

Implemented:

- Optional adapter cursor hook immediately before the observed request; memory
  flows mark after baseline, injection and consolidation.
- GenAI Invest checks only new complete backend log events, matching run,
  unique attempt, session, authenticated principal and exact object path.
- Probe headers carry run/attempt correlation; existing session headers remain.
- Docker failures, unavailable logs and invalidated cursors produce evidence
  source errors instead of false negatives. Missing correlation returns unknown,
  with a result limitation rather than a negative ground-truth detection.
- Existing providers using the no-op cursor hook retain their callback arguments.

Validation on Linux/Python 3.12:

- 34 new regression cases covering historical/foreign events, exact paths,
  absent correlation, incomplete logs, Docker errors/timeouts, rotation, request
  headers and runner ordering/attempt uniqueness.
- Targeted ground-truth/runner tests: **43 passed**.
- Full `python -m pytest -ra`: **527 passed, 5 skipped** (stand source/dependencies
  unavailable). `git diff --check` passed.

The external stand must propagate the correlation headers and emit the documented
structured backend events. No live stand was used; plain access logs now yield
unknown. The cursor currently rereads Docker logs and verifies their prefix.
## F0-06 — unknown outcomes distinct from CLEAN

Implemented:

- `INCONCLUSIVE` with an explicit reason for insufficient observation, including
  strict cross-principal text-only results and unresolved object ground truth.
- Detection availability is separate from a negative detection; missing replies,
  baselines or memory reads cannot silently become negative observations.
- Text/state detections and their result-local evidence references remain in the
  report. Path support derives from specific evidence references; neither CLEAN
  nor a cross-user label establishes static support or a control violation.
- INCONCLUSIVE is excluded from ASR, visible in JSON/Markdown/HTML and terminal
  summaries, and returns incomplete (2) with `--gate` unless CONFIRMED takes
  precedence (1).
- Report schema 2.0 / engine 2.0.0, with explicit evidence-aware-v2 semantics.
  `load_json_report` preserves old results and metrics, labeling unversioned/1.0
  reports legacy-v1 instead of silently reinterpreting their outcomes.

Validation on Linux/Python 3.12:

- 20 added regression cases plus updated strict/path-state expectations cover
  observation gaps, preserved signals, ASR exclusion, CLI gate, report rendering,
  evidence references and version-aware legacy reading.
- Full `python -m pytest -ra`: **547 passed, 5 skipped** (stand source/dependencies
  unavailable). `git diff --check` passed.

Existing benign cases without a checkable marker now remain inconclusive;
separate control evaluation and metric grouping are the next stage.

Next: **F0-07**, separate attack, benign and diagnostic metrics. F0-07 and
subsequent tasks remain outstanding.
