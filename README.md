<p align="center">
  <img src="docs/assets/banner.png" alt="memrot" width="1000">
</p>

<p align="center">
  A  multi-step audit && attack harness for AI-agent memory and tool compromise.
</p>

---

`memrot` tests whether an attacker can poison an AI agent's persistent
memory or state so that it later performs an unauthorized action — not just
whether one chat turn can be jailbroken. It plants a payload, waits, and
checks a *different* session, user, or turn to see if the payload survived
and did something.

## Why this exists

Off-the-shelf red-teaming tools (Garak, Promptfoo, and similar) treat an
agent like a one-session chatbot: send a prompt, grade the reply. That misses most of an
agent's real attack surface, which looks like this:

```
input → context → memory → planning → tool choice → tool arguments →
tool result → state change → a later, unrelated action
```

A successful attack doesn't have to produce a visibly malicious reply in the
same turn. It can write a poisoned "fact" into long-term memory that
resurfaces for a *different user* two sessions later, or get a tool result
treated as an instruction instead of data. Checking only the final response
misses exactly this class of compromise — so `memrot` checks state, not just
replies.

## What it answers

1. Does an untrusted instruction persist into memory and surface later (same
   user, other user, or other session)?
2. Does tool output (a search snippet, an email, a document) get treated as
   instructions rather than data?
3. Which delivery technique (direct override, obfuscation, many-shot, …)
   actually lands?
4. When a run is incomplete, was that a genuine miss (`CLEAN`) or a coverage
   gap (`NOT_EVALUATED` / `ERROR` / `INVALID`)?

Every attempt gets one of five verdicts, and the ASR (Attack Success Rate)
denominator is never fabricated: a category nobody could test displays
`n/a (0/0)`, never a silent 0%.

## Quickstart — offline, no target or API key

```bash
git clone https://github.com/userIlyas/memrot.git
cd memrot
git switch feature/memory-trace-v0.1
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m memrot.smoke
```

Requires Python 3.12 or newer; Linux/Python 3.12 is the primary test target.
The smoke command uses deterministic in-memory targets, validates bundled
schemas/catalogs, emits and validates memory traces, and exercises the report
renderers. It makes no network requests, including localhost or Presidio.
Expected fixture outcomes are `persistent: CONFIRMED` and `nonpersistent: CLEAN`.
These check the harness installation, not the security of a real agent.

The optional [quickstart notebook](examples/notebooks/memrot_quickstart.ipynb)
can be run after `python -m pip install -e '.[notebook]'`. Unlike the smoke
command, that notebook tries a stand at `localhost:8600` before falling back
to an in-memory target.

For the richer, real-target demo — real tool-poisoning, a real attacker LLM,
an imported jailbreak bank, all against a genuinely running stand — see
[`memrot_full_demo.ipynb`](examples/notebooks/memrot_full_demo.ipynb)
(needs a running target and real LLM API keys; its own intro cell spells out
exactly what).

## Installation

Install from the repository root in a virtual environment:

```bash
python -m pip install .
python -m memrot --help
python -m mcp_audit --help
```

Use `python -m pip install -e '.[dev]'` for an editable development install.
On Windows, activate the venv with `.venv\Scripts\Activate.ps1`; CI runs a
separate Windows installation smoke check. The full offline suite targets Linux.

The memory-trace runtime requires Pydantic 2, `jsonschema`, and
`rfc3339-validator`; installation resolves these declared dependencies.
Wheels include the schemas, profiles, lexicon, catalogs, and imported-bank
notices, so the installed CLI works outside the checkout. Optional extras:

| Extra | Unlocks |
|---|---|
| `.[cli]` | `tqdm` progress bars; plain progress remains available without it. |
| `.[stand]` | Mongo/Redis inspection and dotenv loading for separately configured target stands. |
| `.[yaml]` | YAML configuration via PyYAML (JSON always works). |
| `.[notebook]` | Jupyter notebooks; live demos still require their own target and credentials. |

See [Development](#development) for the locked CI installation.

## CLI overview

```
memrot {run, list-catalog, validate-catalog, quickstart}
```

| Command | Purpose |
|---|---|
| `run` | Run an attack matrix against a target described by a JSON/YAML config. |
| `quickstart` | Same idea, no config file — point it at an OpenAI-compatible URL and go. |
| `list-catalog` | Print the variant inventory of one or more catalog files/dirs. |
| `validate-catalog` | Validate catalog files (schema + optional strict taxonomy). |

`run`'s flags group into a few concerns:

- **Audit-driven selection**: `--audit <report.json>`, `--audit-mode {filter,prioritize,ranked}`,
  `--audit-min-severity`, `--audit-top-n`.
- **Mutation**: `--mutate <techniques>`, `--mutation-base-url/-model/-api-key-env`
  (deterministic techniques are free; LLM-driven ones need the base-url/model pair).
- **Adaptive attacker**: `--adaptive`, `--adaptive-max-rounds`, `--attacker-*` (a PAIR/TAP-lite retry loop).
- **Judge**: `--judge-base-url/-model/-api-key-env` (swaps the detector for an LLM judge, falling back to literal matching on judge failure).
- **Imported jailbreak banks**: `--catalog-bank {garak_dan,trustairlab_jailbreak}` (tagged `threat_model=llm_jailbreak_susceptibility`, a separate axis from memory poisoning).
- **Output**: `--out <dir>`, `--report-html <path>`, `--gate` (nonzero exit on a CONFIRMED verdict).
- **UI**: `--fancy` / `--no-fancy` (see below).

Full flag semantics and worked examples: [`docs/attacker.md`](docs/attacker.md).

## Our cool sexy fancy CLI

Run `memrot run` in an interactive terminal and it shows a full, human-readable
walkthrough of the run — no flags needed, it auto-detects a TTY (`--fancy`/
`--no-fancy` override either way; piped/CI output is unaffected either way,
since it defaults to the old plain machine-readable output there).

```
╔══════════════════════════════════════════════════════════════════════════════╗
║           ███╗   ███╗███████╗███╗   ███╗██████╗  ██████╗ ████████╗           ║
║           ████╗ ████║██╔════╝████╗ ████║██╔══██╗██╔═══██╗╚══██╔══╝           ║
║           ██╔████╔██║█████╗  ██╔████╔██║██████╔╝██║   ██║   ██║              ║
║           ██║╚██╔╝██║██╔══╝  ██║╚██╔╝██║██╔══██╗██║   ██║   ██║              ║
║           ██║ ╚═╝ ██║███████╗██║ ╚═╝ ██║██║  ██║╚██████╔╝   ██║              ║
║           ╚═╝     ╚═╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝    ╚═╝              ║
║                                  v0.1 demo                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════════════════════╗
║                              Run Configuration                               ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Target:       genai_invest @ http://localhost:8600/v1 (auth_mode=vulnerable) ║
║ Judge LLM:    openai/gpt-4o-mini via https://openrouter.ai/api/v1            ║
║ Catalog:      6 variant(s) from 2 path(s)                                    ║
║ Audit-driven: ranked (examples/genai_invest_stand.audit.json)                ║
╚══════════════════════════════════════════════════════════════════════════════╝

Validating models...
  ✓ Target (genai_invest) -- reachable (genai_invest)
  ✓ Judge LLM (openai/gpt-4o-mini) -- reachable (openai/gpt-4o-mini)

╔══════════════════════════════════════════════════════════════════════════════╗
║                                Audit Summary                                 ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ 26 FAIL finding(s) from the mcp_audit report, most severe first              ║
║ By severity: CRITICAL: 8, HIGH: 12, MEDIUM: 6                                ║
║ Catalog re-ranked (not filtered) by severity -- top priority: bac-direct-... ║
╚══════════════════════════════════════════════════════════════════════════════╝

Attacking: 100%|██████████| 6/6 [00:25<00:00, 4.32s/variant]

┌───┬─────────────────────────┬───────────┬───────┬─────────────┬───────────────────────────────┐
│   │ Category                │ Confirmed │ Clean │ Err/Inv/N-E │ ASR (attack strength)         │
├───┼─────────────────────────┼───────────┼───────┼─────────────┼───────────────────────────────┤
│ ✘ │ AUTH-02+TOOL-04+TOOL-05 │ 3         │ 0     │ 0           │ [██████████████] 3/3 (100.0%) │
│ ✔ │ (untagged)              │ 0         │ 3     │ 0           │ [--------------] 0/3 (0.0%)   │
└───┴─────────────────────────┴───────────┴───────┴─────────────┴───────────────────────────────┘

Target failed 3/6 (50.0%) of attack simulations.
```
*(abridged; captured from a real run against the project's own live-tested target)*

The important adaptation vs. a plain vulnerability scanner: the **Audit
Summary prints before the attack table**, not after, when `--audit` is
given. This project's premise is that a real audit's findings should drive
attack priority, not the other way around — see [Audit → Attack](#audit--attack-workflow).

The Status Legend (also printed) explains the project's own verdict
vocabulary, never collapsed into a simple pass/fail:

```
CONFIRMED     -- the attack reached its goal (canary/behavior observed)
CLEAN         -- absent in usable observations (not proof of safety)
INCONCLUSIVE  -- insufficient observation; excluded from ASR, gate exit 2
ERROR         -- adapter/transport failure -- never silently counted as CLEAN
INVALID       -- canary was already present before this variant ran (stale)
NOT_EVALUATED -- this adapter cannot exercise this variant's delivery channel
```

"Validating models..." is a real connectivity check (one turn against the
target, one completion against each configured LLM) — a required check
failing aborts the run before any attack turn is spent.

## Audit → Attack workflow

Two tools, one shared vocabulary. [`mcp_audit`](mcp_audit/) is a separate
auditor with offline analysis, live inventory, and controlled validation.
In offline mode it reads a target's config/source/policy and
produces a JSON report of findings (`rule_id`s like `MEM-02`/`AUTH-02`/
`TOOL-04`, each with a severity and a `claim_status` that starts at
`hypothesis`). `memrot` can consume that report to *rank* its own catalog by
what the audit actually flagged, so the highest-severity findings get
attacked first:

```bash
mkdir -p .audit
python -m mcp_audit audit examples/genai_invest_stand.manifest.json --json .audit/stand.json --md .audit/stand.md
python -m memrot run --config examples/genai_invest_stand.attack.config.json \
  --audit examples/genai_invest_stand.audit.json --audit-mode ranked --out .attack --report-html .attack/run.html
```

(The command above runs entirely off the checked-in static snapshot — no
live target needed to see the ranking behavior; a live attack run needs the
target reachable, see [Worked examples](#worked-examples).)

Every result also carries a `path_state`, closing the loop back to the same
vocabulary the audit used:

```
static_path_supported ──> runtime_path_observed ──> control_violation_observed
   (audit: hypothesis,        (payload persisted /       (payload reached a
    or attack not               surfaced at runtime)       different principal --
    reproduced live)                                        cross-user payoff)
```

A `rule_id` groups into a handful of attack categories (mirrored in
`memrot.audit_plan.REDTEAM_CATEGORIES`):

| Category | Rule IDs |
|---|---|
| `memory-poisoning` | MEM-02, MEM-03, MEM-04, MEM-06 |
| `tool-poisoning` | TOOL-04, TOOL-05 |
| `idor-bac` | AUTH-02, AUTH-03 |
| `token-validation` | AUTH-04 |
| `delegation` | AUTH-05 |
| `exfiltration` | EGRESS-01 |
| `memory-hygiene` | MEM-05, MEM-08, MEM-09, MEM-10 |
| `infrastructure` | INFRA-01, INFRA-02 |
| `inventory` | INV-01, INV-02, TOOL-01, TOOL-02 |

## Adapters

| `kind` | Access | When to use | Extra channels |
|---|---|---|---|
| `openai_compat` | black-box | Any OpenAI-compatible `/v1/chat/completions` | none |
| `http_generic` | black-box | Same, custom field mapping (`response_path`, `messages_field`, `session_in_body`) | none |
| `mcp_client` | grey-box | Streamable-HTTP or stdio MCP server; `send` is `tools/call` | none unless the server allows tool staging |
| `genai_invest` | white-box (if Mongo configured) | An HTTP target speaking this project's own reference API shape | finalize, optional Mongo/Redis, docker-log ground truth |
| `callable` | whatever you wire | In-process memory library (mem0, LangGraph, tests) | whatever callables you pass |

Onboarding a new target in ~40 lines (no JSON config, pure Python):
[`docs/attacker.md`](docs/attacker.md#connect-a-new-agent-in-40-lines-white-box).
Credentials are never embedded in a config — only a `credential_ref`,
resolved at call time from `MEMROT_CRED_<ref>`.

## Worked examples

**genai-invest-agent-memory-stand** — this project's own primary validation
target, a deliberately-vulnerable banking assistant demo. Static snapshots
ship under `examples/genai_invest_stand.*` (manifest, deployment, policy,
audit report) — the [Audit → Attack](#audit--attack-workflow) command above
runs entirely off those, no live services required. A fully live run (real
BAC/memory-poisoning findings, as shown in [The fancy CLI](#the-fancy-cli)
above) needs the stand actually running — it's a separate repo, not vendored
here: `../genai-invest-agent-memory-stand` (`docker compose up -d`).

**[MemPalace](https://github.com/MemPalace/mempalace)** — the portability
proof: the same engine, ported to a *foreign* system with zero engine code
changes, only a config + a domain catalog overlay
(`memrot/catalog/prompts/domain/mempalace/`, each variant citing the exact
audit finding it attacks). Be precise about what needs no setup vs. what
does: config loading, catalog validity, and audit-ranking are checkable
right now (`pytest tests/test_mempalace_attack.py`); an actual live run
needs a reachable MemPalace hub the reader won't have by default:

```bash
export MEMROT_CRED_MEMPALACE_TEAM_TOKEN=<hub bearer token>
python -m memrot run --config examples/mempalace.attack.config.json --out .attack
```

## Porting to a new target

Two moving parts, both data-only (no engine changes): a `TargetBinding` +
channels (which adapter, which credentials) and, optionally, a domain
catalog overlay under `memrot/catalog/prompts/domain/<name>/`. See
[`docs/attacker.md`](docs/attacker.md#moving-the-pool-to-a-new-domain) for
the attack side specifically, and
[`docs/porting_to_a_new_stand.md`](docs/porting_to_a_new_stand.md) for the
`mcp_audit` side (most of that doc is about porting the auditor; only its
final step covers the attack side).

## Development

Implementation follows [the roadmap](docs/ROADMAP_memrot.md); see
[completed work and validation](docs/roadmap-progress.md).

From the repository root, create a virtualenv and install the dev extra:

```bash
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest -ra
python -m memrot.smoke
```

Default discovery includes both `tests/` and `memory_trace/tests/`.
Four in-process adapter tests and one portability test require the separate
`genai-invest-agent-memory-stand` repository and skip when it is absent.
The rest of the suite uses local fixtures; some tests start loopback HTTP or
stdio servers. No live stand or cloud model is required.

CI pins development and build dependencies (including transitive dependencies)
with hashes. To reproduce that dependency set in a fresh venv:

```bash
python -m pip install --require-hashes -r requirements-dev.lock
python -m pip install --no-deps --no-build-isolation -e '.[dev]'
python -m pytest -ra
python -m build --no-isolation
```

The installation tests build a wheel and run both CLIs and the offline smoke
outside the checkout. CI additionally builds a wheel from the sdist and checks
it in a clean virtualenv with only declared runtime dependencies.
Regenerate the lock deliberately after dependency changes using
`uv pip compile pyproject.toml --extra dev --universal --python-version 3.12 --generate-hashes --output-file requirements-dev.lock --no-annotate`.

## Repository layout

```text
memrot/        -- the attack harness itself: engine, adapters, detectors,
                  catalog (generic + domain/{invest_bank,mempalace} overlays)
mcp_audit/     -- sibling static-audit engine memrot's --audit consumes
redteam/       -- an older, narrower harness coupled to one specific stand
                  (see redteam/PIPELINE.md) -- not the tool this README covers
profiles/      -- mcp_audit profiles (which rules apply to which system)
schemas/       -- JSON schema for the audit report format
examples/      -- configs, manifests, and pre-generated audit reports for
                  the two worked examples above
docs/          -- deep-dive docs (attacker.md, auditor.md, rules_catalog.md, ...)
tests/         -- pytest suite for both memrot and mcp_audit
```
