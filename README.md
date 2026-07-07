# Blindspot

The instruction and data boundary for MCP.

## Thesis

Agents cannot reliably tell trusted instructions from untrusted data, because a
model reads system instructions, user input, and retrieved content as one token
stream with no enforced boundary between them. Anything that reaches the context
can act like a command. Blindspot makes that boundary explicit and enforceable at
the MCP layer.

- A scanner finds where the boundary is violated (the on-ramp).
- A provenance library lets a server author mark the trust level of what it emits
  (the centerpiece, server side).
- A reference client enforcer keeps untrusted content out of the instruction path
  on the consuming side (the centerpiece, client side).
- An adaptive-attack evaluation measures how well the boundary holds under an
  attacker who knows how it works (the proof).

The differentiator is author-side provenance plus a client enforcement contract,
not content moderation. See [`spec/convention.md`](spec/convention.md) for the
proposed convention, [`docs/positioning.md`](docs/positioning.md) for where it sits
in the landscape, and [`docs/prevalence-findings.md`](docs/prevalence-findings.md)
for a scan of ~1,000 real MCP servers.

## Status

Phase 1 (the on-ramp), Phase 2 (the trust-boundary centerpiece), and the Phase 3
adaptive-attack evaluation are complete.

- Phase 1: a scanner for the neglected surfaces (Prompts, Resources, and Tool
  descriptions, including tool parameter descriptions - the tool-poisoning vector) with
  local pattern and invisible-unicode detection and an optional local-model judge; a
  labeled benchmark reporting precision, recall, and false-positive rate against a
  stated bar; and a least-privilege auditor.
- Phase 2: the provenance convention (`spec/convention.md`, `spec/schema.json`), a
  server-side tagging library (with optional signing that authenticates the trust
  label - HMAC-SHA256 or Ed25519, so a client verifies with a published public key), a
  client-side reference enforcer (with authoritative-path sanitization), an enforcing
  proxy that applies the contract for an unmodified client (optionally with LLM-inferred
  provenance for untagged servers, and optional active gating that blocks or holds a
  side-effecting tool call once untrusted content is in the session), sanitized-rewrite
  remediation, and drift / rug-pull detection.
- Phase 3: the adaptive-attack harness (`src/blindspot/redteam/`) attacks the
  reference defense as an adversary who knows how it works. Across 56 verified
  attacks the defense holds: every in-scope attack (naive and adaptive) fails, and
  only the documented residuals succeed - five attacks, all of two root causes (a
  malicious server labeling its own content, and an active in-transit relabel without
  a signature). Plus cross-server composition analysis
  (`src/blindspot/compose.py`): it flags when a set of individually-clean servers
  jointly enables the lethal trifecta (private-data access plus untrusted content
  plus an exfiltration path). Remaining: the prevalence study over real servers,
  which stays gated behind responsible disclosure.

The enforcement surface has since been extended in three directions:

- Reverse-channel enforcement: the proxy also enforces the two server->client channels
  (sampling `createMessage` and `elicitation`), framing server-supplied text as data,
  never leaving a server system prompt in the instruction region, and refusing them under
  `--on-sampling block` / `--on-elicitation block` (`--on-elicitation` always declines the
  URL-mode phishing vector).
- Continuous (mid-session) rug-pull detection: with `--lock` or `--pin-on-start` the proxy
  re-checks the surface on every list and forwarded `list_changed`, not just at startup, so
  a server that mutates a tool after adoption is caught live - tainting the session and (under
  `--on-drift block`) withholding the mutated definition and refusing a call to it.
- Provenance for MCP-exposed memory: `scan-memory` finds injection already persisted in a
  memory server, the proxy gates a poisoning memory WRITE once the session is tainted, and
  tags what is persisted so a later recall attributes it as untrusted-origin.

Runs at $0. The only optional network dependency is a local open-source model for
the semantic judge; without one, the scanner degrades to local-only detection.
Nothing is sent off the machine.

## Requirements

- Python 3.11 or newer (developed on 3.12).
- `uv` for dependency management.
- MCP Python SDK, pinned to `mcp>=1.28,<2` (stable v1.x).
- Optional: a local [Ollama](https://ollama.com) server for the semantic judge.

## CLI

```bash
uv sync

# Scan a server's tool descriptions, prompts, and resources for injection (human / JSON / SARIF),
# with sanitized-rewrite remediation. Add --judge on for the optional local judge.
uv run blindspot scan  fixtures/vulnerable_server.py
uv run blindspot scan  fixtures/vulnerable_server.py --format sarif --sarif out.sarif

# Statically scan a server's SOURCE tree for injectable declared strings (tool/prompt
# descriptions) WITHOUT executing it. The safe way to analyze an untrusted server.
uv run blindspot scan-source path/to/server/src

# Flag capabilities a server advertises but does not exercise.
uv run blindspot audit fixtures/vulnerable_server.py

# Scan an MCP memory server's STORED entries for injection. Persistent memory reached
# through MCP is a poisoning surface the other scanners miss: content written once is
# recalled as trusted later. This calls the server's recall tools and runs the detectors
# over what is actually persisted, catching a poisoned memory before it is recalled.
uv run blindspot scan-memory fixtures/memory_server.py

# Read a server's provenance and run the client enforcer over it. Injected content
# is demoted to data or quarantined and is never instruction-eligible.
uv run blindspot guard fixtures/tagged_server.py

# Run an enforcing PROXY in front of a server. An unmodified MCP client points at the
# proxy instead of the server and is protected end to end: untrusted content arrives
# framed as data, even from a server that emits no provenance at all. This is how the
# boundary works without waiting for client vendors to adopt the convention.
uv run blindspot proxy fixtures/vulnerable_server.py

# Add --infer to classify untagged content with a local model (Ollama by default, $0)
# so the proxy explains WHY each item is treated as data instead of blanket-framing
# everything. It fails safe: with no model reachable, untagged content stays untrusted.
uv run blindspot proxy fixtures/vulnerable_server.py --infer

# Actively gate side-effecting tool calls. Once untrusted content has entered the
# session, a call to a tool that can send data outward (email/post/upload/HTTP) is
# held for approval (--on-action approve) or refused (--on-action block) BEFORE it
# reaches the upstream, so an injection cannot drive exfiltration. Default is annotate
# (forward, record the disposition), which is backward compatible.
uv run blindspot proxy fixtures/vulnerable_server.py --on-action block

# Enforce the REVERSE (server->client) channels too. A server can push text into the
# client's own LLM via sampling (createMessage) or a coercive prompt to the user via
# elicitation. The proxy frames that server-supplied text as data, never leaves a server
# system prompt in the instruction region, taints the session, and records each request.
# --on-sampling/--on-elicitation block refuses them outright (stops sampling credit-drain);
# URL-mode elicitation (the phishing vector) is always declined.
uv run blindspot proxy fixtures/sampling_server.py --on-sampling frame --on-elicitation frame
uv run blindspot proxy fixtures/sampling_server.py --on-sampling block --audit-log audit.jsonl

# Generate an Ed25519 keypair for content signing. A tagging server signs its content
# with the private key; the enforcer/proxy verifies with the public key, so an
# in-transit relabel is rejected without the verifier ever holding a shared secret.
# --jwks also writes a JWKS the proxy can discover the key from by keyid (--keystore).
uv run blindspot keygen --private server.key --public server.pub --jwks server.jwks --kid srv
# For a raw --key you must declare its algorithm (--key-alg ed25519 for a public key),
# so a published public key can never be misused as an HMAC secret. --keystore is
# Ed25519 by construction and needs no such flag.
uv run blindspot proxy fixtures/tagged_server.py --key server.pub --key-alg ed25519 --require-signature
uv run blindspot proxy fixtures/tagged_server.py --keystore server.jwks --require-signature

# Capture a hashed baseline of a server's surface, then detect drift (rug pulls).
uv run blindspot baseline fixtures/tagged_server.py --out baseline.json
uv run blindspot drift    fixtures/tagged_server.py --baseline baseline.json

# LIVE rug-pull detection: the proxy re-checks the surface on every list, not just at
# startup, so a server that mutates a tool AFTER adoption is caught mid-session. With a
# --lock the drifted definition is withheld and a call to it is refused (--on-drift block);
# with --pin-on-start (trust-on-first-use, no lock) drift taints the session (--on-drift
# taint) so a later side-effecting call is gated. Every drift is written to the audit trail.
uv run blindspot proxy fixtures/tagged_server.py --lock blindspot.lock --audit-log audit.jsonl
uv run blindspot proxy fixtures/tagged_server.py --pin-on-start --on-drift taint

# --- Governance layer: attest, pin, and gate ---

# Flight recorder: write a signed, hash-chained audit trail of every enforcement and
# action-gate decision. --audit-key signs each entry with the operator's key; verify-log
# proves the trail was not edited, reordered, or truncated after the fact.
uv run blindspot proxy fixtures/vulnerable_server.py --audit-log audit.jsonl \
                       --audit-key server.key --audit-keyid op-1
uv run blindspot verify-log audit.jsonl --key server.pub

# Trust lockfile: pin a server's surface, then run the proxy with --lock. If the server
# has drifted from the pin (a rug pull), the proxy refuses to start.
uv run blindspot lock  fixtures/tagged_server.py --out blindspot.lock
uv run blindspot proxy fixtures/tagged_server.py --lock blindspot.lock --audit-log audit.jsonl

# Approval broker: in --on-action approve, POST each gated side-effecting call to a
# webhook for a human approve/deny decision (Slack, a form, a script). Timeout or denial
# fails closed. The request and decision are recorded in the audit trail.
uv run blindspot proxy fixtures/vulnerable_server.py --on-action approve \
                       --approval-webhook https://your.endpoint/approve --audit-log audit.jsonl

# Attack our own defense as an adaptive adversary and report the residual risk.
# Exits non-zero only if a non-residual attack reaches the instruction path.
uv run blindspot redteam
uv run blindspot redteam --format json

# Analyze a set of servers together for the lethal trifecta. Each of these three
# fixtures is individually clean; only the composition enables it (exits non-zero).
uv run blindspot compose fixtures/compose_files_server.py \
                         fixtures/compose_web_server.py \
                         fixtures/compose_mailer_server.py

# Score the detector against the labeled benchmark.
uv run python benchmark/run.py

# Run the tests.
uv run pytest -q
```

`fixtures/tagged_server.py` is a conforming server that emits provenance `_meta`;
`fixtures/vulnerable_server.py` is a poisoned server with no provenance, which the
enforcer treats as untrusted and fails closed on.

## Layout

```
spec/
  convention.md           the proposed provenance and enforcement convention
  schema.json             the provenance annotation JSON Schema
src/blindspot/
  cli.py                  scan / scan-memory / audit / guard / proxy / keygen / baseline /
                          drift / lock / verify-log / redteam / compose
  models.py               shared types (Finding, Severity, AttackClass, Provenance, ...)
  sanitize.py             the one shared invisible-unicode sanitizer
  compose.py              Phase 3 cross-server composition (lethal-trifecta) analysis;
                          also classify_memory_tool (MCP-memory write/read taxonomy)
  ledger.py               the flight recorder: signed, hash-chained provenance audit trail
  lockfile.py             the trust lockfile: pin a server's surface (supply-chain pinning)
  scan/                   Phase 1 on-ramp: client, detectors, judge, leastpriv,
                          remediate, drift, memory (scan-memory)
  provenance/             Phase 2 server side: tagger, integrity (hash + signing), emit
  enforce/                Phase 2 client side: reference enforcer, proxy, LLM inferer,
                          Ed25519/JWKS key discovery (keys.py), approval broker (broker.py)
  redteam/                Phase 3 adaptive harness: adaptive.py (engine), catalog.py
                          (the verified attack battery)
  report.py               human, JSON, SARIF 2.1.0
fixtures/                 vulnerable, clean, tagged, compose_*, sampling, mutating, and
                          memory servers + scratch client
benchmark/                the labeled cases and the precision/recall runner
tests/                    pytest suite
```

## Safety

Every attack payload in this repository is an inert fixture. Nothing performs
network, email, or filesystem I/O against a real target. The scanner is not pointed
at any third-party server. See `fixtures/README.md` for the payload inventory and
the inert-sink statement.
