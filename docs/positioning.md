# Blindspot: Positioning and Prior Art

Status: positioning draft, v0. This document places Blindspot honestly in the research
and product landscape. It is written for security engineers, so it states what is prior
art, what Blindspot mirrors, and the one thing that is genuinely ours, without
overclaiming. Read it alongside `spec/convention.md` (how the trust boundary works) and
`README.md` (current status and the exact counts, which move as the project grows).

The convention it describes (`spec/convention.md`) is a draft (v0), not a ratified
standard.

Repository: <https://github.com/adi2kool/blindspot-mcp> · Security contact: adityacaug15@gmail.com

## One-line positioning

Blindspot is a proposed convention plus a reference enforcement contract that carries a
typed instruction/data trust boundary through MCP, signs the provenance of tool output at
runtime with zero changes to the server it fronts, and emits a verifiable record of what
the enforcer did with each item.

A gateway decides and prevents a dangerous flow at runtime; Blindspot marks what content
an agent is allowed to act on, keeps untrusted content out of the instruction path, and
signs an attestation of what the enforcer actually did, so you can prove the control was
in place later.

## The problem

A language model reads system instructions, user input, and retrieved content as one
undifferentiated token stream. There is no enforced boundary between a trusted instruction
and untrusted data, so anything that reaches the context can act like a command. In MCP
specifically, a Resource body, a tool result, and a Prompt template all arrive as plain
strings with no marker of trust, and the model cannot tell an instruction the server
author intended from data the server merely fetched or echoed from somewhere untrusted.
Indirect prompt injection is the direct consequence.

The field's consensus fix is to reintroduce that boundary in architecture rather than to
rely on prompting the model to behave. Blindspot is a concrete, minimal way to carry that
boundary through the MCP layer so a client can enforce it. It does not make the model
immune to injected text; the model still sees the content. What it provides is the
information a client needs to present untrusted content as data, to refuse to act on
instructions found inside it without human approval, and to detect tampering. The
protection lives in the client's handling, not in the model.

For a security team, the injection risk is only half the pain. The other half is
accountability. Even where a control exists, it usually leaves a plain log line: an
assertion, not proof, and one an in-transit attacker (or a careless edit) could have
altered. When an auditor asks "prove this agent never acted on untrusted content," a log
line says at most "we would have blocked it." Blindspot addresses both halves: it carries
an explicit, enforceable trust boundary through MCP, and it emits a signed, tamper-evident
record of every enforcement decision.

## What Blindspot is

Blindspot has four parts, each with a runnable CLI verb (see `README.md`):

- A **scanner** (`scan`) that finds where the boundary is violated on the neglected MCP
  surfaces (Prompts, Resources, and Tool descriptions): local pattern and invisible-unicode detection, an
  optional local-model judge, a least-privilege auditor, and sanitized-rewrite
  remediation. This is the on-ramp.
- A **provenance library** (`src/blindspot/provenance/`, server side) that lets a server
  author mark the origin and trust level of what it emits, carried in the item's `_meta`
  under the namespaced key `x-mcp-provenance/v0` so a non-aware client simply ignores it
  and nothing breaks, with an integrity hash and an optional signature.
- A **client-side reference enforcer** (`src/blindspot/enforce/middleware.py`) and an
  **enforcing proxy** (`src/blindspot/enforce/proxy.py`) that implement the convention's
  client contract: `trusted` content may be presented as authoritative only after
  integrity verification and authoritative-path sanitization; `untrusted` content is
  presented as data only and never placed in the instruction region; `quarantined` content
  is withheld; and missing or unknown provenance is treated as `untrusted`. It fails
  closed.
- An **adaptive-attack evaluation** (`redteam`, `src/blindspot/redteam/`) that attacks the
  reference defense as an adversary who knows how it works, and a **cross-server
  composition analyzer** (`compose`, `src/blindspot/compose.py`) that flags when a set of
  individually-clean servers jointly enables the lethal trifecta.

Two design commitments make this deployable today rather than after an ecosystem shift:

- **The proxy needs zero server changes.** An unmodified MCP client points at the proxy
  instead of the upstream server; the proxy connects upstream, applies the enforcement
  contract to every Resource body, Prompt message, and tool output, and returns the result.
  A server that emits no provenance at all has all its content demoted to data (untagged
  maps to `untrusted`), so the proxy protects the existing ecosystem of untagged servers
  unilaterally. Server tagging (and signing) is a precision upgrade, not a precondition.
  Optionally, `--infer` classifies untagged content with a local model so the proxy can
  explain why each item is treated as data instead of blanket-framing everything; it fails
  safe, staying `untrusted` when no model is reachable. This collapses a two-sided adoption
  problem down to one deployable component.
- **Fail closed is the default posture.** Absence of provenance is not trust; an unknown
  trust level is treated as `untrusted`; an integrity mismatch quarantines. The documented
  residuals are stated plainly rather than papered over.

Everything above runs locally at $0. The only optional network dependency is a local
open-source model for the semantic judge and for optional provenance inference; without
one, the tools degrade to local-only behavior and fail safe. Nothing is sent off the
machine by the deterministic core. The project is Apache-2.0 licensed (`LICENSE`,
`NOTICE`).

The differentiator is author-side provenance plus a client enforcement contract, not
content moderation. The protection lives in the client's handling of labeled content, not
in making the model immune to injected text.

## Honest differentiation: what Blindspot does that gateways and scanners do not

The nearest product neighbor is a runtime dataflow gateway such as Invariant (now part of
Snyk), which does real, good work: it analyzes flows and **blocks** the dangerous ones at
runtime, and its Toxic Flow Analysis reasons about multi-tool compositions the way
Blindspot's `compose` analyzer does. That is a good product and this document does not
pretend otherwise. Blindspot is positioned alongside a gateway, not as a replacement, and
the difference is orthogonal, not a claim to be "better on the same axis."

### 1. Attest, do not just block

A gateway decides and prevents. Blindspot attests. Per decision, it records the provenance
of what entered the context and what the enforcer did with it, under a key an in-transit
attacker does not hold. When an auditor asks "prove this agent never acted on untrusted
content," a gateway can say "we would have blocked it"; Blindspot can hand over a
verifiable record.

Concretely, this is the flight recorder (`src/blindspot/ledger.py`): a signed,
hash-chained, append-only JSONL audit trail of every enforcement and action-gate decision.
Each entry carries a `prev_hash` and an `entry_hash` over its canonical fields, with an
optional Ed25519 signature over that hash, so `blindspot verify-log` can prove the trail
was not edited, reordered, or truncated after the fact. This composes with a gateway rather
than competing: where a gateway is deployed, the flight recorder can be the tamper-evident
system of record for its decisions too.

### 2. Runtime content signing, deployable with zero server changes via the proxy

The genuinely novel claim, stated carefully: Blindspot provides runtime signing of
tool-returned content, and the enforcing proxy lets you deploy the boundary with no changes
to the server or the client.

The mechanism (`src/blindspot/provenance/integrity.py`): the integrity block carries an
unkeyed `sha-256` hash over the exact emitted body, and an optional `signature`. The hash
alone detects body tampering but does not stop an active in-transit attacker from
relabeling `untrusted` content as `trusted` — such an attacker flips the `trust` field and
recomputes a matching hash over the unchanged body. The signature closes that gap. It is
computed over a canonical serialization that binds the body hash together with `origin`,
`trust`, `source`, `fenced`, and the signature algorithm itself (so the algorithm cannot be
downgraded on the wire). Two algorithms are supported, selected by `sig_alg`:

- `hmac-sha256`, a symmetric keyed MAC where the verifier holds the same shared secret; and
- `ed25519`, an asymmetric signature bound to a server identity, where the server signs
  with its private key and any client verifies with a published public key it never had to
  share secretly. An optional `keyid` supports public-key discovery via a JWKS-style key
  set (`src/blindspot/enforce/keys.py`).

A verifier binds the verification algorithm to the configured key source, never to the
item's self-declared `sig_alg`, which is what closes a signature algorithm-confusion attack:
an Ed25519 public key is published, so if it could be accepted as an HMAC secret an attacker
could forge a `trusted` label from public information alone. Keys resolved from a
JWKS/keystore are Ed25519 by construction; a directly configured key must declare its
algorithm out of band (`--key-alg`).

Signing *tool-returned* content — as opposed to tool definitions — deployable in front of an
unmodified server via the proxy is, to our knowledge, a gap otherwise unaddressed in the MCP
ecosystem. We state that as our read of the landscape, not as a proven exhaustive survey.
This is the framing to defend; it is not a claim to have invented signing, typed boundaries,
or the trust-separation principle.

### 3. Active action-gating, before the call reaches upstream

The proxy can actively gate side-effecting tool calls (`--on-action approve` or
`--on-action block`; the default `annotate` only records the disposition and forwards, which
is backward compatible). The model is a session-level taint flag: once the proxy enforces
any content that is not clean `trusted` (untrusted, quarantined, requiring approval, or
non-text content it cannot verify), the session is tainted, and a subsequent side-effecting
tool call is held for approval or refused before it reaches the upstream server, so the side
effect never happens. "Side-effecting" is identified structurally and locally in two layers:
the composition analyzer's exfiltration classifier (a call that can send data outward — send
a message, publish or upload, outbound HTTP, post to a channel) plus a set of destructive,
state-changing, and code-execution verbs. This is a heuristic; the honest residual is an
unrecognized custom action verb, on which the gate fails open — the same limitation the
scanner and composition classifier carry.

In `--on-action approve`, a gated call can be routed to a human via a webhook
(`src/blindspot/enforce/broker.py`); a timeout or denial fails closed, and the request and
decision are recorded in the audit trail.

### 4. Compose: the lethal-trifecta analysis across servers

An agent rarely connects to one server. The danger is emergent: each server can be
individually clean while the combination enables the lethal trifecta — access to private
data, exposure to untrusted content, and a path to exfiltrate — so an injection carried by
one server's untrusted content can read another server's private data and send it out
through a third. `blindspot compose` (`src/blindspot/compose.py`) classifies each connected
server's surface into the three trifecta legs with a deterministic local taxonomy and flags
when the union across the set covers all three, distinguishing a jointly-enabled composition
(no single culprit) from a single-server culprit. It folds in the provenance signal: a
server observed emitting external/untrusted `_meta` is, by construction, an
untrusted-content source. Its mitigations tie back to the rest of the tool: route the
untrusted-content source through the enforcer, and gate the exfil tool on approval. This
reasons about multi-tool compositions the way Toxic Flow Analysis does; the difference,
again, is that the output feeds the enforcer and the attestation, not only a block.

### 5. Enforce the channels and surfaces others ignore

Most tooling watches the forward path (tool descriptions, tool output). Blindspot's proxy
also enforces three surfaces that are commonly left open, each an extension of the same
trust boundary rather than a separate product:

- The server-initiated channels. MCP `sampling/createMessage` lets an upstream server push
  text into the client's own model, and `elicitation` puts a server-controlled prompt in
  front of the user. The proxy frames that text as data, never leaves a server system prompt
  in the instruction region, taints the session, and can refuse the request outright (which
  also stops sampling resource-drain). To our read of the landscape, gating the sampling
  channel is not something shipping tools do.
- Continuous, mid-session rug-pull detection. Startup pinning (a lockfile, trust-on-first-use)
  is the common state of the art; a server that mutates a tool after adoption, mid-session,
  is the gap. The proxy re-checks the pinned surface on every listing and forwarded
  `list_changed`, records the drift to the tamper-evident ledger, and can withhold the mutated
  definition and refuse a call to it.
- Provenance for MCP-exposed memory. Persistent memory is a poisoning surface the scanners
  miss: `scan-memory` inspects what is already stored, the proxy gates a poisoning memory
  write once the session is tainted, and it tags persisted-under-taint content so a later
  recall is attributed rather than trusted.

As with the rest of the tool, the honest framing is our read of the landscape, not a proven
exhaustive survey; each is a small, testable extension of the client enforcement contract.

## What Blindspot mirrors versus what is ours

Blindspot's durable contribution is a convention plus an enforcement contract, not a novel
primitive. Cryptographic hashing, HMAC, Ed25519, and the idea of a typed trust boundary are
all prior art. What a convention adds is agreement: a stable, namespaced place to carry
origin and trust through MCP, and a normative statement of what a conforming client MUST do
with each level. That contract is the thing that turns scattered good ideas into an
interoperable boundary, and it is the piece designed to outlive any single implementation.

**What we mirror (prior art we align to, and do not claim):**

- The architectural principle of separating a trusted control path from untrusted data,
  rather than trusting the model to keep them apart.
- A standard trust-annotation vocabulary for MCP content (SEP-1913), which the convention
  deliberately speaks so a standard-aware client can read our objects.
- Multi-tool composition reasoning about the lethal trifecta, which Toxic Flow Analysis
  established as a product-grade idea.

**What is ours (the genuinely novel claim, scoped carefully):**

- Runtime tool-output content signing, deployable with zero server changes via the proxy,
  producing a signed attestation of what the enforcer did. Each borrowed idea is credited;
  the composition and the zero-adoption deployment path are the new part.

We did not originate typed trust boundaries, we did not invent the trust-separation
architecture, and Blindspot is not an implementation of any of the references below.

## Prior art, cited without overclaiming

- **CaMeL** (arXiv 2503.18813) makes the strongest academic case for separating a trusted
  control path from untrusted data by construction. Blindspot's convention is a concrete,
  shippable MCP-layer expression of the same principle. It is **not** an implementation of
  CaMeL and **not** a claim to have originated the idea.
- **MCP SEP-1913** proposes a standard trust-annotation vocabulary. Blindspot mirrors it
  (`spec/convention.md` §5.1) so a standard-aware client can read its provenance object,
  while keeping `x-mcp-provenance/v0` as the stable carrier. Concretely, a tagging server
  MAY additionally emit `openWorldHint`, `sensitiveHint`, `privateHint`, and `attribution`.
  These hints are additive and, in the reference implementation, purely informational: they
  are emitted and parsed but do not by themselves change any enforcement or gating decision,
  which is driven entirely by `trust`/taint. A conforming client MAY consult them (for
  example to raise a side-effecting action to human approval), but the reference enforcer
  does not yet do so, and a client MUST NOT raise trust based on any hint. Blindspot tracks
  SEP-1913 rather than competing with it.
- **Invariant / Snyk Toxic Flow Analysis** is the runtime dataflow-gateway approach
  described above: it reasons about multi-tool compositions and blocks dangerous flows at
  runtime. Blindspot's `compose` analyzer (`src/blindspot/compose.py`) performs a related
  cross-server lethal-trifecta analysis — flagging when the union across a connected set of
  servers covers all three legs even though each server is individually clean. This is prior
  art for the composition idea; Blindspot's contribution here is a local, deterministic
  analyzer whose output feeds the enforcer and the attestation, not a new theory of toxic
  flows.

We do not cite any reference beyond these, and we do not assert URLs, arXiv IDs, author
names, or dates we cannot ground in the repository. (An internal planning note names "MIS"
as an intended reference, but the acronym is unexpanded and ungrounded in the repo, so it is
deliberately not cited here until a primary source is supplied.)

## The measured proof

The claims above are backed by an adaptive-attack evaluation, not assertion. The harness
(`src/blindspot/redteam/`) attacks the reference defense as an adversary who knows how it
works. Across **56 verified attacks** the defense holds: every in-scope attack, naive and
adaptive, fails, and only the documented residuals succeed — **five attacks, all of two root
causes**: a malicious server labeling (and signing) its own content, and an active
in-transit relabel without a signature (present when no signature is attached or no key is
configured). The malicious-server root cause is a trust-root problem no signature can close
by definition, addressed instead by scanning and vetting; the unsigned-relabel root cause is
closed once a key is configured. Both residuals are stated plainly in the threat model
(`spec/convention.md` §3) rather than hidden. The full test suite is **307 passing** as of
the most recent audit session; re-read `README.md` before quoting any of these numbers, as
they move as the project grows. Every attack payload in the repository is
an inert fixture; nothing performs network, email, or filesystem I/O against a real target.

## Where Blindspot sits alongside a gateway

Blindspot is not a replacement for a dataflow gateway; the two axes are complementary.

| | A dataflow gateway / scanner | Blindspot |
| --- | --- | --- |
| Primary action | Decide and prevent a dangerous flow at runtime | Carry a trust label through MCP and enforce data-vs-instruction handling on the client |
| What it leaves behind | A log line of a block | A signed, hash-chained attestation of each enforcement decision |
| Server changes to adopt | Varies | None (the proxy fails closed on untagged servers; tagging/signing is a precision upgrade) |
| Content authenticity | Not the focus | Runtime content signing (HMAC or Ed25519) binding the trust label to the body |
| Cross-server composition | Toxic Flow Analysis reasons about it | `compose` flags the lethal trifecta and routes the finding into the enforcer |

A gateway answers "should this flow run?" Blindspot answers "prove what the agent was
allowed to act on, and that a human could gate the side effects" — and where a gateway is
deployed, its flight recorder can be the system of record for the gateway's own decisions.

## Who this is for

The buyer is not the individual developer who runs a scanner once. It is the security and
GRC team that has to answer for AI agents in production. Their problem is not "is this flow
safe" in the abstract; it is whether they can demonstrate, on demand, control over what
their agents acted on — to an auditor, a customer security review, or a regulator. Agents are
the newest unmanaged actor in the estate: they read email, issues, web pages, and database
rows, and they can send mail, open pull requests, and call outbound APIs. Blindspot is built
to produce that evidence as a first-class output, not as a side effect of a log line you
have to trust.

The compliance backdrop makes this a budgeted problem: the EU AI Act pushes
logging/record-keeping and human-oversight obligations for higher-risk systems, and SOC 2 /
ISO control language increasingly wants evidence for automated decisions rather than a policy
document asserting one exists. Blindspot produces evidence relevant to those obligations; it
is not a certification, and this document does not claim conformance to any specific control
on your behalf. Treat the mapping as a starting point for your own auditor, not a legal
opinion.

## The central limitation, stated up front

The convention protects end to end only when the consuming side enforces it. That is the
central caveat and it belongs wherever the project is presented. The reference enforcer and
the proxy demonstrate the value unilaterally on the client side, which is why the proxy
exists — it removes the dependency on client-vendor adoption. But a server author who wants
precise, signed provenance still needs to tag, and a third party who wants to verify the
attestations still needs to run the enforcer. The two documented residuals in the threat
model are the boundaries a client-side trust boundary cannot cross on its own, and they are
disclosed rather than papered over:

- **A malicious server is out of scope.** Trust is rooted in the server operator. A server
  that labels its own malicious instructions as trusted and signs them with its own key
  defeats the convention by definition; that is a supply-chain problem for scanning and
  vetting (and the lockfile/drift detection), not something a content signature can solve.
- **The model still sees untrusted text.** Blindspot does not make the model immune to
  injected instructions; it keeps that content out of the instruction region and presents it
  as data. The protection lives in the client's handling.
- **The action-gate side-effect classifier is a heuristic.** An unrecognized custom action
  verb is the honest residual: the gate can fail open on it. This is documented in
  `spec/convention.md` §8 and shared by the scanner and the composition classifier.
- **The convention is a v0 proposal, not a ratified standard.** The `x-mcp-provenance`
  namespace and carrier field are provisional pending confirmation against the installed MCP
  spec version, and breaking changes should be expected. Prior-art pointers and critique are
  welcome.

## Where to read more

- `spec/convention.md` — the proposed provenance and enforcement convention, including the
  full threat model, the integrity and signing scheme, and the normative client contract.
- `docs/prevalence-findings.md` — a scan of ~1,000 real MCP servers for injectable surface.
- `README.md` — current status, the exact CLI, and the verified attack and test counts.

---

Repository: <https://github.com/adi2kool/blindspot-mcp> · Security contact: adityacaug15@gmail.com
