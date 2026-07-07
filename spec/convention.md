# MCP Content Provenance and Enforcement Convention

Status: proposal, v0. This is a draft convention, not a ratified standard. Expect breaking changes. Prior-art pointers and critique are welcome.

Namespace used throughout: `x-mcp-provenance` (provisional; finalize before any public release).

## Summary

MCP content flows into an agent's context as plain text with no marker of trust. A Resource body, a tool result, or a Prompt template all arrive as strings, and the model cannot tell an instruction the server author intended from data the server merely fetched or echoed from somewhere untrusted. Indirect prompt injection is the direct consequence.

This convention adds a trust boundary at the MCP layer in three parts: a provenance annotation attached to emitted content, an integrity mechanism so tampering is detectable, and a fencing scheme for marking untrusted spans inside otherwise trusted content. It then defines a client enforcement contract that says what a conforming client must do with each trust level. The convention is optional and backward compatible. Its protection is only realized end to end when both the server and the client conform, which is why a reference implementation of both sides ships with it.

## 1. Motivation

A language model reads system instructions, user input, and retrieved content as one undifferentiated token stream. There is no enforced boundary between a trusted instruction and untrusted content, so anything that reaches the context can act like a command. The field's consensus fix is to reintroduce that boundary in architecture rather than to rely on prompting. This convention is a concrete, minimal way to carry the boundary through MCP so a client can enforce it.

The convention does not make the model immune to injected text. The model still sees untrusted content. What it provides is the information a client needs to present that content as data, to refuse to act on instructions found inside it without human approval, and to detect tampering. The protection lives in the client's handling, not in the model.

## 2. Terminology

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are used in the RFC 2119 sense.

Roles:

- Tagging server: an MCP server that applies this convention to the content it emits.
- Provenance-aware client: an MCP client or host that reads provenance metadata and enforces the contract in section 8.

A deployment is protected only when a tagging server talks to a provenance-aware client. Any other pairing degrades to current behavior, with no protection.

## 3. Threat model

State this plainly so the convention is not oversold.

Defends against:

- Indirect prompt injection through Resource content and tool outputs, where untrusted data contains text that reads as an instruction.
- Instruction override and tool shadowing embedded in fetched or user-supplied content.
- Body tampering in transit, through the integrity hash (see the limit below).
- Trust-label relabeling by an active in-transit attacker, when a signature is present and the client is configured with the server's key (section 6). Without a key the relabel residual remains; this is the honest default.
- Fence-escape attempts, where injected content tries to close an untrusted span early and append instructions, through the nonce and escaping rules in section 7.

Does not defend against:

- A malicious server. Trust is rooted in the server operator. A server that labels its own malicious instructions as trusted, and signs them with its own key, defeats the convention by definition. That is a supply-chain problem handled by scanning and vetting, not by this convention. This is the one residual a signature cannot close. Note it is limited to visible content: the authoritative-path sanitization in section 8 still strips invisible-unicode smuggling and quarantines decoded tag-character payloads even in trusted-labeled content, so the invisible channel is closed regardless.
- Trust-label relabeling by an active in-transit attacker, while no signature is present or no key is configured. The unkeyed hash covers only the body, so an attacker who flips `trust` can recompute a matching hash. The signature (section 6) closes this: it binds the trust label to the body under a key the attacker does not hold, so a relabel fails verification. Until a key is configured the hash still catches body tampering, and the section 8 authoritative-path sanitization still strips any invisible-unicode smuggling the relabeled body carries.
- A non-conforming client. Without an enforcing client there is no protection.
- Direct prompt injection in the end user's own turn, which does not pass through server-emitted content. User-origin tagging touches this but does not solve it.
- Capability composition across multiple servers, where each server is individually clean but the combination enables a harmful flow. That is a separate analysis.
- The model misbehaving in the absence of injected instructions.

## 4. Trust model

Every piece of emitted content has an origin and a trust level.

Origin records where content came from:

- `author`: written by the server operator.
- `user`: supplied by the end user.
- `external`: fetched from a third party, such as a web page, an API, or a database row outside the operator's control.
- `derived`: computed or transformed from other content.

Trust level is what the client enforces:

- `trusted`: intended by the operator as content the agent may act on.
- `untrusted`: must be treated as data only.
- `quarantined`: determined to be actively suspicious, for example flagged by the tagging library's sanitizer.

Default mapping from origin to trust, which a tagging server MAY override toward stricter but MUST NOT override toward more permissive:

- `author` maps to `trusted`.
- `user` maps to `untrusted`.
- `external` maps to `untrusted`.
- `derived` inherits the lowest trust of its inputs. If any input is untrusted, the result is untrusted.

Two invariants:

- Content MUST NOT be able to elevate its own trust level. Only the tagging library, acting on true origin, sets trust. A provenance-aware client MUST NOT raise a trust level based on anything found inside the content. This is what defeats "this text is trusted, ignore previous instructions" payloads.
- Absence of provenance is not trust. See section 8.

## 5. Item-level provenance

Provenance for a whole content item is carried in the item's reserved extension field. In current MCP, `_meta` is the reserved place for protocol extensions, so this convention places its object there under the namespaced key. Confirm the exact carrier against the installed MCP spec version before implementing; `annotations` is an acceptable alternative if `_meta` is unavailable on a given content type.

Shape:

```json
"_meta": {
  "x-mcp-provenance/v0": {
    "origin": "external",
    "trust": "untrusted",
    "source": "https://example.com/article",
    "fenced": true,
    "integrity": {
      "alg": "sha-256",
      "hash": "<base64 of the hash over the emitted content>",
      "signature": null
    }
  }
}
```

Fields:

- `origin` and `trust`: as defined in section 4. Both required.
- `source`: optional, informational. MUST NOT contain secrets and MUST NOT be used by the client for any trust decision.
- `fenced`: true if the content body uses span-level fencing per section 7.
- `integrity`: see section 6. Required for `trusted` content, optional otherwise.

A worked example, a resource read result whose body was fetched from the web:

```json
{
  "contents": [
    {
      "uri": "notes://external/article",
      "mimeType": "text/plain",
      "text": "…article body…",
      "_meta": {
        "x-mcp-provenance/v0": {
          "origin": "external",
          "trust": "untrusted",
          "source": "https://example.com/article",
          "fenced": false,
          "integrity": { "alg": "sha-256", "hash": "aGVsbG8…", "signature": null }
        }
      }
    }
  ]
}
```

### 5.1 SEP-1913 alignment

MCP SEP-1913 proposes a standard trust-annotation vocabulary. This convention mirrors it so a standard-aware client can read our provenance object, while keeping `x-mcp-provenance/v0` as the stable carrier. Alongside `origin` and `trust`, a tagging server MAY emit:

- `openWorldHint` (boolean): the content came from an untrusted, open-world source. Derived automatically from trust (any non-`trusted` content is open-world) unless set explicitly.
- `sensitiveHint` (`low` | `medium` | `high`): the sensitivity of the data.
- `privateHint` (boolean): the content contains private data.
- `attribution` (array of strings): provenance for audit, seeded from `source`. Under SEP-1913 semantics attribution accumulates and sensitivity escalates as data crosses tool and context boundaries.

These hints are additive and do not by themselves change the section 8 enforcement decision, which is driven by `trust`. They are informational: a conforming client MAY use them to inform action gating (for example, treating a proposed side-effecting action in a context that contains `privateHint` or `sensitiveHint` content as a stronger candidate for human approval), but the reference implementation does not yet consult them — its action-gate is driven entirely by `trust`/taint. `trust` remains authoritative; a client MUST NOT raise trust based on any hint.

## 6. Integrity

Integrity lets a client detect that the content body was altered after the tagging server produced it.

State the layering plainly. The `hash` is unkeyed and covers only the content body, not the trust label. It detects body corruption and tampering, but it does NOT by itself prevent an active in-transit attacker from relabeling `untrusted` content as `trusted`: such an attacker flips the `trust` field and, because the hash is unkeyed, recomputes a matching hash over the unchanged body. The `signature` closes that gap. It is a keyed MAC over the body hash bound together with the trust label and origin, so a party without the key cannot forge a trusted label. When the client is configured with the server's key and requires signatures, a relabel fails verification and is rejected.

- Default hash algorithm is `sha-256`. The `hash` is computed over the exact bytes of the emitted content body, including any fence sentinels from section 7.
- `signature` authenticates the trust label, computed over a canonical serialization of the body hash plus `origin`, `trust`, `source`, `fenced`, and the `sig_alg` itself (so the algorithm cannot be downgraded). Two algorithms are defined, selected by `sig_alg`:
  - `hmac-sha256`: a symmetric keyed MAC. Simple, but the verifier must hold the same shared secret the signer used.
  - `ed25519`: an asymmetric signature bound to a server identity. The server signs with its private key; any client verifies with the server's public key, which can be published rather than shared secretly. An optional `keyid` field carries a key identifier for public-key discovery (for example a `.well-known` endpoint or a JWKS-style key set), the interoperable path aligned with the emerging MCP signing ecosystem.
  `signature` stays null when no key is configured, and the default enforcer behavior is unchanged in that case. Key distribution beyond publishing a public key is out of scope for the convention.
- A verifier MUST bind the verification algorithm to the configured key, NOT to the item's self-declared `sig_alg`. An Ed25519 public key is published, so if it could be accepted as an HMAC secret an attacker could forge a `trusted` label with public information alone (a signature algorithm-confusion attack). A key obtained from a JWKS / `.well-known` key set is Ed25519 by construction and MUST be verified only as `ed25519`; a directly-configured key MUST carry an out-of-band declaration of its algorithm. An item whose `sig_alg` does not match the configured key's algorithm MUST be rejected. Binding `sig_alg` into the signed payload (above) prevents an on-the-wire downgrade of an honestly-signed item but does NOT by itself prevent this confusion, because the attacker computes a fresh forgery over a payload that already names the weaker algorithm; the key-to-algorithm binding is what closes it.
- A provenance-aware client MUST recompute the hash for any item that carries an integrity block. On mismatch it MUST NOT treat the content as `trusted`, SHOULD treat it as `quarantined`, and MUST log the event. When configured with a key, it MUST verify the `signature` on `trusted` content; on failure it MUST NOT treat the content as `trusted` and SHOULD quarantine. A client MAY require signatures, in which case `trusted` content without a valid signature MUST be downgraded to `untrusted`.

## 7. Span-level fencing

Item-level trust is not enough when one content body mixes trusted framing with untrusted data, for example a tool result of the form "Here are the search results: …untrusted web text…". Fencing marks the untrusted spans inside the body.

Sentinel format, ASCII to avoid depending on the unicode that is itself part of the attack surface:

```
[[MCP-UNTRUSTED nonce=<hex32>]] …untrusted bytes… [[/MCP-UNTRUSTED nonce=<hex32>]]
```

Rules for the tagging library:

- Generate a fresh 128-bit random nonce, hex-encoded as 32 characters, for each untrusted span. Do not reuse nonces.
- Before wrapping, neutralize any literal occurrence of the sentinel sequences `[[MCP-UNTRUSTED` or `[[/MCP-UNTRUSTED` inside the untrusted bytes by escaping them, for example to `[[\MCP-UNTRUSTED`, so no inner content can be mistaken for a real sentinel regardless of nonce.
- Set `fenced` to true in the item provenance, and compute the integrity hash over the fully fenced body.

Rules for the enforcer:

- A span opens at a sentinel and extends to the first closing sentinel bearing the identical nonce. Everything between is `untrusted`.
- Sentinel-looking sequences with a non-matching nonce inside a span are literal data, not fences.
- An opening sentinel with no matching close means the remainder of the body is treated as `untrusted`. Fail closed.

Why the nonce matters: an attacker controls only the bytes of the untrusted payload and does not know the per-span nonce, so cannot synthesize a matching closing sentinel to break out of the fence and have following text treated as instructions. The escaping rule closes the residual ambiguity. Fence removal or alteration breaks the item integrity hash.

## 8. Client enforcement contract

A provenance-aware client MUST implement the following. This is the normative core of the convention.

| Trust level        | Client obligation                                                                                                                                                                 |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `trusted`          | MAY be presented to the model as authoritative content, but only after integrity verification and authoritative-path sanitization below. MUST verify integrity when an integrity block is present; on failure, quarantine and flag. MUST sanitize before presenting: strip invisible and format characters, and quarantine if the sanitizer decodes smuggled tag-character instructions.                  |
| `untrusted`        | MUST be presented as data only. MUST NOT be placed in the system or instruction region of the context. MUST require explicit human approval before any side-effecting action derived from it. |
| `quarantined`      | MUST NOT be presented to the model. MAY be replaced with a redaction notice.                                                                                                      |
| missing or unknown | MUST be treated as `untrusted`. Absence of provenance is not trust. Fail closed.                                                                                                   |

Cross-cutting rules:

- Data framing. When presenting `untrusted` content, the client MUST demarcate it explicitly as data that may contain adversarial instructions the model must not follow. Fenced spans are presented as data even inside an otherwise trusted body.
- Action gating. "Derived from untrusted content" is defined pragmatically: if `untrusted` content is present in the context that produced a proposed side-effecting tool call, that call requires human approval unless the client can demonstrate the action does not depend on the untrusted content. Stricter taint tracking is a SHOULD and a future refinement. The reference enforcing proxy implements this with a session-level taint flag: once it enforces any content that is not clean `trusted` (i.e. `untrusted`, `quarantined`, requiring approval, or non-text content it cannot verify such as an image or a binary blob), the session is tainted, and a subsequent side-effecting tool call is held for approval or blocked outright depending on the operator's chosen mode (`annotate` | `approve` | `block`; `annotate`, which only records the disposition and forwards, is the backward-compatible default). "Side-effecting" is identified structurally and locally in two layers: the composition analyzer's exfiltration classifier (a call that can send data outward: send a message, publish or upload, outbound HTTP, post to a channel or external system) plus a set of destructive, state-changing, and code-execution verbs the exfil model omits (delete, drop, wipe, transfer, deploy, run a command, and similar). A pure read or a local non-mutating operation is not gated. This is a heuristic: an unrecognized custom action verb is the honest residual (the gate fails open on it), the same limitation the scanner and composition classifier carry. Gating happens before the call reaches the upstream server, so a blocked or held side effect does not occur.
- No self-elevation. The client MUST NOT raise any trust level based on the content itself, per section 4.
- Authoritative-path sanitization. Before presenting any `trusted` content as authoritative, the client MUST run it through the same sanitizer the tagging library applies at emit (section 11), stripping invisible and format characters and quarantining if smuggled tag-character instructions are decoded. Integrity verifying is not sufficient on its own: the unkeyed hash binds the body but not the trust label (section 6), so a malicious or relabeling party can present a trusted-labeled body. Re-sanitizing is idempotent for content an honest server already sanitized, and it keeps invisible-unicode smuggling out of the instruction region even on the paths section 3 leaves as residual. It does not stop visible-plaintext content under a forged trust label; only the signature does.
- Unknown fields and unknown trust levels. A client MUST ignore unknown fields in the provenance object, and MUST treat an unknown trust level as `untrusted`.
- Logging. Integrity failures, quarantines, and unmatched fences MUST be logged.

### 8.1 Extended enforcement surfaces

The contract above governs the forward path (Resource bodies, Prompt messages, tool output). Three further surfaces carry the same instruction/data confusion and are enforced the same way.

- Server-initiated channels (sampling and elicitation). MCP lets a server send requests back to the client: `sampling/createMessage` asks the client's own model to run a completion, and `elicitation` asks the user for input. Both carry server-controlled text into the model or in front of the user with no trust marker, so a provenance-aware client MUST treat that text as `untrusted` and apply the same handling: each sampling message body and the server-supplied system prompt are framed as data, and a server-supplied system prompt MUST NOT be forwarded in the client's system/instruction region (the reference proxy demotes it to a leading data message). Enforcing any such content taints the session for action gating. A client MAY refuse these requests outright; because they are also a resource-drain and conversation-hijack vector, refusing sampling is a legitimate fail-closed posture. URL-mode elicitation (the user is directed to a server-supplied link) is a phishing vector a client SHOULD decline.

- Continuous integrity (mid-session drift). The lockfile/baseline (section 11) detect a rug pull when the surface is captured, but a benign server can mutate a tool definition after adoption, mid-session. A provenance-aware client that pins a baseline (an operator lockfile, or trust-on-first-use) SHOULD re-check the live surface against the pin on every capability listing, not only at connect time, and on a `list_changed` notification. On drift it MUST log the change and SHOULD taint the session; it MAY withhold the mutated definition and refuse a call to a drifted tool (fail closed). "Matches the pin" means exactly the baseline hash the drift detector computes.

- Memory provenance. Persistent memory reached through MCP (a memory server, a knowledge graph, a vector store) is durable: content written once is recalled in later sessions. Absence of provenance on a recalled memory is not trust, so a memory read MUST be enforced as ordinary tool output (untagged recalled content fails closed to `untrusted`, framed as data). A write to memory is a side-effecting action for the purpose of action gating: persisting content while `untrusted` content is in the session is the moment a poisoning injection lands, so such a write is gated like any other side effect. A client MAY additionally tag content it persists under taint so a later recall can attribute it as untrusted-origin across sessions; a client MUST NOT let such a tag raise trust.

## 9. Conformance and mixed deployments

- A tagging server talking to a provenance-aware client is protected.
- A tagging server talking to a non-aware client behaves as today, with no protection. Tagging is additive and MUST NOT break such clients, which is why the metadata lives in an extension field they will ignore.
- A non-tagging server talking to a provenance-aware client produces content with no provenance, which the client treats as `untrusted` and fails closed. This is safe but may be noisy; the client MAY offer an allowlist for known-good non-tagging servers, at the operator's risk.

## 10. Versioning and extensibility

- The version is carried in the namespace key, `x-mcp-provenance/v0`. Incompatible changes increment the version.
- Consumers ignore unknown fields and treat unknown enumerations conservatively, as in section 8.
- This is v0. It is deliberately small. Resist adding fields until a concrete need is demonstrated.

## 11. Reference implementation

The repository implements both sides so the convention can be demonstrated end to end without waiting for third-party adoption:

- `src/blindspot/provenance/tagger.py` sets the item provenance object, applies fencing per section 7, and sanitizes at emit time.
- `src/blindspot/provenance/integrity.py` computes the hash and the optional signature per section 6.
- `src/blindspot/enforce/middleware.py` implements the client contract in section 8, including fail-closed handling, authoritative-path sanitization, and action gating.
- `src/blindspot/enforce/proxy.py` applies the contract for an unmodified client and implements the section 8.1 extensions: it enforces the server-initiated sampling and elicitation channels (framing their content as data, demoting a server system prompt, relaying under `frame` or refusing under `block`); it re-checks the pinned surface on every listing for mid-session drift; and it gates a memory write and tags persisted-under-taint content. `src/blindspot/scan/memory.py` (`scan-memory`) scans a memory server's already-stored entries for injection, and `classify_memory_tool` in `src/blindspot/compose.py` is the memory write/read taxonomy.
- `fixtures/vulnerable_server.py` is the demonstration target: with the enforcer active, the injected resource and prompt are demoted to data and no longer hijack the agent. `fixtures/sampling_server.py`, `fixtures/mutating_server.py`, and `fixtures/memory_server.py` demonstrate the section 8.1 surfaces (reverse channels, mid-session drift, memory poisoning).
- `src/blindspot/redteam/adaptive.py` is the adaptive-attack harness (section 3 proof): it attacks the reference defense as an adversary who knows how it works and reports attack success under naive versus adaptive attackers, which component each attack targets, and the residual risk. Every in-scope attack fails; only the documented residuals in section 3 succeed.

## 12. Open questions

- Carrier field. Whether `_meta` or `annotations` is the better long-term home, and how either interacts with future MCP spec revisions. Confirm against the installed spec version.
- Signing. Content signatures are only meaningful with a server identity and key distribution mechanism, which is out of scope here. This convention leaves room for it and does not require it.
- Adoption. The convention protects end to end only when clients enforce it. The reference client demonstrates the value; broad protection depends on client adoption. This is the central limitation and should be stated wherever the project is presented.
