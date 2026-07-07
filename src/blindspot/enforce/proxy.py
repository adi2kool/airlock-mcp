"""Client-side enforcing proxy: the trust boundary as a drop-in middleware.

The convention only protects end to end when the consuming client honors it. Rather
than wait for every client vendor to adopt it, this proxy sits between an unmodified
MCP client and an upstream server and enforces the contract on the consuming side.
The client points at the proxy as if it were the server; the proxy connects to the
real server, applies the reference enforcer to every Resource body, Prompt message,
and tool output, and returns the enforced result. Untrusted content arrives at the
model demarcated as data, quarantined content is withheld, and only trusted content
that verifies passes through as authoritative.

This collapses the two-sided adoption problem to one side. It needs no client change,
and because the enforcer fails closed, it protects even against a server that emits no
provenance at all: absent provenance is treated as untrusted and demoted to data. A
server that does tag its content only makes the boundary more precise.

Built on the low-level MCP Server so the proxy controls exactly what it emits. The
upstream capabilities are mirrored: the proxy advertises only the primitives the
upstream actually exposes.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import logging
import re
from dataclasses import dataclass, field

from mcp import ClientSession, types
from mcp.server.lowlevel import Server
from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.server.stdio import stdio_server
from pydantic import AnyUrl

from blindspot.compose import (
    ServerSurface,
    ToolInfo,
    TrifectaLeg,
    _normalize,
    classify_memory_tool,
    classify_server,
)
from blindspot.enforce.broker import build_request, resolve_approval
from blindspot.enforce.infer import InferredProvenance, ProvenanceInferer
from blindspot.enforce.middleware import Enforcement, enforce
from blindspot.ledger import EV_DRIFT, EV_ELICITATION, EV_ENFORCE, EV_LOCK, EV_SAMPLING, Ledger
from blindspot.models import Origin, Trust
from blindspot.provenance.tagger import tag_meta
from blindspot.scan.client import connect
from blindspot.scan.drift import SurfaceChange, capture_category, diff_surfaces, surface_hash

logger = logging.getLogger("blindspot.proxy")

# Where the proxy records what it did to each item, for a provenance-aware client or
# for debugging. The enforced text is the real protection; this is informational.
ENFORCEMENT_NS = "x-mcp-provenance/enforcement"


class LockViolationError(RuntimeError):
    """The upstream surface drifted from the trust lockfile; the proxy will not start."""


class ProxyPolicy:
    """How the proxy enforces. Defaults are fail-closed and honest."""

    def __init__(
        self,
        assume_origin: Origin | None = None,
        verify_key: bytes | None = None,
        require_signature: bool = False,
        infer: bool = False,
        trust_inferred: bool = False,
        key_resolver=None,
        action_mode: str = "annotate",
        key_alg: str = "hmac-sha256",
        audit_log=None,
        audit_sign_key: bytes | None = None,
        audit_keyid: str | None = None,
        lock: dict | None = None,
        approval_resolver=None,
        approval_timeout: float = 300.0,
        pin_on_start: bool = False,
        drift_mode: str = "taint",
        sampling_mode: str = "frame",
        elicitation_mode: str = "frame",
    ) -> None:
        # assume_origin: when the upstream sends no provenance, tag its content at this
        # origin before enforcing (an operator vouching for a known server, at their
        # risk). None (the default) leaves untagged content to fail closed as untrusted.
        self.assume_origin = assume_origin
        self.verify_key = verify_key
        self.require_signature = require_signature
        # infer: when the upstream sends no provenance, classify each item's origin with
        # a local model instead of blanket-failing-closed. trust_inferred: allow an
        # inferred `author` label to be instruction-eligible (off by default; a model
        # fooled into calling injected content trusted must not weaken the boundary).
        self.infer = infer
        self.trust_inferred = trust_inferred
        # key_resolver: keyid -> Ed25519 public key (e.g. KeyStore.resolve), so signed
        # content is verified against a published key set rather than one shared key.
        self.key_resolver = key_resolver
        # key_alg: the algorithm the directly-configured verify_key is for
        # (hmac-sha256 shared secret, or ed25519 raw public key). Bound to the key so a
        # published Ed25519 public key can never be accepted as an HMAC secret (an
        # algorithm-confusion forgery). Keys from key_resolver are always ed25519.
        self.key_alg = key_alg
        # action_mode: what to do when a side-effecting tool call is made in a session
        # that has already seen untrusted content (convention section 8 action gating).
        #   annotate: forward the call, but the enforcement annotation records the taint
        #             (the backward-compatible default; behavior unchanged).
        #   approve : hold the call for explicit human approval; do NOT forward upstream.
        #   block   : refuse the call outright; do NOT forward upstream.
        self.action_mode = action_mode
        # audit_log: path for the signed, hash-chained provenance audit trail (the flight
        # recorder). audit_sign_key/keyid: an Ed25519 private key to sign each entry.
        self.audit_log = audit_log
        self.audit_sign_key = audit_sign_key
        self.audit_keyid = audit_keyid
        # lock: a loaded blindspot.lock (trust lockfile). When set, the proxy refuses to
        # start if the upstream surface has drifted from the pin, and applies the lock's
        # signing requirement / keyid allowlist.
        self.lock = lock
        # approval_resolver: an async callable(ApprovalRequest)->bool for the approval
        # broker. When set and action_mode is "approve", a gated side-effecting call is
        # sent for a human decision instead of being refused outright. approval_timeout
        # bounds the wait; a timeout / denial / error fails closed.
        self.approval_resolver = approval_resolver
        self.approval_timeout = approval_timeout
        # pin_on_start: when no --lock is given, pin the first surface the proxy sees
        # (trust-on-first-use) so mid-session drift is still caught. drift_mode: what to do
        # when the live surface drifts from the pin after startup (a live rug pull).
        #   taint: forward the drifted definitions but taint the session, so any subsequent
        #          side-effecting call is gated (backward compatible; nothing is withheld).
        #   block: withhold the added/changed definitions from the model and refuse a call
        #          to a drifted tool (fail closed). Startup drift is still handled by --lock.
        self.pin_on_start = pin_on_start
        self.drift_mode = drift_mode
        # sampling_mode / elicitation_mode: what to do with a server-INITIATED sampling
        # (createMessage) or elicitation request - the reverse-direction channels where an
        # upstream server can push instructions into the client's own LLM or a coercive
        # prompt to the user. Both channels are enforced (server-supplied text is framed as
        # untrusted data, a server-supplied system prompt is never left in the instruction
        # region, and the session is tainted), then:
        #   frame: relay the enforced request to the downstream client (default), so the
        #          channel keeps working but injected instructions arrive as data.
        #   block: refuse the request (fail closed). No downstream LLM call, no credit spend.
        self.sampling_mode = sampling_mode
        self.elicitation_mode = elicitation_mode


@dataclass
class _Applied:
    """The result of applying enforcement to one item: the decision plus, when the
    proxy inferred provenance, what the model saw."""

    enforcement: Enforcement
    inference: InferredProvenance | None = None


@dataclass
class _SessionState:
    """Per-proxy-session taint for action gating (convention section 8).

    Set once any content the proxy enforced was not fully trusted (untrusted,
    quarantined, or flagged as requiring approval). A tainted session means untrusted
    content is in the context that could influence a subsequent tool call, so a
    side-effecting call is gated under approve/block. The flag is monotonic: once
    untrusted content is seen it stays tainted for the life of the session, matching
    the pragmatic "untrusted content is present in the context" definition in the
    convention (stricter per-call taint tracking is a documented future refinement).

    `pinned_surface` is the trusted baseline (from --lock or --pin-on-start) that live
    drift is checked against; None disables live drift detection. `drifted` remembers,
    per category, the idents whose definition mutated after startup, so a call/read to a
    drifted item can be refused under `--on-drift block`.
    """

    tainted: bool = False
    pinned_surface: dict | None = None
    drifted: dict[str, set[str]] = field(
        default_factory=lambda: {"tools": set(), "prompts": set(), "resources": set()}
    )
    # Per-category hash of the last drift already attested, so a client that re-lists the
    # same mutated surface does not spam the ledger; a NEW mutation (different hash) is
    # still recorded. Withholding under block happens on every list regardless.
    reported_drift: dict[str, str] = field(default_factory=dict)


def _maybe_taint(state: _SessionState, applied: _Applied | None) -> None:
    """Taint the session if this item was anything other than clean trusted content."""
    if applied is None:
        return
    e = applied.enforcement
    if e.disposition is not Trust.TRUSTED or e.requires_approval:
        state.tainted = True


def evaluate_drift(
    pinned_surface: dict | None, category: str, current_map: dict
) -> list[SurfaceChange]:
    """Return the definition-level changes in one category versus the pinned baseline.

    Empty when there is no pin (nothing to compare against) or the category is byte-for-byte
    unchanged. Pure over its inputs, so the mid-session drift decision is unit-testable
    without a live session. Reuses the drift differ, so "matches the pin" means exactly
    "matches the baseline the drift detector would compute" (same as the trust lockfile).
    """
    if not pinned_surface:
        return []
    pinned_cat = pinned_surface.get(category, {})
    if pinned_cat == current_map:
        return []
    return diff_surfaces({category: pinned_cat}, {category: current_map})


async def _check_list_drift(
    items: list,
    category: str,
    is_resource: bool,
    state: _SessionState,
    policy: ProxyPolicy,
    gate: asyncio.Lock,
    ledger: Ledger | None,
    upstream_label: str,
) -> list:
    """Detect mid-session drift for one just-listed category; taint, attest, and (under
    `block`) withhold the mutated definitions.

    This is what makes rug-pull detection continuous rather than startup-only: the trust
    lockfile is checked once when the proxy starts, but a benign server can mutate a tool
    after adoption, and the client re-lists. Every list re-hashes the live surface against
    the pin. Drift taints the session (so a later side-effecting call is gated) and is
    recorded to the tamper-evident ledger. Under `block`, added/changed definitions are
    dropped from the returned list and remembered so a call/read to them is refused too.
    """
    # No pin -> no drift machinery: skip the per-item model_dump + hash entirely (mirrors
    # evaluate_drift's own guard, but avoids capture_category's cost on every list).
    if not state.pinned_surface:
        return items
    current = capture_category(items, is_resource=is_resource)
    changes = evaluate_drift(state.pinned_surface, category, current)
    if not changes:
        # Surface is back at the pin. Clear any prior drift record for this category so a
        # later re-drift (an oscillating pin->malicious->pin->malicious rug pull) is attested
        # again rather than suppressed as a duplicate of the earlier malicious hash.
        state.reported_drift.pop(category, None)
        return items
    # Attest and taint once per distinct mutation; a client re-listing the same drifted
    # surface should not re-spam the ledger, but a further mutation (new hash) is recorded.
    cat_hash = surface_hash({category: current})
    if state.reported_drift.get(category) != cat_hash:
        state.reported_drift[category] = cat_hash
        async with _gate_cm(policy, gate):
            state.tainted = True
        logger.warning(
            "mid-session surface drift in %s (mode=%s): %s",
            category, policy.drift_mode, "; ".join(f"{c.kind} {c.name}" for c in changes),
        )
        if ledger is not None:
            ledger.record_drift(category, changes, policy.drift_mode, upstream_label)
    if policy.drift_mode != "block":
        # taint-only: the definitions still reach the client, but the session is now
        # tainted so any subsequent side-effecting call is held/refused by the action gate.
        return items
    # block: withhold the added/changed definitions so the mutated surface never reaches
    # the model, and remember the drifted idents so call_tool / read refuse them too.
    bad = {c.name for c in changes if c.kind in ("added", "changed")}
    state.drifted[category] |= bad
    key = (lambda it: str(it.uri)) if is_resource else (lambda it: it.name)
    return [it for it in items if key(it) not in bad]


def _drift_refused_tool(name: str) -> types.CallToolResult:
    """The result returned when a call targets a tool whose definition drifted from the
    pin under `--on-drift block`. The call is NOT forwarded upstream."""
    meta = {ENFORCEMENT_NS: {"drift_blocked": True, "tool": name, "reason": "surface-drift"}}
    msg = (
        f"[blindspot] BLOCKED: '{name}' drifted from the pinned surface after this session "
        "started (a live rug pull). Its mutated definition was withheld and the call was "
        "NOT forwarded upstream. Re-pin the server (blindspot lock) once the change is vetted."
    )
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=msg, _meta=meta)], isError=True, _meta=meta
    )


def _gate_cm(policy: ProxyPolicy, gate: asyncio.Lock):
    """Serialize taint reads/writes and the gate decision, but only in the gating modes.

    In `annotate` (the default) this is a no-op context so the proxy keeps full request
    concurrency. In `approve`/`block` it returns the shared lock, so a side-effecting
    call's "check taint then forward" is atomic with respect to any concurrent handler
    that taints the session: a pipelined side-effecting call cannot slip past the gate on
    stale untainted state (a TOCTOU race)."""
    if policy.action_mode in ("approve", "block"):
        return gate
    return contextlib.nullcontext()


def _passthrough_applied() -> _Applied:
    """A synthetic 'untrusted' decision for a non-text block the proxy forwards without
    enforcing: an image, audio, blob resource, or resource link. The proxy cannot verify
    or sanitize such content, and it is an attacker-influenceable injection channel (a
    multimodal prompt injection rides in an image; a fetched file rides in a blob), so
    fail closed and taint the session. The block itself is passed through unchanged; this
    decision exists only to drive taint so a non-text channel cannot slip a side-effecting
    call past the action gate. Its presentation is unused (the caller keeps the block)."""
    return _Applied(
        Enforcement(
            disposition=Trust.UNTRUSTED,
            presentation="",
            instruction_allowed=False,
            requires_approval=True,
            flags=["non_text_passthrough"],
        )
    )


# High-consequence actions the exfil classifier does not model: destructive data ops,
# money movement, deploy/infra control, and code/command execution. The action gate
# holds these too, so "side-effecting" matches the convention's contract (section 8),
# not just the exfil leg of the trifecta. Anchored and run over the same normalized
# text as the classifier to limit false positives; it remains a heuristic, and an
# unrecognized custom verb is the honest residual (fail-open, like the rest of the tool).
_DESTRUCTIVE_ACTION = re.compile(
    r"\b(delete|remove|destroy|drop|wipe|erase|purge|truncate|revoke)\b"
    r"|\b(transfer|wire|pay|charge|refund|withdraw)\b"
    r"|\b(deploy|release|rollback|provision|terminate|shutdown|reboot|restart)\b"
    r"|\b(run|execute|exec|eval|invoke|spawn) (a |the )?"
    r"(command|shell|script|code|program|binary|job|task|process)\b"
    r"|\b(shell|subprocess|os command|arbitrary code)\b"
)


# A provenance envelope prefixed onto content persisted to memory while the session is
# tainted, so a later recall - even in a fresh, not-yet-tainted session - can attribute the
# stored content as untrusted-origin rather than trusting it. ASCII, to avoid depending on
# the unicode that is itself part of the attack surface.
_MEM_ENVELOPE = "[[BLINDSPOT-UNTRUSTED-MEMORY]] "
# Argument keys whose string value is the memory *content* (as opposed to an id/key), so
# the envelope is prefixed onto the payload and never onto an identifier.
_MEMORY_CONTENT_KEY = re.compile(
    r"\b(content|text|value|memory|data|body|note|fact|information|message|observation|payload|entry)\b",
    re.IGNORECASE,
)
# Keys that are identifiers, never content: the envelope must not be prefixed onto these
# even in the fallback (prefixing a key/namespace/uuid corrupts the write).
_MEMORY_ID_KEY = re.compile(
    r"\b(id|ids|key|keys|uuid|guid|name|names|namespace|uri|url|slug|ref|handle|tag|type|kind|label|index)\b",
    re.IGNORECASE,
)


def _wrap_memory_write(arguments: dict) -> tuple[dict, bool]:
    """Prefix the untrusted-memory envelope onto content-like string args being persisted.

    Returns (possibly-rewritten args, wrapped?). Only content-keyed strings are touched, so
    an id/key/namespace field is never corrupted. Idempotent (an already-enveloped value is
    left alone). If no content-like key is present, the longest NON-identifier string value
    is wrapped as a fallback so an unconventional schema is still attributed without
    corrupting an identifier field. Robust to non-dict arguments (returns them unchanged)."""
    if not isinstance(arguments, dict):
        return arguments, False
    out = dict(arguments)
    wrapped = False
    # Match key names on their NORMALIZED form (underscores/camelCase split to words) so
    # `session_id` / `sessionId` register as identifiers and `user_content` as content -
    # a raw `\bid\b` never matches across the underscore in `session_id`.
    norm = {k: _normalize(str(k)) for k in arguments}
    for k, v in arguments.items():
        if isinstance(v, str) and v and _MEMORY_CONTENT_KEY.search(norm[k]) and not v.startswith(_MEM_ENVELOPE):
            out[k] = _MEM_ENVELOPE + v
            wrapped = True
    if not wrapped:
        # Fallback: the longest string under a key that is NOT identifier-shaped, so we never
        # prepend the envelope onto an id/key/namespace/uri and break the write.
        strings = [
            (k, v)
            for k, v in arguments.items()
            if isinstance(v, str) and v and not _MEMORY_ID_KEY.search(norm[k])
        ]
        if strings:
            k, v = max(strings, key=lambda kv: len(kv[1]))
            if not v.startswith(_MEM_ENVELOPE):
                out[k] = _MEM_ENVELOPE + v
                wrapped = True
    return out, wrapped


def _is_side_effecting(name: str, description: str) -> bool:
    """True if a tool can cause an outward or irreversible side effect.

    Three layers, all structural and local:
      1. The composition classifier's EXFIL leg: send a message, publish/upload,
         outbound HTTP, post to a channel or external system (data leaving).
      2. Destructive / state-changing / code-execution verbs the exfil model omits
         (delete, drop, wipe, transfer, deploy, run a command, ...).
      3. A write to MCP-exposed memory: persisting content (especially untrusted content)
         to a memory / knowledge store is a durable state change, and it is the exact
         moment a memory-poisoning injection lands. Gating it once the session is tainted
         stops the poison from ever being written.
    Pure reads and local, non-mutating operations are not gated. This is the same
    meaning of "side-effecting" the convention's action-gating rule uses.
    """
    if classify_memory_tool(name, description or "") == "write":
        return True
    surface = ServerSurface(name="_gate", tools=[ToolInfo(name, description or "")])
    if any(sig.leg is TrifectaLeg.EXFIL for sig in classify_server(surface)):
        return True
    return bool(_DESTRUCTIVE_ACTION.search(_normalize(f"{name} {description or ''}")))


def _gated_response(name: str, mode: str) -> types.CallToolResult:
    """The result returned to the client when a side-effecting call is gated. The call
    is NOT forwarded upstream, so the side effect never happens.

    Returned as a full CallToolResult (isError=True) rather than a bare content list so
    the gating message and the audit `_meta` survive even for a tool that declares an
    outputSchema (the low-level server passes a CallToolResult through unchanged, but
    would replace a bare content list with an output-validation error)."""
    if mode == "block":
        msg = (
            f"[blindspot] BLOCKED: '{name}' is a side-effecting tool and untrusted "
            "content is present in this session's context. Per the enforcement contract "
            "(convention section 8), a side-effecting action derived from untrusted "
            "content requires human approval. The call was NOT forwarded upstream."
        )
    else:  # "approve"
        msg = (
            f"[blindspot] APPROVAL REQUIRED: '{name}' is a side-effecting tool and "
            "untrusted content is present in this session's context. The call is held "
            "pending explicit human approval and was NOT forwarded upstream. Re-issue it "
            "out-of-band once a human has authorized it."
        )
    meta = {
        ENFORCEMENT_NS: {
            "action_gated": mode,
            "tool": name,
            "reason": "untrusted-content-in-context",
            "side_effecting": True,
        }
    }
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=msg, _meta=meta)],
        isError=True,
        _meta=meta,
    )


# Upper bound on the length of a single server-supplied text item the proxy will enforce.
# A hostile upstream controls tool results, resource bodies, and sampling text; the enforcer
# scans content character by character (invisible-unicode sanitization), so an unbounded body
# is a cheap event-loop-stall DoS. Beyond this, the item is truncated for enforcement and
# treated as untrusted data (framed) - safe, since oversized content is not instruction-
# eligible anyway. 1 MiB comfortably exceeds any legitimate declared item.
_MAX_ENFORCE_CHARS = 1_000_000


def _bound_text(text: str) -> tuple[str, bool]:
    """Truncate an oversized body so enforcement work is bounded. Returns (text, truncated)."""
    if isinstance(text, str) and len(text) > _MAX_ENFORCE_CHARS:
        return text[:_MAX_ENFORCE_CHARS], True
    return text, False


def _enforce_text(
    text: str, meta: dict | None, policy: ProxyPolicy, inferer: ProvenanceInferer | None
) -> _Applied:
    """Enforce one text item. Precedence: real `_meta` > assume_origin > inference >
    fail-closed-untrusted."""
    inference: InferredProvenance | None = None
    text, oversized = _bound_text(text)
    body, use_meta = text, meta
    # An oversized item cannot be authoritative regardless of any assume-origin/infer policy;
    # force the fail-closed untrusted path so the truncated body is framed as data only.
    if meta is None and not oversized:
        if policy.assume_origin is not None:
            body, use_meta = tag_meta(text, policy.assume_origin)
        elif inferer is not None and policy.infer:
            inference = inferer.infer(text)
            origin = inference.origin
            # Trust ceiling: inference alone may not promote to a trusted origin.
            if origin is Origin.AUTHOR and not policy.trust_inferred:
                origin = Origin.EXTERNAL
            body, use_meta = tag_meta(text, origin)
    if oversized:
        use_meta = None  # ignore any real _meta too: a truncated body cannot verify integrity
    e = enforce(
        body,
        use_meta,
        verify_key=policy.verify_key,
        require_signature=policy.require_signature,
        key_resolver=policy.key_resolver,
        key_alg=policy.key_alg,
    )
    if oversized and "oversize_truncated" not in e.flags:
        e.flags.append("oversize_truncated")
    return _Applied(e, inference)


def _enforcement_meta(applied: _Applied) -> dict:
    e = applied.enforcement
    annotation: dict = {
        "disposition": e.disposition.value,
        "instruction_allowed": e.instruction_allowed,
        "requires_approval": e.requires_approval,
        "flags": list(e.flags),
    }
    if applied.inference is not None:
        inf = applied.inference
        annotation["inferred_provenance"] = {
            "origin": inf.origin.value,
            "trust": inf.trust.value,
            "rationale": inf.rationale,
            "model_inferred": inf.inferred,
        }
    return {ENFORCEMENT_NS: annotation}


def _log(surface: str, ident: str, applied: _Applied) -> None:
    e = applied.enforcement
    if e.disposition is not Trust.TRUSTED or e.flags:
        detail = ""
        if applied.inference is not None:
            detail = f" inferred={applied.inference.origin.value}: {applied.inference.rationale}"
        logger.info(
            "enforced %s %s -> %s (instruction_allowed=%s) %s%s",
            surface, ident, e.disposition.value, e.instruction_allowed, e.flags, detail,
        )


def _enforce_block(
    block: types.ContentBlock, policy: ProxyPolicy, inferer: ProvenanceInferer | None
) -> tuple[types.ContentBlock, _Applied | None]:
    """Enforce any text a content block carries, returning the transformed block.

    Handles both a plain text block and text embedded in a resource block (an
    injection can ride inside an EmbeddedResource, which has no top-level `.text`).
    Non-text blocks (image, audio, binary resources) carry no text-injection surface
    and pass through unchanged.
    """
    if getattr(block, "type", None) == "text" and getattr(block, "text", None) is not None:
        applied = _enforce_text(block.text, getattr(block, "meta", None), policy, inferer)
        text = applied.enforcement.presentation
        return types.TextContent(type="text", text=text, _meta=_enforcement_meta(applied)), applied

    res = getattr(block, "resource", None)
    if res is not None and getattr(res, "text", None) is not None:
        applied = _enforce_text(res.text, getattr(res, "meta", None), policy, inferer)
        new_res = types.TextResourceContents(
            uri=res.uri,
            mimeType=getattr(res, "mimeType", None),
            text=applied.enforcement.presentation,
            _meta=_enforcement_meta(applied),
        )
        return types.EmbeddedResource(type="resource", resource=new_res), applied

    # Non-text block (image, audio, blob resource, resource link): the proxy cannot
    # enforce text it does not have, so it forwards the block unchanged. It is still
    # untrusted, attacker-influenceable content (a multimodal injection channel), so it
    # taints the session. Returning a passthrough decision instead of None is what makes
    # _maybe_taint fire, closing the "deliver the injection as a blob/image to dodge the
    # action gate" bypass.
    return block, _passthrough_applied()


def _source_text(block) -> str | None:
    """The text a content block carries (top-level, or inside a text resource), for
    hashing into the audit trail. None for non-text/binary blocks."""
    t = getattr(block, "text", None)
    if t is not None:
        return t
    res = getattr(block, "resource", None)
    return getattr(res, "text", None) if res is not None else None


@dataclass
class _Runtime:
    """Shared, mutable proxy state the client-session callbacks and the request handlers
    both close over. It exists because the sampling / elicitation / notification callbacks
    are installed on the UPSTREAM session at connect() time (before the downstream server
    is built), and they run in the session's receive task rather than a request handler,
    so they cannot reach the downstream client via the request-context contextvar. The
    handlers capture the downstream ServerSession here; the callbacks read it back."""

    policy: ProxyPolicy
    state: _SessionState
    ledger: Ledger | None
    gate: asyncio.Lock
    inferer: ProvenanceInferer | None
    upstream_label: str = ""
    session: ClientSession | None = None  # upstream (set after connect yields)
    downstream: object | None = None  # downstream ServerSession (captured in handlers)


def _capture_downstream(runtime: _Runtime, server: Server) -> None:
    """Stash the downstream client session so the sampling/elicitation callbacks (which
    run outside any request context) can relay to it. Cheap and idempotent."""
    try:
        runtime.downstream = server.request_context.session
    except Exception:  # noqa: BLE001 - no active request context yet
        pass


def _downstream_supports(down, capability: str) -> bool:
    """True if the downstream client declared `sampling` or `elicitation`. Fail closed on
    an unknown/old client so the proxy never relays to a client that cannot handle it."""
    if down is None:
        return False
    try:
        if capability == "sampling":
            cap = types.ClientCapabilities(sampling=types.SamplingCapability())
        else:
            cap = types.ClientCapabilities(elicitation=types.ElicitationCapability())
        return bool(down.check_client_capability(cap))
    except Exception:  # noqa: BLE001
        return False


def _collect_text(content) -> str:
    """Concatenate every text-bearing sub-block of a sampling message content value.

    Sampling content may be a single text block, an image/audio block, a LIST of blocks, or
    a structured block that nests other content. Collecting all of it lets the proxy frame
    the text even when an injection hides in a list item or a nested block, closing the
    bypass where any content without a top-level `.text` was relayed to the model verbatim.
    """
    if content is None:
        return ""
    if isinstance(content, (list, tuple)):
        return "\n".join(_collect_text(c) for c in content)
    t = getattr(content, "text", None)
    if isinstance(t, str):
        return t
    nested = getattr(content, "content", None)
    if nested is not None and nested is not content:
        return _collect_text(nested)
    return ""


async def _handle_sampling(runtime: _Runtime, params):
    """Enforce, then relay or refuse, a server-initiated sampling (createMessage) request.

    createMessage lets the UPSTREAM server push messages - and a system prompt - into the
    DOWNSTREAM client's own LLM: server-controlled text entering the model with no trust
    marker, the reverse-direction twin of the tool-output channel, and a credit-drain /
    conversation-hijack vector. Each message body and the system prompt are enforced as
    STRICTLY untrusted - via enforce(text, None) directly, ignoring any operator
    assume-origin / infer policy, which vouches for the forward path only and must never
    promote server-pushed reverse-channel text to trusted. Untrusted text is framed as data
    and the session is tainted. The server's system prompt is never forwarded as a system
    prompt (untrusted content must not sit in the instruction region) - it is framed and
    demoted to a leading data message. `frame` relays the enforced request downstream;
    `block` refuses it (no LLM call, no credit spend)."""
    mode = runtime.policy.sampling_mode
    ledger = runtime.ledger
    out: list[types.SamplingMessage] = []

    def _record(applied: _Applied, ident: str, text: str | None) -> None:
        # Taint WITHOUT the gate: this callback runs nested inside an in-flight call_tool
        # that may hold runtime.gate (the fast path forwards under the lock), so acquiring
        # it here would deadlock. The taint write is a monotonic boolean, so an
        # unsynchronized set is safe; the residual is only a narrow decide-then-taint window
        # for a side-effecting call issued concurrently with this reverse-channel request.
        _maybe_taint(runtime.state, applied)
        if ledger is not None:
            ledger.record_sampling(EV_SAMPLING, ident, text, applied.enforcement, mode)

    if params.systemPrompt:
        sp = _bound_text(params.systemPrompt)[0]
        applied = _Applied(enforce(sp, None))
        _record(applied, "systemPrompt", sp)
        out.append(types.SamplingMessage(
            role="user", content=types.TextContent(type="text", text=applied.enforcement.presentation)))
    for i, msg in enumerate(params.messages):
        text = _bound_text(_collect_text(msg.content))[0]
        if text:
            applied = _Applied(enforce(text, None))
            _record(applied, f"message[{i}]", text)
            # Emit as a single framed text block, replacing any structured/list shape so no
            # sub-block of it reaches the model un-framed.
            out.append(types.SamplingMessage(
                role=msg.role, content=types.TextContent(type="text", text=applied.enforcement.presentation)))
        else:
            # Pure non-text content (image/audio) carries no framable text: taint and pass
            # it through (an unverifiable, attacker-influenceable channel).
            _record(_passthrough_applied(), f"message[{i}]", None)
            out.append(msg)

    if mode == "block":
        logger.info("sampling refused by policy (block)")
        return types.ErrorData(
            code=types.INVALID_REQUEST,
            message="[blindspot] sampling refused (--on-sampling block): the upstream's "
            "createMessage was enforced and recorded but not run against the client's LLM.",
        )
    down = runtime.downstream
    if not _downstream_supports(down, "sampling"):
        return types.ErrorData(
            code=types.INVALID_REQUEST,
            message="[blindspot] sampling not available downstream; failing closed.",
        )
    try:
        return await down.create_message(
            messages=out,
            max_tokens=params.maxTokens or 1024,
            system_prompt=None,  # untrusted server text never occupies the system region
            temperature=params.temperature,
            stop_sequences=params.stopSequences,
            model_preferences=params.modelPreferences,
            include_context=params.includeContext,
        )
    except Exception as exc:  # noqa: BLE001 - a downstream failure fails closed
        logger.warning("downstream sampling relay failed: %s", exc)
        return types.ErrorData(
            code=types.INTERNAL_ERROR, message=f"[blindspot] downstream sampling failed: {exc}"
        )


async def _handle_elicitation(runtime: _Runtime, params):
    """Enforce, then relay or refuse, a server-initiated elicitation request.

    Elicitation puts a server-controlled prompt (and, in URL mode, a link) in front of the
    USER: a social-engineering / phishing surface. The message is framed as untrusted data
    and the session is tainted before anything reaches the user. URL-mode elicitation (the
    user is asked to visit a server-supplied link) is the strongest phishing vector and is
    always declined. Otherwise `frame` relays a form elicitation with the framed message,
    and `block` declines (no user input solicited)."""
    mode = runtime.policy.elicitation_mode
    message = _bound_text(getattr(params, "message", "") or "")[0]
    # Strictly untrusted (ignore assume-origin/infer). Taint without the gate: like the
    # sampling callback this can run nested inside an in-flight call_tool holding the gate.
    applied = _Applied(enforce(message, None))
    _maybe_taint(runtime.state, applied)
    if runtime.ledger is not None:
        runtime.ledger.record_sampling(EV_ELICITATION, "message", message, applied.enforcement, mode)
    # URL-mode elicitation directs the user to a server-supplied link (the phishing vector):
    # decline. Detect it by the declared mode OR the mere presence of a url field, so a
    # form-mode payload cannot smuggle a url past the check.
    is_url = getattr(params, "mode", None) == "url" or bool(
        getattr(params, "url", None) or (getattr(params, "model_extra", None) or {}).get("url")
    )
    down = runtime.downstream
    if mode == "block" or is_url or not _downstream_supports(down, "elicitation"):
        return types.ElicitResult(action="decline")
    try:
        schema = getattr(params, "requestedSchema", None) or {"type": "object", "properties": {}}
        return await down.elicit(message=applied.enforcement.presentation, requestedSchema=schema)
    except Exception as exc:  # noqa: BLE001 - fail closed
        logger.warning("downstream elicitation relay failed: %s", exc)
        return types.ElicitResult(action="decline")


async def _handle_notification(runtime: _Runtime, message) -> None:
    """Forward an upstream list_changed notification to the downstream client so it
    re-lists, which runs the mid-session drift check on the normal request path. Only
    list_changed is relayed; everything else is ignored. Fire-and-forget, so it cannot
    deadlock the receive loop."""
    down = runtime.downstream
    if down is None:
        return
    root = getattr(message, "root", None)
    try:
        if isinstance(root, types.ToolListChangedNotification):
            await down.send_tool_list_changed()
        elif isinstance(root, types.PromptListChangedNotification):
            await down.send_prompt_list_changed()
        elif isinstance(root, types.ResourceListChangedNotification):
            await down.send_resource_list_changed()
    except Exception as exc:  # noqa: BLE001 - forwarding is best-effort
        logger.debug("list_changed forward failed: %s", exc)


def make_proxy(
    session: ClientSession,
    init_result,
    runtime: _Runtime,
    name: str = "blindspot-proxy",
) -> Server:
    """Build the client-facing proxy server over a live upstream session.

    Only the primitives the upstream declares are registered, so the proxy mirrors the
    upstream's capability surface rather than over-advertising. Shared, mutable state
    (taint, the pinned surface for drift, the downstream-session handle the sampling /
    elicitation callbacks relay to) lives on `runtime`.
    """
    server: Server = Server(name)
    caps = init_result.capabilities
    policy = runtime.policy
    state = runtime.state
    gate = runtime.gate
    inferer = runtime.inferer
    ledger = runtime.ledger
    upstream_label = runtime.upstream_label
    # A tool name -> description cache. call_tool only receives (name, arguments), so the
    # description needed to classify a tool as side-effecting is captured from list_tools
    # (and populated lazily in call_tool if not yet seen).
    tool_descs: dict[str, str] = {}
    # `gate` is runtime.gate (bound above): the ONE lock shared by the request handlers and
    # the server-initiated sampling/elicitation callbacks, so the action-gate taint-read and
    # a reverse-channel taint-write are serialized (the sampling/elicitation callbacks taint
    # without acquiring it to avoid a nested-reentrancy deadlock; see _handle_sampling). A
    # fresh per-make_proxy lock here would split the two and reopen the action-gate TOCTOU.
    # Per-tool memoization of the memory/side-effect classification (depends only on the
    # static (name, description), so compute once per tool name, not per call).
    mem_cache: dict[str, str | None] = {}
    side_effect_cache: dict[str, bool] = {}

    if caps.resources is not None:

        @server.list_resources()
        async def list_resources() -> list[types.Resource]:
            resources = (await session.list_resources()).resources
            return await _check_list_drift(
                resources, "resources", True, state, policy, gate, ledger, upstream_label
            )

        @server.list_resource_templates()
        async def list_resource_templates() -> list[types.ResourceTemplate]:
            try:
                return (await session.list_resource_templates()).resourceTemplates
            except Exception:  # noqa: BLE001 - upstream may not support templates
                return []

        @server.read_resource()
        async def read_resource(uri: AnyUrl):
            _capture_downstream(runtime, server)
            if policy.drift_mode == "block" and str(uri) in state.drifted["resources"]:
                # A drifted resource body is withheld under block (rug pull): return a
                # redaction rather than the mutated content.
                return [
                    ReadResourceContents(
                        content="[blindspot] resource withheld: drifted from the pinned surface",
                        mime_type="text/plain",
                        meta=None,
                    )
                ]
            result = await session.read_resource(uri)
            out: list[ReadResourceContents] = []
            for c in result.contents:
                mime = getattr(c, "mimeType", None) or "text/plain"
                text = getattr(c, "text", None)
                if text is None:
                    # Binary resource: no text to enforce, pass the bytes through.
                    blob = getattr(c, "blob", "")
                    try:
                        raw = base64.b64decode(blob) if isinstance(blob, str) else blob
                    except Exception:  # noqa: BLE001
                        raw = b""
                    out.append(ReadResourceContents(content=raw, mime_type=mime, meta=None))
                    # Binary body is unverified, attacker-influenceable content: taint.
                    binary_applied = _passthrough_applied()
                    async with _gate_cm(policy, gate):
                        _maybe_taint(state, binary_applied)
                    if ledger is not None:
                        ledger.record_enforcement("resource", str(uri), None, binary_applied.enforcement)
                    continue
                applied = _enforce_text(text, getattr(c, "meta", None), policy, inferer)
                _log("resource", str(uri), applied)
                async with _gate_cm(policy, gate):
                    _maybe_taint(state, applied)
                if ledger is not None:
                    ledger.record_enforcement("resource", str(uri), text, applied.enforcement)
                out.append(
                    ReadResourceContents(
                        content=applied.enforcement.presentation,
                        mime_type=mime,
                        meta=_enforcement_meta(applied),
                    )
                )
            return out

    if caps.prompts is not None:

        @server.list_prompts()
        async def list_prompts() -> list[types.Prompt]:
            prompts = (await session.list_prompts()).prompts
            return await _check_list_drift(
                prompts, "prompts", False, state, policy, gate, ledger, upstream_label
            )

        @server.get_prompt()
        async def get_prompt(name: str, arguments: dict[str, str] | None) -> types.GetPromptResult:
            _capture_downstream(runtime, server)
            if policy.drift_mode == "block" and name in state.drifted["prompts"]:
                # A drifted prompt is withheld under block (rug pull).
                return types.GetPromptResult(
                    description="withheld by blindspot (surface drift)",
                    messages=[
                        types.PromptMessage(
                            role="user",
                            content=types.TextContent(
                                type="text",
                                text="[blindspot] prompt withheld: drifted from the pinned surface",
                            ),
                        )
                    ],
                )
            result = await session.get_prompt(name, arguments)
            messages: list[types.PromptMessage] = []
            last_meta: dict | None = None
            for m in result.messages:
                block, applied = _enforce_block(m.content, policy, inferer)
                if applied is not None:
                    _log("prompt", name, applied)
                    async with _gate_cm(policy, gate):
                        _maybe_taint(state, applied)
                    if ledger is not None:
                        ledger.record_enforcement("prompt", name, _source_text(m.content), applied.enforcement)
                    last_meta = _enforcement_meta(applied)
                messages.append(types.PromptMessage(role=m.role, content=block))
            return types.GetPromptResult(
                description=result.description, messages=messages, _meta=last_meta
            )

    if caps.tools is not None:

        @server.list_tools()
        async def list_tools() -> list[types.Tool]:
            tools = (await session.list_tools()).tools
            tools = await _check_list_drift(
                tools, "tools", False, state, policy, gate, ledger, upstream_label
            )
            for t in tools:
                tool_descs[t.name] = t.description or ""
            return tools

        # validate_input=False: the upstream server validates arguments; the proxy just
        # forwards them and enforces the output.
        @server.call_tool(validate_input=False)
        async def call_tool(name: str, arguments: dict) -> list[types.ContentBlock] | types.CallToolResult:
            _capture_downstream(runtime, server)
            # A tool whose definition drifted from the pin is refused under block: the call
            # never reaches the (possibly rug-pulled) upstream tool. state.drifted is
            # populated by a list, but a client can call WITHOUT ever listing, so under block
            # we re-capture and re-check the live tools against the pin right here before
            # deciding - closing the "mutate then call, never list" bypass. Fail-safe: if the
            # verification list fails, fall through to whatever the cached drift set says.
            if policy.drift_mode == "block" and state.pinned_surface is not None:
                try:
                    current = (await session.list_tools()).tools
                    await _check_list_drift(
                        current, "tools", False, state, policy, gate, ledger, upstream_label
                    )
                    for t in current:
                        tool_descs.setdefault(t.name, t.description or "")
                except Exception:  # noqa: BLE001 - verification is best-effort; use cached set
                    pass
            if policy.drift_mode == "block" and name in state.drifted["tools"]:
                logger.warning("refusing call to drifted tool %s (surface drift, block)", name)
                return _drift_refused_tool(name)

            async def _forward_and_enforce() -> types.CallToolResult:
                # Called with the gate lock held (fast path) or re-held (after approval);
                # it must NOT re-acquire the lock. Enforces every output block, taints,
                # records to the ledger, and forwards structuredContent + isError so an
                # outputSchema tool is not bricked and a failed call is not shown as success.
                # Classify only when the result can change behavior (a tainted write to
                # envelope, or a ledger to label a memory read); memoized per tool name since
                # it depends only on the static (name, description). Avoids the full regex
                # battery on every call in the common annotate + no-audit path.
                mem = None
                if state.tainted or ledger is not None:
                    if name not in mem_cache:
                        mem_cache[name] = classify_memory_tool(name, tool_descs.get(name, ""))
                    mem = mem_cache[name]
                call_args = arguments
                # A write to MCP-exposed memory while untrusted content is in the session
                # persists possibly-poisoned content. If the write was not gated (annotate
                # mode, or an approved call), envelope the content so a later recall - even
                # in a fresh session - attributes it as untrusted-origin. The write itself is
                # gated under approve/block by _is_side_effecting. The audit record is made
                # whenever a tainted write occurs, even if no content-like field could be
                # enveloped (e.g. an all-structured knowledge-graph write), so the trail never
                # silently omits an untrusted persist.
                if mem == "write" and state.tainted:
                    call_args, wrapped = _wrap_memory_write(arguments)
                    if ledger is not None:
                        ledger.append(EV_ENFORCE, surface="memory", ident=name,
                                      disposition=Trust.UNTRUSTED.value,
                                      detail={"flags": ["untrusted_memory_write"],
                                              "enveloped": bool(wrapped)})
                result = await session.call_tool(name, call_args)
                # A memory read is recorded under surface "memory" so the audit trail
                # distinguishes what flowed out of persistent storage from ordinary tool
                # output; the content is enforced (framed as data) on the same path.
                surface = "memory" if mem in ("read", "write") else "tool"
                blocks: list[types.ContentBlock] = []
                for c in result.content:
                    block, applied = _enforce_block(c, policy, inferer)
                    if applied is not None:
                        _log(surface, name, applied)
                        _maybe_taint(state, applied)
                        if ledger is not None:
                            ledger.record_enforcement(surface, name, _source_text(c), applied.enforcement)
                        # Recall-side recognition of the untrusted-memory envelope (an
                        # UNAUTHENTICATED attribution hint written by an earlier session). The
                        # recalled content is already framed as untrusted (memory reads fail
                        # closed), so this only ATTESTS the cross-session origin; a forged
                        # marker can at most keep content untrusted, never elevate it.
                        if mem == "read" and _MEM_ENVELOPE in (_source_text(c) or ""):
                            state.tainted = True
                            if ledger is not None:
                                ledger.append(EV_ENFORCE, surface="memory", ident=name,
                                              disposition=Trust.UNTRUSTED.value,
                                              detail={"flags": ["untrusted_origin_memory_recalled"]})
                    blocks.append(block)
                structured = getattr(result, "structuredContent", None)
                if structured is not None:
                    _maybe_taint(state, _passthrough_applied())
                return types.CallToolResult(
                    content=blocks,
                    structuredContent=structured,
                    isError=bool(getattr(result, "isError", False)),
                )

            # Action gating (convention section 8). Decide UNDER the lock (a TOCTOU-safe
            # read of taint + side-effect classification), but never hold the lock across
            # a human approval wait, which would serialize / deadlock the session.
            async with _gate_cm(policy, gate):
                gated = False
                if policy.action_mode in ("approve", "block") and state.tainted:
                    desc = tool_descs.get(name)
                    if desc is None:
                        # Not seen via list_tools (a client may call without listing first).
                        try:
                            for t in (await session.list_tools()).tools:
                                tool_descs[t.name] = t.description or ""
                        except Exception:  # noqa: BLE001 - upstream list may fail; classify by name
                            pass
                        desc = tool_descs.get(name, "")
                    # Memoized: side-effecting-ness depends only on the static (name, desc),
                    # so the trifecta regex battery runs once per tool name, not per call.
                    if name not in side_effect_cache:
                        side_effect_cache[name] = _is_side_effecting(name, desc)
                    gated = side_effect_cache[name]
                if not gated:
                    # Fast path: forward under the lock (keeps decide-then-forward atomic).
                    return await _forward_and_enforce()

            # Gated; the lock is released. Record the decision, then resolve it.
            logger.info(
                "action-gated tool %s (mode=%s): untrusted content in context", name, policy.action_mode
            )
            if ledger is not None:
                ledger.record_action(name, policy.action_mode, gated=True, side_effecting=True)
            # block, or approve with no resolver configured: refuse (never forwarded).
            if policy.action_mode == "block" or policy.approval_resolver is None:
                return _gated_response(name, policy.action_mode)
            # approve with a resolver: broker a human decision OUTSIDE the lock.
            request = build_request(
                name, arguments, "untrusted-content-in-context",
                {"action_gated": "approve", "tool": name,
                 "reason": "untrusted-content-in-context", "side_effecting": True},
                sign_key=policy.audit_sign_key, keyid=policy.audit_keyid,
            )
            approved = await resolve_approval(
                policy.approval_resolver, request, timeout=policy.approval_timeout, ledger=ledger
            )
            if not approved:
                return _gated_response(name, "approve")
            # Approved. Re-acquire the lock (taint is monotonic, so re-checking is safe)
            # and forward this specific, human-authorized call.
            async with _gate_cm(policy, gate):
                return await _forward_and_enforce()

    return server


async def run_proxy(upstream: str, is_http: bool, policy: ProxyPolicy) -> None:
    """Connect to the upstream, then serve the enforcing proxy over stdio.

    The upstream session stays open for the life of the proxy. The client speaks to the
    proxy over this process's stdio, so nothing but MCP protocol may touch stdout.
    """
    ledger = (
        Ledger(policy.audit_log, sign_key=policy.audit_sign_key, keyid=policy.audit_keyid)
        if policy.audit_log
        else None
    )
    # Shared runtime the request handlers and the server-initiated-channel callbacks close
    # over. Built before connect() because the sampling / elicitation / notification
    # callbacks are installed on the upstream session at connect time.
    runtime = _Runtime(
        policy=policy,
        state=_SessionState(),
        ledger=ledger,
        gate=asyncio.Lock(),
        inferer=ProvenanceInferer() if policy.infer else None,
        upstream_label=upstream,
    )

    async def _sampling_cb(context, params):
        return await _handle_sampling(runtime, params)

    async def _elicitation_cb(context, params):
        return await _handle_elicitation(runtime, params)

    async def _message_handler(message):
        await _handle_notification(runtime, message)

    async with connect(
        upstream, is_http,
        sampling_callback=_sampling_cb,
        elicitation_callback=_elicitation_cb,
        message_handler=_message_handler,
    ) as (session, init_result):
        runtime.session = session
        state = runtime.state
        # The baseline that live (mid-session) drift is checked against. --lock pins to the
        # operator's checked-in surface; --pin-on-start pins the first surface seen (TOFU).
        if policy.lock is not None:
            # Trust lockfile: refuse to front a server whose surface drifted from the pin
            # (a rug pull) at startup. Fail closed - the proxy does not start.
            from blindspot.lockfile import check as _lock_check
            from blindspot.lockfile import restrict_resolver as _restrict
            from blindspot.scan.drift import capture_surface as _capture_surface

            surface = await _capture_surface(session)
            violations = _lock_check(surface, policy.lock)
            if violations:
                if ledger is not None:
                    for v in violations:
                        ledger.append(EV_LOCK, surface="server", ident=upstream,
                                      detail={"kind": v.kind, "detail": v.detail})
                raise LockViolationError(
                    "trust lockfile violation: "
                    + "; ".join(f"{v.kind}: {v.detail}" for v in violations)
                )
            # Apply the lock's signing requirement / keyid allowlist to the live policy.
            if policy.lock.get("require_signature"):
                policy.require_signature = True
            allowed = policy.lock.get("allowed_keyids")
            if allowed:
                policy.key_resolver = _restrict(policy.key_resolver, allowed)
            # Startup matched the lock, so pin to it for continuous drift detection.
            state.pinned_surface = policy.lock.get("surface")
        elif policy.pin_on_start:
            from blindspot.scan.drift import capture_surface as _capture_surface

            state.pinned_surface = await _capture_surface(session)
        server = make_proxy(session, init_result, runtime)
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())
