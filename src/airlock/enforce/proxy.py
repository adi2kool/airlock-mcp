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
from functools import lru_cache

from mcp import ClientSession, types
from mcp.server.lowlevel import Server
from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.server.stdio import stdio_server
from pydantic import AnyUrl

from airlock.compose import (
    ServerSurface,
    ToolInfo,
    TrifectaLeg,
    _normalize,
    classify_memory_tool,
    classify_server,
)
from airlock.enforce import dlp
from airlock.enforce.broker import build_request, resolve_approval
from airlock.enforce.taintbus import SharedTaint
from airlock.enforce.infer import InferredProvenance, ProvenanceInferer
from airlock.enforce.middleware import Enforcement, enforce
from airlock.ledger import (
    EV_DRIFT,
    EV_EGRESS,
    EV_ELICITATION,
    EV_ENFORCE,
    EV_LOCK,
    EV_SAMPLING,
    Ledger,
)
from airlock.models import Origin, Trust
from airlock.provenance.tagger import tag_meta
from airlock.scan.client import connect
from airlock.scan.drift import SurfaceChange, capture_category, diff_surfaces, surface_hash

logger = logging.getLogger("airlock.proxy")

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
        egress_mode: str = "annotate",
        egress_optional: tuple[str, ...] = (),
        taint_context: str | None = None,
        taint_ttl: float = 3600.0,
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
        # lock: a loaded airlock.lock (trust lockfile). When set, the proxy refuses to
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
        # egress_mode: what to do when an OUTBOUND tool call to an exfil-capable tool carries
        # a secret or high-confidence PII in its arguments (egress DLP). The action gate
        # decides WHETHER a side-effecting call proceeds; this inspects WHAT sensitive data
        # is inside the call the client is about to send out.
        #   annotate: forward the call unchanged; record the finding to the ledger (default,
        #             backward compatible - with no audit log this path is a no-op).
        #   redact  : replace the detected secret/PII spans in a COPY of the arguments and
        #             forward the redacted copy, so the call still works but the secret does
        #             not leave.
        #   block   : refuse the call outright; do NOT forward upstream (the secret never
        #             leaves the boundary).
        self.egress_mode = egress_mode
        # egress_optional: names of opt-in DLP detectors (us_ssn / email / phone) to add to the
        # default battery. Off by default because their shape collides with benign business data
        # (a recipient email is legitimate in a send_email arg); enable only where warranted.
        self.egress_optional = tuple(egress_optional)
        # taint_context: a directory shared by every proxy fronting the servers of ONE client
        # (airlock init gives them the same one). When set, untrusted content enforced by any
        # proxy in the context taints the whole context, so a side-effecting call to a
        # DIFFERENT server is gated too - the lethal trifecta enforced across servers at
        # runtime, not just flagged statically. None (default) is single-server, local-only.
        # taint_ttl bounds how long a taint marker stays live (so a past session self-expires).
        self.taint_context = taint_context
        self.taint_ttl = taint_ttl


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
    # Cross-server taint bus (from --taint-context), shared with the other proxies fronting
    # this client's servers. None disables it (single-server, local-only). See taintbus.py.
    shared: SharedTaint | None = None


def _propagate_taint(state: _SessionState, reason: str) -> None:
    """Taint this session AND, when a cross-server context is configured, the shared bus so a
    side-effecting call to a DIFFERENT server in the same context is gated too."""
    state.tainted = True
    if state.shared is not None:
        state.shared.taint(reason)


def _session_tainted(state: _SessionState) -> bool:
    """True if this session is tainted, OR a peer proxy in the same cross-server context has
    seen untrusted content. Reads the shared bus only while still-untainted and promotes it to
    local (taint is monotonic), so the per-call gate pays at most one filesystem read."""
    if not state.tainted and state.shared is not None and state.shared.is_tainted():
        state.tainted = True
    return state.tainted


def _maybe_taint(state: _SessionState, applied: _Applied | None) -> None:
    """Taint the session if this item was anything other than clean trusted content."""
    if applied is None:
        return
    e = applied.enforcement
    if e.disposition is not Trust.TRUSTED or e.requires_approval:
        _propagate_taint(state, "untrusted content enforced")


# A coercive imperative aimed at the model. Paired with an exfil directive it is tool
# poisoning even when the exfil target is a documented-looking email (which the scanner
# softens to NOTE). Used ONLY to arm the gate (taint), where a rare false taint just
# over-gates a side-effecting call; a bare documented recipient with no coercion never matches.
_COERCIVE_IMPERATIVE = re.compile(
    r"\byou\s+(?:must|should|need\s+to|have\s+to|are\s+required\s+to|shall|will)\b"
    r"|\b(?:always|immediately|secretly|silently|be\s+sure\s+to|make\s+sure\s+to|"
    r"don'?t\s+forget\s+to|without\s+(?:telling|informing|asking))\b",
    re.IGNORECASE,
)


def _declared_text(obj) -> str:
    """Every declared string value of a tool / prompt / resource definition, for the list-time
    poison scan. Serializes the object and collects ALL string leaves - name, title,
    description, annotations (incl. annotations.title), inputSchema property descriptions and
    enum values, prompt-argument descriptions - so a poison hidden in ANY model-visible declared
    field arms the gate, not just `description`. The audit found `title` / `annotations.title` /
    parameter descriptions were uncovered channels; scanning the whole definition closes the
    class rather than one field at a time. Best-effort: falls back to name+description."""
    try:
        d = obj.model_dump(mode="json", exclude_none=True)
    except Exception:  # noqa: BLE001
        return f"{getattr(obj, 'name', '') or ''} {getattr(obj, 'description', '') or ''}"
    out: list[str] = []

    def walk(v) -> None:
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, (list, tuple)):
            for x in v:
                walk(x)

    walk(d)
    return " ".join(out)


def _description_poisoned(texts: list[str]) -> bool:
    """True if a declared tool/prompt/resource DESCRIPTION carries a tool-poisoning signal
    strong enough to arm the action gate for the model's next call.

    A statically-poisoned description is untrusted content the model reads, but it is not a
    tool RESULT, so the normal taint path never sees it (the audit's M1): under `--on-action
    block` an untainted session skips the gate and forwards a description-coerced exfil call.
    Scanning descriptions at list time and tainting on a hit closes that hole.

    Tainting is deliberately MORE sensitive than the scanner's CI gate (a false taint only
    over-gates a side-effecting call, which is safe), but must not fire on a tool that merely
    DOCUMENTS a destination (a send_email recipient), which would cause approval fatigue. So
    it taints on: any WARNING+ scanner finding (instruction override, hidden unicode,
    homoglyph, exfil-to-URL, sleeper, 'call X instead'), OR an exfil directive CO-PRESENT with
    a coercive imperative aimed at the model. Best-effort: a scanner error never taints."""
    try:
        from airlock.models import AttackClass, Severity, severity_rank
        from airlock.scan.detectors.patterns import scan_text

        warn = severity_rank(Severity.WARNING)
        for t in texts:
            if not t:
                continue
            snippet = t[:_MAX_ENFORCE_CHARS]
            findings = scan_text(snippet, "tool", "_desc", ())
            if any(severity_rank(f.severity) >= warn for f in findings):
                return True
            if _COERCIVE_IMPERATIVE.search(snippet) and any(
                f.attack_class == AttackClass.DATA_EXFILTRATION for f in findings
            ):
                return True
    except Exception:  # noqa: BLE001 - never let description scanning break a list call
        return False
    return False


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
            _propagate_taint(state, f"mid-session surface drift in {category}")
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
        f"[airlock] BLOCKED: '{name}' drifted from the pinned surface after this session "
        "started (a live rug pull). Its mutated definition was withheld and the call was "
        "NOT forwarded upstream. Re-pin the server (airlock lock) once the change is vetted."
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
_MEM_ENVELOPE = "[[AIRLOCK-UNTRUSTED-MEMORY]] "
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


@lru_cache(maxsize=2048)
def _is_exfil_tool(name: str, description: str) -> bool:
    """True if a tool can send data OUTWARD (the exfil leg of the trifecta): a send/post,
    an outbound HTTP call, an upload/publish, a channel message. This is the precision gate
    for egress DLP: a secret only *leaves* the boundary through an exfil-capable tool, so a
    pure local read or a destructive-but-not-outbound tool is never scanned - which keeps
    false positives off the calls that cannot exfiltrate anyway. Reuses the same composition
    classifier the action gate uses, so 'can exfil' means exactly what the rest of the tool
    means by it."""
    surface = ServerSurface(name="_egress", tools=[ToolInfo(name, description or "")])
    return any(sig.leg is TrifectaLeg.EXFIL for sig in classify_server(surface))


def _egress_blocked_response(name: str, detectors: list[str]) -> types.CallToolResult:
    """The result returned when an outbound call is refused under `--on-egress block`
    because its arguments carry a secret / high-confidence PII. The call is NOT forwarded
    upstream, so the sensitive data never leaves the boundary."""
    kinds = ", ".join(detectors)
    meta = {
        ENFORCEMENT_NS: {
            "egress_blocked": True,
            "tool": name,
            "detectors": list(detectors),
            "reason": "sensitive-data-in-arguments",
        }
    }
    msg = (
        f"[airlock] BLOCKED: the outbound call to '{name}' carries sensitive data "
        f"({kinds}) in its arguments. Per the egress policy (--on-egress block) the call "
        "was NOT forwarded upstream, so the secret/PII did not leave the boundary. Re-issue "
        "the call without the sensitive value once it has been vetted."
    )
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=msg, _meta=meta)], isError=True, _meta=meta
    )


def _apply_egress(
    name: str,
    arguments: dict,
    description: str,
    policy: ProxyPolicy,
    ledger: Ledger | None,
    tainted: bool,
) -> tuple[dict, types.CallToolResult | None]:
    """Scan an outbound tool call's arguments for secrets/PII and apply the egress policy.

    Returns (arguments_to_forward, blocked_response). When blocked_response is not None the
    caller must return it WITHOUT forwarding (block mode). Otherwise it forwards the returned
    arguments (unchanged for annotate, a redacted copy for redact).

    Fail-open: the whole scan is wrapped, so a scanner error degrades to forwarding the call
    unchanged - a bug here must never break every outbound call. The one exception is a
    redact that fails on a KNOWN finding: forwarding the raw secret would be worse than
    refusing, so it fails closed to a block. Only EXFIL-classified tools are scanned; in
    annotate mode with no audit log there is nothing to do, so the default hot path is a
    no-op."""
    try:
        mode = policy.egress_mode
        # Default hot path: annotate with no audit log has nothing to record and nothing to
        # withhold, so short-circuit BEFORE the classifier - a call with the default policy
        # pays only this compare (backward-compatible, zero added work).
        if mode == "annotate" and ledger is None:
            return arguments, None
        # DLP is a WHAT-is-in-the-payload control, not a WHETHER-can-exfil one. In the strict
        # containment modes (block/redact) the operator's contract is "no secret leaves",
        # which an imperfect exfil classifier must not silently narrow: a plausibly-named
        # exfil tool (sync-to-remote, ftp_put, a graphql mutation, telemetry send) whose args
        # carry a secret would otherwise skip the scan and forward it (the audit's H2). So
        # block/redact scan EVERY forwarded call. annotate keeps the precision gate (only
        # exfil-classified tools are annotated) so the audit trail is not flooded with
        # findings on non-exfil calls where a secret could never leave the boundary anyway.
        if mode == "annotate" and not _is_exfil_tool(name, description):
            return arguments, None
        findings, complete = dlp.scan_args_bounded(arguments, dlp.detectors_for(policy.egress_optional))
        # An INCOMPLETE scan (outbound args exceed the size / width / depth the scanner will
        # examine) means "no finding" no longer implies "no secret": a hostile client can hide
        # a real secret in the unscanned tail behind a large filler value. In block/redact,
        # fail CLOSED - refuse the call rather than forward a possibly-secret payload.
        if not complete and policy.egress_mode in ("block", "redact"):
            detectors = sorted({f.detector for f in findings}) or ["scan_incomplete"]
            logger.warning(
                "egress DLP: outbound args to %s exceed scan limits; blocking (fail-closed)", name
            )
            if ledger is not None:
                try:
                    ledger.record_egress(
                        name, policy.egress_mode, detectors, len(findings), blocked=True, tainted=tainted
                    )
                except Exception:  # noqa: BLE001 - best-effort audit; never changes the decision
                    logger.debug("egress ledger write failed for %s", name, exc_info=True)
            return arguments, _egress_blocked_response(name, detectors)
        if not findings:
            return arguments, None
        detectors = sorted({f.detector for f in findings})
        logger.warning(
            "egress DLP: %d finding(s) [%s] in call to %s (mode=%s, session_tainted=%s)",
            len(findings), ", ".join(detectors), name, mode, tainted,
        )
        # The ledger write is best-effort and MUST NOT alter the decision once a secret is
        # known: a ledger error here must never fall through to the outer fail-open handler
        # and forward the secret. Wrap it locally so block/redact stay fail-closed.
        if ledger is not None:
            try:
                ledger.record_egress(
                    name, mode, detectors, len(findings),
                    redacted=(mode == "redact"), blocked=(mode == "block"), tainted=tainted,
                )
            except Exception:  # noqa: BLE001 - best-effort audit; never changes the decision
                logger.debug("egress ledger write failed for %s", name, exc_info=True)
        if mode == "block":
            return arguments, _egress_blocked_response(name, detectors)
        if mode == "redact":
            try:
                return dlp.redact_args(arguments, findings), None
            except Exception:  # noqa: BLE001 - a redaction bug on a KNOWN secret fails CLOSED
                logger.warning("egress redaction failed for %s; blocking instead of leaking", name)
                return arguments, _egress_blocked_response(name, detectors)
        return arguments, None  # annotate: forward unchanged, finding recorded
    except Exception:  # noqa: BLE001 - fail-open: a scanner error must not break the call
        logger.debug("egress DLP scan errored for %s; forwarding unchanged", name, exc_info=True)
        return arguments, None


def _gated_response(name: str, mode: str) -> types.CallToolResult:
    """The result returned to the client when a side-effecting call is gated. The call
    is NOT forwarded upstream, so the side effect never happens.

    Returned as a full CallToolResult (isError=True) rather than a bare content list so
    the gating message and the audit `_meta` survive even for a tool that declares an
    outputSchema (the low-level server passes a CallToolResult through unchanged, but
    would replace a bare content list with an output-validation error)."""
    if mode == "block":
        msg = (
            f"[airlock] BLOCKED: '{name}' is a side-effecting tool and untrusted "
            "content is present in this session's context. Per the enforcement contract "
            "(convention section 8), a side-effecting action derived from untrusted "
            "content requires human approval. The call was NOT forwarded upstream."
        )
    else:  # "approve"
        msg = (
            f"[airlock] APPROVAL REQUIRED: '{name}' is a side-effecting tool and "
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

# Bound the TOTAL enforcement work per single upstream response, not just per item (audit H6).
# A hostile server can return ONE result whose `content` holds many ~1 MB blocks; the per-item
# cap bounds each block but not their count, so unbounded blocks x the synchronous per-character
# sanitizer is an event-loop-stall DoS that freezes every other session on the loop. Past this
# cumulative budget the remaining text blocks are passed through framed as UNTRUSTED - which
# still taints the session, so a later side-effecting/exfil call is gated and egress DLP still
# scans it - WITHOUT running the sanitizer, so the sync CPU cost of any one response is bounded
# regardless of block count.
_MAX_ENFORCE_CHARS_PER_RESPONSE = 2_000_000


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


def _enforce_block_bounded(
    block: types.ContentBlock,
    policy: ProxyPolicy,
    inferer: ProvenanceInferer | None,
    budget: list[int],
) -> tuple[types.ContentBlock, _Applied | None]:
    """`_enforce_block`, but once the per-RESPONSE character budget (`budget[0]`) is exhausted
    a text block is passed through framed as untrusted (taint only) instead of paying the
    synchronous sanitizer, so total per-response work is bounded regardless of block count
    (audit H6). Non-text blocks are unaffected (they never ran the sanitizer)."""
    text = _source_text(block)
    if text is not None and budget[0] <= 0:
        return block, _passthrough_applied()
    b, applied = _enforce_block(block, policy, inferer)
    if text is not None:
        budget[0] -= len(text)
    return b, applied


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
    # Bound the TOTAL sanitize work across the system prompt + every message in one
    # createMessage request: a hostile upstream can push many ~1 MB non-ASCII messages, and
    # the per-message cap alone does not bound their COUNT, so it is the same synchronous
    # event-loop-stall DoS the tool-result loops have - here on the reverse channel (audit H6,
    # re-review). Past the budget, remaining messages pass through framed as untrusted (taint
    # only, no per-char sanitizer).
    enforce_budget = [_MAX_ENFORCE_CHARS_PER_RESPONSE]

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
        if enforce_budget[0] <= 0:
            applied, presentation = _passthrough_applied(), sp
        else:
            applied = _Applied(enforce(sp, None))
            enforce_budget[0] -= len(sp)
            presentation = applied.enforcement.presentation
        _record(applied, "systemPrompt", sp)
        out.append(types.SamplingMessage(
            role="user", content=types.TextContent(type="text", text=presentation)))
    for i, msg in enumerate(params.messages):
        text = _bound_text(_collect_text(msg.content))[0]
        if text:
            if enforce_budget[0] <= 0:
                applied, presentation = _passthrough_applied(), text
            else:
                applied = _Applied(enforce(text, None))
                enforce_budget[0] -= len(text)
                presentation = applied.enforcement.presentation
            _record(applied, f"message[{i}]", text)
            # Emit as a single framed text block, replacing any structured/list shape so no
            # sub-block of it reaches the model un-framed.
            out.append(types.SamplingMessage(
                role=msg.role, content=types.TextContent(type="text", text=presentation)))
        else:
            # Pure non-text content (image/audio) carries no framable text: taint and pass
            # it through (an unverifiable, attacker-influenceable channel).
            _record(_passthrough_applied(), f"message[{i}]", None)
            out.append(msg)

    if mode == "block":
        logger.info("sampling refused by policy (block)")
        return types.ErrorData(
            code=types.INVALID_REQUEST,
            message="[airlock] sampling refused (--on-sampling block): the upstream's "
            "createMessage was enforced and recorded but not run against the client's LLM.",
        )
    down = runtime.downstream
    if not _downstream_supports(down, "sampling"):
        return types.ErrorData(
            code=types.INVALID_REQUEST,
            message="[airlock] sampling not available downstream; failing closed.",
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
            code=types.INTERNAL_ERROR, message=f"[airlock] downstream sampling failed: {exc}"
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
    name: str = "airlock-proxy",
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
    # Per-tool memoization of the memory/side-effect classification. Keyed on (name, LIVE
    # description), NOT the name alone: a server can rug-pull a tool's description mid-session
    # (the exact drift the proxy exists to catch), so a name-only cache would serve a stale
    # classification after a benign->side-effecting drift and skip the gate (the audit's H1).
    # Including the current description makes a drifted description a cache miss -> re-classify.
    mem_cache: dict[tuple[str, str], str | None] = {}
    side_effect_cache: dict[tuple[str, str], bool] = {}

    if caps.resources is not None:

        @server.list_resources()
        async def list_resources() -> list[types.Resource]:
            resources = (await session.list_resources()).resources
            resources = await _check_list_drift(
                resources, "resources", True, state, policy, gate, ledger, upstream_label
            )
            # Tool poisoning via any declared resource-listing field (see M1).
            if policy.action_mode in ("approve", "block") and not state.tainted:
                if _description_poisoned([_declared_text(r) for r in resources]):
                    async with _gate_cm(policy, gate):
                        _propagate_taint(state, "poisoned resource description at list time")
                    if ledger is not None:
                        ledger.append(EV_ENFORCE, surface="resource", ident="(list_resources)",
                                      disposition=Trust.UNTRUSTED.value,
                                      detail={"flags": ["poisoned_description"]})
            return resources

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
                        content="[airlock] resource withheld: drifted from the pinned surface",
                        mime_type="text/plain",
                        meta=None,
                    )
                ]
            result = await session.read_resource(uri)
            out: list[ReadResourceContents] = []
            enforce_budget = [_MAX_ENFORCE_CHARS_PER_RESPONSE]  # bound total work (H6)
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
                if enforce_budget[0] <= 0:
                    # Per-response budget exhausted (H6): forward the body framed as untrusted
                    # (taint only), skipping the synchronous sanitizer.
                    applied = _passthrough_applied()
                    presentation = text
                else:
                    applied = _enforce_text(text, getattr(c, "meta", None), policy, inferer)
                    enforce_budget[0] -= len(text)
                    presentation = applied.enforcement.presentation
                _log("resource", str(uri), applied)
                async with _gate_cm(policy, gate):
                    _maybe_taint(state, applied)
                if ledger is not None:
                    ledger.record_enforcement("resource", str(uri), text, applied.enforcement)
                out.append(
                    ReadResourceContents(
                        content=presentation,
                        mime_type=mime,
                        meta=_enforcement_meta(applied),
                    )
                )
            return out

    if caps.prompts is not None:

        @server.list_prompts()
        async def list_prompts() -> list[types.Prompt]:
            prompts = (await session.list_prompts()).prompts
            prompts = await _check_list_drift(
                prompts, "prompts", False, state, policy, gate, ledger, upstream_label
            )
            # Tool poisoning via any declared prompt/argument field (see list_tools / M1).
            if policy.action_mode in ("approve", "block") and not state.tainted:
                if _description_poisoned([_declared_text(p) for p in prompts]):
                    async with _gate_cm(policy, gate):
                        _propagate_taint(state, "poisoned prompt description at list time")
                    if ledger is not None:
                        ledger.append(EV_ENFORCE, surface="prompt", ident="(list_prompts)",
                                      disposition=Trust.UNTRUSTED.value,
                                      detail={"flags": ["poisoned_description"]})
            return prompts

        @server.get_prompt()
        async def get_prompt(name: str, arguments: dict[str, str] | None) -> types.GetPromptResult:
            _capture_downstream(runtime, server)
            if policy.drift_mode == "block" and name in state.drifted["prompts"]:
                # A drifted prompt is withheld under block (rug pull).
                return types.GetPromptResult(
                    description="withheld by airlock (surface drift)",
                    messages=[
                        types.PromptMessage(
                            role="user",
                            content=types.TextContent(
                                type="text",
                                text="[airlock] prompt withheld: drifted from the pinned surface",
                            ),
                        )
                    ],
                )
            result = await session.get_prompt(name, arguments)
            messages: list[types.PromptMessage] = []
            last_meta: dict | None = None
            enforce_budget = [_MAX_ENFORCE_CHARS_PER_RESPONSE]  # bound total work (H6)
            for m in result.messages:
                block, applied = _enforce_block_bounded(m.content, policy, inferer, enforce_budget)
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
            # Arm the action gate against tool poisoning: a statically-poisoned tool
            # description coerces the model into a side-effecting call, but the description is
            # never a tool RESULT so it would not otherwise taint the session (the audit's M1),
            # and an untainted session skips the gate. Only meaningful where taint gates
            # (approve/block) and only until the session is tainted, so this is off the default
            # hot path and bounded to at most one scan per session.
            if policy.action_mode in ("approve", "block") and not state.tainted:
                if _description_poisoned([_declared_text(t) for t in tools]):
                    async with _gate_cm(policy, gate):
                        _propagate_taint(state, "poisoned tool description at list time")
                    if ledger is not None:
                        ledger.append(EV_ENFORCE, surface="tool", ident="(list_tools)",
                                      disposition=Trust.UNTRUSTED.value,
                                      detail={"flags": ["poisoned_description"]})
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
                if _session_tainted(state) or ledger is not None:
                    desc_now = tool_descs.get(name, "")
                    mem_key = (name, desc_now)
                    if mem_key not in mem_cache:
                        mem_cache[mem_key] = classify_memory_tool(name, desc_now)
                    mem = mem_cache[mem_key]
                call_args = arguments
                # A write to MCP-exposed memory while untrusted content is in the session
                # persists possibly-poisoned content. If the write was not gated (annotate
                # mode, or an approved call), envelope the content so a later recall - even
                # in a fresh session - attributes it as untrusted-origin. The write itself is
                # gated under approve/block by _is_side_effecting. The audit record is made
                # whenever a tainted write occurs, even if no content-like field could be
                # enveloped (e.g. an all-structured knowledge-graph write), so the trail never
                # silently omits an untrusted persist.
                if mem == "write" and _session_tainted(state):
                    call_args, wrapped = _wrap_memory_write(arguments)
                    if ledger is not None:
                        ledger.append(EV_ENFORCE, surface="memory", ident=name,
                                      disposition=Trust.UNTRUSTED.value,
                                      detail={"flags": ["untrusted_memory_write"],
                                              "enveloped": bool(wrapped)})
                # Egress DLP: inspect the OUTBOUND arguments for secrets / high-confidence PII
                # before they leave to an exfil-capable tool, then annotate / redact / block
                # per policy. Runs on call_args (after any memory envelope) so a redaction
                # covers the exact bytes that would be sent. In block mode it returns a refusal
                # and the call is never forwarded, so the secret never leaves the boundary.
                call_args, egress_blocked = _apply_egress(
                    name, call_args, tool_descs.get(name, ""), policy, ledger, state.tainted
                )
                if egress_blocked is not None:
                    return egress_blocked
                result = await session.call_tool(name, call_args)
                # A memory read is recorded under surface "memory" so the audit trail
                # distinguishes what flowed out of persistent storage from ordinary tool
                # output; the content is enforced (framed as data) on the same path.
                surface = "memory" if mem in ("read", "write") else "tool"
                blocks: list[types.ContentBlock] = []
                enforce_budget = [_MAX_ENFORCE_CHARS_PER_RESPONSE]  # bound total work (H6)
                for c in result.content:
                    block, applied = _enforce_block_bounded(c, policy, inferer, enforce_budget)
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
                            _propagate_taint(state, "untrusted-origin memory recalled")
                            if ledger is not None:
                                ledger.append(EV_ENFORCE, surface="memory", ident=name,
                                              disposition=Trust.UNTRUSTED.value,
                                              detail={"flags": ["untrusted_origin_memory_recalled"]})
                    blocks.append(block)
                structured = getattr(result, "structuredContent", None)
                if structured is not None:
                    # KNOWN RESIDUAL: structuredContent is relayed VERBATIM, not data-framed.
                    # A tool's outputSchema binds this field's shape, so wrapping its string
                    # leaves in an <<UNTRUSTED DATA>> frame would make the result fail the
                    # client's schema validation. We therefore cannot demarcate an injection a
                    # hostile server hides here. It is NOT unmitigated: the session is tainted
                    # unconditionally below, so any later side-effecting/exfil call is still
                    # gated (convention section 8) and egress DLP still scans it. The residual
                    # is limited to model/output manipulation from undemarcated text - the same
                    # class as any untrusted content the model reads, minus the data frame.
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
                if policy.action_mode in ("approve", "block") and _session_tainted(state):
                    # Fetch the LIVE description at decision time. tool_descs is only refreshed
                    # when the CLIENT re-lists, but a hostile server can rug-pull a tool from
                    # benign into side-effecting WITHOUT the client re-listing (and without
                    # emitting a list_changed), so a cached benign description would be served
                    # stale and the (name, desc) cache key would not change -> the just-drifted
                    # tool would be classified from the stale benign text and forwarded ungated
                    # (the audit's H1, and the residual its first fix missed). Re-list here on
                    # every gated call, exactly as the drift-block path does, so the
                    # classification is always over the description the server is serving NOW.
                    list_ok = True
                    # ALL live descriptions per name, not last-wins: a hostile server can return
                    # the same name TWICE (a side-effecting definition shadowed by a benign
                    # duplicate), and a last-wins classification would read the benign one.
                    live_descs: dict[str, list[str]] = {}
                    try:
                        for t in (await session.list_tools()).tools:
                            d = t.description or ""
                            tool_descs[t.name] = d  # last-wins for other consumers
                            live_descs.setdefault(t.name, []).append(d)
                    except Exception:  # noqa: BLE001 - upstream list failed; see fail-closed below
                        list_ok = False
                    descs = live_descs.get(name)
                    if not list_ok or not descs:
                        # FAIL CLOSED. We could not obtain a LIVE description for THIS tool:
                        # list_tools() raised (H1 round-3), OR it succeeded but OMITTED the tool
                        # being called (round-4). Both let a hostile upstream hide a rug-pulled
                        # tool's current surface while call_tool() still works, which would force
                        # the gate onto a stale benign cached description. Untrusted content is in
                        # the session and the tool name is attacker-controlled, so gate rather than
                        # trust an unverifiable classification. Availability-for-safety trade, only
                        # in the opt-in gating modes.
                        gated = True
                    else:
                        # Gate if ANY live definition of this name is side-effecting, so a benign
                        # duplicate cannot shadow a side-effecting one (H1 round-5, duplicate-name
                        # shadowing). Memoized per (name, desc); a drifted description is a miss.
                        gated = False
                        for d in descs:
                            se_key = (name, d)
                            if se_key not in side_effect_cache:
                                side_effect_cache[se_key] = _is_side_effecting(name, d)
                            if side_effect_cache[se_key]:
                                gated = True
                                break
                if not gated:
                    # Fast path: forward under the lock (keeps decide-then-forward atomic).
                    return await _forward_and_enforce()

            # Gated; the lock is released. Record the decision, then resolve it. A gate driven
            # by a DIFFERENT server's taint (via the shared context) is the cross-server
            # trifecta caught at runtime - attribute it in the log and the audit trail.
            cross = bool(state.shared and any(
                s.get("label") and s.get("label") != upstream_label for s in state.shared.sources()
            ))
            logger.info(
                "action-gated tool %s (mode=%s): untrusted content in context%s",
                name, policy.action_mode, " (CROSS-SERVER)" if cross else "",
            )
            if ledger is not None:
                ledger.record_action(
                    name, policy.action_mode, gated=True, side_effecting=True, cross_server=cross
                )
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


async def run_proxy(
    upstream: str,
    is_http: bool,
    policy: ProxyPolicy,
    stdio_command: str | None = None,
    stdio_args: list[str] | None = None,
) -> None:
    """Connect to the upstream, then serve the enforcing proxy over stdio.

    The upstream session stays open for the life of the proxy. The client speaks to the
    proxy over this process's stdio, so nothing but MCP protocol may touch stdout.

    `stdio_command`/`stdio_args` front an ARBITRARY local command as the upstream (e.g.
    `npx -y @scope/server`, `uvx server`) instead of the default `python <upstream>`, so the
    proxy can wrap the Node/uv/binary servers `airlock init` finds in a client config, not
    just python scripts. `upstream` is then just a label for logs and the audit trail.
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
    # Cross-server taint: share taint with the other proxies fronting this client's servers.
    # In a gating action mode the cross-server signal is load-bearing, so a bus read error or a
    # detected marker deletion must fail CLOSED (treat as tainted) rather than silently drop
    # cross-server protection (audit L3/H8).
    if policy.taint_context:
        runtime.state.shared = SharedTaint(
            policy.taint_context,
            label=upstream,
            ttl=policy.taint_ttl,
            fail_closed=policy.action_mode in ("approve", "block"),
        )

    async def _sampling_cb(context, params):
        return await _handle_sampling(runtime, params)

    async def _elicitation_cb(context, params):
        return await _handle_elicitation(runtime, params)

    async def _message_handler(message):
        await _handle_notification(runtime, message)

    async with connect(
        upstream, is_http,
        stdio_command=stdio_command,
        stdio_args=stdio_args,
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
            from airlock.lockfile import check as _lock_check
            from airlock.lockfile import restrict_resolver as _restrict
            from airlock.scan.drift import capture_surface as _capture_surface

            surface = await _capture_surface(session, getattr(init_result, "instructions", None))
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
            from airlock.scan.drift import capture_surface as _capture_surface

            state.pinned_surface = await _capture_surface(
                session, getattr(init_result, "instructions", None)
            )
        server = make_proxy(session, init_result, runtime)
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())
