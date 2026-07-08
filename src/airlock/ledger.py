"""The flight recorder: a signed, tamper-evident, append-only provenance audit trail.

Every enforcement decision and every action-gate/approval decision the proxy makes is
recorded as one entry in a hash-chained log. Each entry's `entry_hash` covers the previous
entry's hash, so a chain is internally consistent. Entries MAY additionally be Ed25519-signed
by the operator, so a verifier with the operator's public key can confirm the log was produced
by the holder of the key and not forged wholesale.

IMPORTANT - the hash chain alone is KEYLESS, so it detects accidental corruption, NOT an
adversary: anyone who can write the file can edit any interior entry and recompute every
subsequent `entry_hash` to relink the chain, and `verify_chain` (called WITHOUT a public key)
will still report it intact. Tamper-evidence against a file writer requires SIGNING (run the
proxy with `--audit-key`) AND verifying with the corresponding public key (`verify-log --key`),
which makes every entry carry a signature the attacker cannot forge; an unsigned entry in a
keyed verify is then rejected as a signature-strip. `verify_chain` sets `ChainResult.unsigned`
whenever it verified without a key, and `verify-log` / `report` surface it, so an unsigned
"chain intact" is not mistaken for a tamper-proof one.

One property a bare hash chain does NOT give you: detecting truncation of the most RECENT
entries. Any valid prefix of a valid chain is itself a valid chain, so an attacker who can
write the file (but does not hold the signing key) can drop trailing entries - e.g. the
records of their own actions - and the remainder still verifies. This is fundamental to
append-only logs and cannot be closed from the file alone; it needs an out-of-band anchor.
`verify_chain` therefore accepts an optional `expected_entries` / `expected_tip` the operator
persists elsewhere (see `ledger_tip`), and flags a short/diverged log as truncated. Without an
anchor, treat "chain intact" as "no interior entry was altered", not "nothing was removed".

This is the free, local primitive: a JSONL file on disk, no network, no service. The
`Ledger` write path and the `verify_chain` read path are the stable seam; a hosted,
searchable transparency log with compliance-report export is a drop-in replacement for
the sink that consumes these same entries, and is the future paid control plane.

Why this is unique: it fuses the two capabilities only airlock has - runtime content
provenance and content signing - into a verifiable record of what actually flowed and
what was authorized. Competitors block flows; only this attests to them.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from airlock.provenance.integrity import hash_body

logger = logging.getLogger("airlock.ledger")

LEDGER_VERSION = "x-mcp-provenance/ledger-v0"
GENESIS_PREV = "0" * 64  # prev_hash of the first entry

# Event types recorded in the trail.
EV_ENFORCE = "enforce"  # an item was enforced (resource/prompt/tool output)
EV_ACTION = "action_gate"  # a side-effecting tool call was evaluated by the gate
EV_LOCK = "lock_violation"  # the upstream surface drifted from the trust lockfile at startup
EV_DRIFT = "surface_drift"  # the upstream surface drifted mid-session (live rug pull)
EV_SAMPLING = "sampling"  # a server-initiated sampling request was enforced/gated
EV_ELICITATION = "elicitation"  # a server-initiated elicitation request was enforced/gated
EV_EGRESS = "egress_dlp"  # an outbound tool call carried a secret/PII in its arguments
EV_APPROVAL_REQUEST = "approval_request"  # a gated action was sent for human approval
EV_APPROVAL_DECISION = "approval_decision"  # a human/broker approved or denied it


def _now_iso() -> str:
    """Real UTC timestamp for an entry (wall-clock; this is product code)."""
    return datetime.now(timezone.utc).isoformat()


@dataclass
class LedgerEntry:
    """One hash-chained record. `entry_hash` and `sig` are derived, not user-set."""

    seq: int
    ts: str
    event: str
    surface: str = ""  # "resource" | "prompt" | "tool" | "action" | "server"
    ident: str = ""  # the resource uri / prompt name / tool name
    content_hash: str | None = None  # base64 sha-256 of the item body, when applicable
    disposition: str | None = None  # trusted | untrusted | quarantined
    detail: dict = field(default_factory=dict)  # event-specific fields
    prev_hash: str = GENESIS_PREV
    entry_hash: str = ""
    sig: str | None = None  # base64 Ed25519 signature over entry_hash (optional)
    keyid: str | None = None  # signer key id, when signed

    def _chained_payload(self) -> bytes:
        """The exact bytes `entry_hash` covers: the logical fields plus prev_hash AND keyid.

        Deterministic (sorted keys, no whitespace). `entry_hash`/`sig` are excluded (derived
        from this payload). `keyid` IS included: it names which key signed the entry, and if it
        were unbound an attacker with file write could relabel the signer on an otherwise-valid
        signed chain (audit L2). It is set before the hash is computed (see `Ledger.append`)."""
        return json.dumps(
            {
                "v": LEDGER_VERSION,
                "seq": self.seq,
                "ts": self.ts,
                "event": self.event,
                "surface": self.surface,
                "ident": self.ident,
                "content_hash": self.content_hash,
                "disposition": self.disposition,
                "detail": self.detail,
                "prev_hash": self.prev_hash,
                "keyid": self.keyid,
            },
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8", "surrogatepass")

    def compute_hash(self) -> str:
        return hashlib.sha256(self._chained_payload()).hexdigest()


def _read_tail(path: Path) -> tuple[int, str]:
    """Return (next_seq, prev_hash) to continue an existing ledger, or genesis."""
    last_seq, last_hash = -1, GENESIS_PREV
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    last_seq = int(obj["seq"])
                    last_hash = str(obj["entry_hash"])
                except (ValueError, KeyError, TypeError):
                    # A malformed tail line does not stop appending; the chain check on
                    # verify will surface the corruption. Keep the last good values.
                    continue
    except OSError:
        # Missing or unreadable: start a fresh chain (append will surface any write error).
        pass
    return last_seq + 1, last_hash


class Ledger:
    """Append-only writer for the audit trail. Synchronous and non-awaiting, so each
    append is atomic under asyncio (no interleaving mid-append), which keeps the
    seq/prev_hash chain consistent even with concurrent proxy handlers."""

    def __init__(self, path: str | Path, sign_key: bytes | None = None, keyid: str | None = None) -> None:
        self.path = Path(path)
        self._sign_key = sign_key
        self._keyid = keyid
        # Construct the Ed25519 signer ONCE, not per append: rebuilding it from raw bytes on
        # every entry dominated the signing cost, and an audit entry is written per enforced
        # item on the proxy hot path (audit L4). A bad key degrades to unsigned (never crashes
        # the audit trail).
        self._signer: Ed25519PrivateKey | None = None
        if sign_key is not None:
            try:
                self._signer = Ed25519PrivateKey.from_private_bytes(sign_key)
            except Exception:  # noqa: BLE001 - a bad key must not stop the audit trail
                self._signer = None
        self._warned = False  # log a write failure only once
        self._seq, self._prev = _read_tail(self.path)
        # Hold one append handle open for the life of the ledger instead of open/close per
        # entry: on the proxy hot path, an audit entry is written per enforced item, and the
        # per-write open+close is pure syscall overhead. None if the location is unwritable,
        # in which case append() degrades to a best-effort per-open (still never crashes).
        self._fh = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = self.path.open("a", encoding="utf-8")
        except OSError as exc:  # unwritable location -> the audit trail degrades, not crashes
            logger.warning("audit ledger not writable (%s); entries may not persist", exc)

    def append(
        self,
        event: str,
        *,
        surface: str = "",
        ident: str = "",
        content_hash: str | None = None,
        disposition: str | None = None,
        detail: dict | None = None,
    ) -> LedgerEntry:
        entry = LedgerEntry(
            seq=self._seq,
            ts=_now_iso(),
            event=event,
            surface=surface,
            ident=ident,
            content_hash=content_hash,
            disposition=disposition,
            detail=detail or {},
            prev_hash=self._prev,
        )
        # Bind the signer id into the hash (and thus the signature) BEFORE computing the hash,
        # so keyid cannot be relabeled on an otherwise-valid signed chain (audit L2).
        if self._signer is not None:
            entry.keyid = self._keyid
        entry.entry_hash = entry.compute_hash()
        if self._signer is not None:
            try:
                sig = self._signer.sign(entry.entry_hash.encode("ascii"))
                import base64

                entry.sig = base64.b64encode(sig).decode("ascii")
            except Exception:  # noqa: BLE001 - a bad key must not stop the audit trail
                entry.sig = None  # keyid stays bound in the hash; verify-with-key still rejects
        # ensure_ascii=True: a hostile server controls tool/prompt/resource names and content,
        # which can carry a lone UTF-16 surrogate (e.g. a smuggled U+D800-DFFF); serialized
        # with ensure_ascii=False and written to a utf-8 file it raises UnicodeEncodeError,
        # which is NOT an OSError and would crash the enforcing handler (a DoS on every
        # request that carries it). Escaping to \uXXXX keeps the on-disk line pure ASCII and
        # round-trips through verify_chain (which recomputes the hash over the parsed fields).
        try:
            line = json.dumps(asdict(entry), ensure_ascii=True) + "\n"
            if self._fh is not None:
                self._fh.write(line)
                self._fh.flush()  # keep the trail durable + readable mid-session
            else:
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(line)
        except (OSError, ValueError, UnicodeError) as exc:
            # The audit trail is best-effort: a write/serialization failure MUST NOT crash the
            # proxy (enforcement is the primary job). Log once and continue without persisting
            # this entry; seq/prev are not advanced, so whatever does get written stays a
            # consistent chain.
            if not self._warned:
                logger.warning("audit ledger write failed (%s); continuing without the trail", exc)
                self._warned = True
            return entry
        self._seq += 1
        self._prev = entry.entry_hash
        return entry

    # Convenience recorders used by the proxy / lockfile / broker so the call sites stay
    # small and the "how an event maps to an entry" logic lives in one place.

    def record_enforcement(self, surface: str, ident: str, body: str | None, enforcement) -> LedgerEntry:
        """Record one enforcement decision. `enforcement` is a middleware.Enforcement
        (duck-typed to avoid an import cycle): its disposition and flags are captured, and
        the body is hashed for the content_hash (None for non-text/binary content)."""
        content_hash = None
        if body is not None:
            try:
                content_hash = hash_body(body)
            except Exception:  # noqa: BLE001 - a bad body must not stop the audit trail
                content_hash = None
        disp = getattr(getattr(enforcement, "disposition", None), "value", None)
        return self.append(
            EV_ENFORCE,
            surface=surface,
            ident=ident,
            content_hash=content_hash,
            disposition=disp,
            detail={
                "flags": list(getattr(enforcement, "flags", []) or []),
                "instruction_allowed": bool(getattr(enforcement, "instruction_allowed", False)),
            },
        )

    def record_action(
        self, tool: str, mode: str, gated: bool, side_effecting: bool, cross_server: bool = False
    ) -> LedgerEntry:
        """Record an action-gate decision (whether a side-effecting call was gated).
        `cross_server` is True when the gate was driven by taint another server in the shared
        context raised - the lethal trifecta enforced across servers at runtime."""
        detail = {"mode": mode, "gated": bool(gated), "side_effecting": bool(side_effecting)}
        if cross_server:
            detail["cross_server"] = True
        return self.append(EV_ACTION, surface="tool", ident=tool, detail=detail)

    def record_egress(
        self,
        tool: str,
        mode: str,
        detectors: list,
        count: int,
        redacted: bool = False,
        blocked: bool = False,
        tainted: bool = False,
    ) -> LedgerEntry:
        """Record an egress-DLP finding on an outbound tool call. SHAPE-ONLY: the detector
        names and a count, never the secret bytes, so the audit trail attests that a secret
        was seen leaving without persisting it. `tainted` records whether untrusted content
        was already in the session (the confused-deputy exfil signal)."""
        return self.append(
            EV_EGRESS,
            surface="tool",
            ident=tool,
            detail={
                "mode": mode,
                "detectors": list(detectors),
                "count": int(count),
                "redacted": bool(redacted),
                "blocked": bool(blocked),
                "session_tainted": bool(tainted),
            },
        )

    def record_drift(self, category: str, changes: list, mode: str, upstream: str = "") -> LedgerEntry:
        """Record a mid-session surface drift (a live rug pull). `changes` is a list of
        drift.SurfaceChange (duck-typed to avoid an import cycle); each is captured as
        kind/category/name so the trail names exactly what mutated."""
        return self.append(
            EV_DRIFT,
            surface="server",
            ident=upstream,
            detail={
                "category": category,
                "mode": mode,
                "changes": [
                    {
                        "kind": getattr(c, "kind", ""),
                        "category": getattr(c, "category", ""),
                        "name": getattr(c, "name", ""),
                        "detail": getattr(c, "detail", ""),
                    }
                    for c in changes
                ],
            },
        )

    def record_sampling(self, event: str, ident: str, body: str | None, enforcement, mode: str) -> LedgerEntry:
        """Record enforcement of a server-initiated sampling / elicitation request. `event`
        is EV_SAMPLING or EV_ELICITATION; `enforcement` is a middleware.Enforcement (or
        None when the request was refused outright)."""
        content_hash = None
        if body is not None:
            try:
                content_hash = hash_body(body)
            except Exception:  # noqa: BLE001 - a bad body must not stop the audit trail
                content_hash = None
        disp = getattr(getattr(enforcement, "disposition", None), "value", None)
        return self.append(
            event,
            surface="sampling" if event == EV_SAMPLING else "elicitation",
            ident=ident,
            content_hash=content_hash,
            disposition=disp,
            detail={
                "mode": mode,
                "flags": list(getattr(enforcement, "flags", []) or []),
            },
        )

    def record_approval_request(self, request) -> LedgerEntry:
        return self.append(
            EV_APPROVAL_REQUEST,
            surface="action",
            ident=getattr(request, "tool", ""),
            detail={
                "request_id": getattr(request, "request_id", ""),
                "args_summary": getattr(request, "args_summary", ""),
                "taint_reason": getattr(request, "taint_reason", ""),
                "signed": bool(getattr(request, "sig", None)),
            },
        )

    def record_approval_decision(
        self, request_id: str, tool: str, approved: bool, reason: str, latency_ms: int | None = None
    ) -> LedgerEntry:
        return self.append(
            EV_APPROVAL_DECISION,
            surface="action",
            ident=tool,
            detail={"request_id": request_id, "approved": bool(approved), "reason": reason, "latency_ms": latency_ms},
        )


@dataclass
class ChainResult:
    """The result of verifying a ledger file."""

    ok: bool
    entries: int
    signed: int  # how many entries carried a valid signature
    reason: str = ""
    first_broken_seq: int | None = None
    # True when the chain is NOT tamper-evident against a file writer: it was verified without
    # a public key (or carries no signatures), so its links are keyless and fully recomputable
    # by anyone who can write the file. "chain intact" then means "no accidental corruption",
    # NOT "no adversarial edit". Callers surface this so an unsigned trail is not mistaken for a
    # tamper-proof one (audit M2).
    unsigned: bool = False


def ledger_tip(path: str | Path) -> tuple[int, str] | None:
    """The current tip of a ledger as (entry_count, tip_entry_hash), or None if empty/unreadable.

    An operator (or the future control plane) persists this out-of-band so a later
    `verify_chain(..., expected_entries=N, expected_tip=H)` can detect truncation of the most
    recent entries - which a bare hash chain cannot. Reads only the last non-blank line."""
    tip_hash = ""
    count = 0
    try:
        with Path(path).open("r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    h = obj.get("entry_hash")
                except ValueError:
                    return None
                if not isinstance(h, str) or not h:
                    return None
                tip_hash = h
                count += 1
    except OSError:
        return None
    if count == 0:
        return None
    return count, tip_hash


def verify_chain(
    path: str | Path,
    public_key: bytes | None = None,
    *,
    expected_entries: int | None = None,
    expected_tip: str | None = None,
) -> ChainResult:
    """Verify the hash chain (and signatures, if a public key is given).

    Checks that sequence numbers increment from 0, that each entry links to the prior
    one, that each recomputed `entry_hash` matches, and - when `public_key` is provided -
    that every signed entry verifies. Returns a result rather than raising, so a caller
    fails closed on a broken or unreadable log.

    Truncation anchor (optional): a bare chain accepts any valid prefix, so dropping the newest
    entries is otherwise undetectable. When `expected_entries` and/or `expected_tip` (a tip
    previously recorded via `ledger_tip`) are supplied, a log that is SHORTER than expected or
    whose tip hash differs is reported as broken (`reason` starts with 'truncated'/'tip mismatch'),
    even though the surviving prefix hashes and signs correctly."""
    import base64

    p = Path(path)
    prev = GENESIS_PREV
    signed = 0
    pub = None
    if public_key is not None:
        try:
            pub = Ed25519PublicKey.from_public_bytes(public_key)
        except Exception:  # noqa: BLE001
            return ChainResult(ok=False, entries=0, signed=0, reason="invalid public key")

    # Stream line-at-a-time so verification is O(1) memory in the ledger size (a flight
    # recorder can grow large), not O(file size). `i` tracks the non-blank entry index.
    i = -1
    try:
        fh = p.open("r", encoding="utf-8")
    except OSError as exc:
        return ChainResult(ok=False, entries=0, signed=0, reason=f"cannot read log: {exc}")
    with fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                continue
            i += 1
            try:
                obj = json.loads(line)
                entry = LedgerEntry(
                    seq=obj["seq"], ts=obj["ts"], event=obj["event"],
                    surface=obj.get("surface", ""), ident=obj.get("ident", ""),
                    content_hash=obj.get("content_hash"), disposition=obj.get("disposition"),
                    detail=obj.get("detail", {}), prev_hash=obj.get("prev_hash", ""),
                    entry_hash=obj.get("entry_hash", ""), sig=obj.get("sig"),
                    keyid=obj.get("keyid"),
                )
            except (ValueError, KeyError, TypeError) as exc:
                return ChainResult(ok=False, entries=i + 1, signed=signed,
                                   reason=f"malformed entry at line {i + 1}: {exc}", first_broken_seq=i)
            if entry.seq != i:
                return ChainResult(ok=False, entries=i + 1, signed=signed,
                                   reason=f"sequence gap: expected {i}, got {entry.seq}", first_broken_seq=i)
            if entry.prev_hash != prev:
                return ChainResult(ok=False, entries=i + 1, signed=signed,
                                   reason=f"broken chain at seq {entry.seq}", first_broken_seq=entry.seq)
            if entry.compute_hash() != entry.entry_hash:
                return ChainResult(ok=False, entries=i + 1, signed=signed,
                                   reason=f"entry hash mismatch at seq {entry.seq} (tampered)", first_broken_seq=entry.seq)
            if pub is not None:
                # The hash chain alone is keyless, so an attacker who edits an entry can
                # recompute its entry_hash and relink the chain. The signature is the only
                # thing binding the log to the operator's key. So when a key is supplied,
                # EVERY entry MUST carry a valid signature - an unsigned entry is a
                # signature-strip downgrade (rewrite history, drop the signatures) and MUST
                # fail, not be silently skipped.
                if not entry.sig:
                    return ChainResult(ok=False, entries=i + 1, signed=signed,
                                       reason=f"unsigned entry at seq {entry.seq} (signature strip)",
                                       first_broken_seq=entry.seq)
                try:
                    pub.verify(base64.b64decode(entry.sig, validate=True), entry.entry_hash.encode("ascii"))
                    signed += 1
                except (InvalidSignature, ValueError, TypeError):
                    return ChainResult(ok=False, entries=i + 1, signed=signed,
                                       reason=f"signature verification failed at seq {entry.seq}", first_broken_seq=entry.seq)
            prev = entry.entry_hash

    count = i + 1
    # Truncation anchor: the interior chain is intact, but the operator may have pinned how long
    # the log should be / what its tip was. A shorter log or a different tip means recent entries
    # were removed (an attacker who can write the file but cannot forge the signing key). `prev`
    # holds the last entry's hash after the loop (GENESIS_PREV if empty).
    if expected_entries is not None and count < expected_entries:
        return ChainResult(ok=False, entries=count, signed=signed,
                           reason=f"truncated: expected {expected_entries} entries, found {count}",
                           first_broken_seq=count)
    if expected_tip is not None and prev != expected_tip:
        return ChainResult(ok=False, entries=count, signed=signed,
                           reason="tip mismatch (log truncated or diverged from the anchored tip)",
                           first_broken_seq=max(count - 1, 0))

    return ChainResult(ok=True, entries=count, signed=signed,
                       reason="chain intact" if i >= 0 else "empty ledger",
                       unsigned=(public_key is None and count > 0))
