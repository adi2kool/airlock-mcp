"""Regression tests for the second full audit, Batch 6 (ledger / crypto claims).

M2 (unsigned chain flagged as not-tamper-evident), L1 (report honors the truncation anchor),
L2 (keyid is bound into the hash + signature).
"""

from __future__ import annotations

import json
import os
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from airlock.ledger import Ledger, ledger_tip, verify_chain
from airlock import ledger_report


def _mk(dirpath, n=3, sign_key=None, keyid=None):
    p = os.path.join(dirpath, "l.jsonl")
    led = Ledger(p, sign_key=sign_key, keyid=keyid)
    for i in range(n):
        led.append("enforce", ident=f"x{i}", disposition="untrusted")
    return p


# --- M2: unsigned chain is flagged as NOT tamper-evident -------------------------------


def test_m2_unsigned_flag_set_without_key():
    d = tempfile.mkdtemp()
    p = _mk(d)
    res = verify_chain(p)                 # no key
    assert res.ok and res.unsigned is True


def test_m2_signed_verified_with_key_is_not_unsigned():
    d = tempfile.mkdtemp()
    priv = Ed25519PrivateKey.generate()
    p = _mk(d, sign_key=priv.private_bytes_raw(), keyid="k")
    res = verify_chain(p, public_key=priv.public_key().public_bytes_raw())
    assert res.ok and res.unsigned is False and res.signed == 3


def test_m2_report_human_shows_unsigned_warning():
    d = tempfile.mkdtemp()
    p = _mk(d)
    out = ledger_report.render_human(ledger_report.build_report(p))
    assert "UNSIGNED" in out


def test_m2_interior_rewrite_relinked_passes_unsigned_but_fails_with_key():
    """An attacker rewrites an interior entry and recomputes the keyless chain: verify WITHOUT a
    key still says intact (but flags unsigned); verify WITH the key rejects it."""
    d = tempfile.mkdtemp()
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()
    p = _mk(d, sign_key=priv.private_bytes_raw(), keyid="k")
    # signed + key-verified is intact
    assert verify_chain(p, public_key=pub).ok
    # strip signatures and relink the keyless chain (what a keyless attacker can do)
    from airlock.ledger import LedgerEntry, GENESIS_PREV

    lines = [json.loads(x) for x in open(p) if x.strip()]
    lines[1]["detail"] = {"flags": ["forged"]}
    prev = GENESIS_PREV
    for obj in lines:
        obj["sig"] = None
        obj["keyid"] = None
        e = LedgerEntry(**{k: obj.get(k) for k in (
            "seq", "ts", "event", "surface", "ident", "content_hash",
            "disposition", "detail", "prev_hash", "entry_hash", "sig", "keyid")})
        e.prev_hash = prev
        e.entry_hash = e.compute_hash()
        obj["prev_hash"], obj["entry_hash"] = e.prev_hash, e.entry_hash
        prev = e.entry_hash
    with open(p, "w") as fh:
        fh.write("\n".join(json.dumps(o) for o in lines) + "\n")
    assert verify_chain(p).ok and verify_chain(p).unsigned          # keyless: passes but flagged
    assert not verify_chain(p, public_key=pub).ok                   # with key: rejected


# --- L1: report honors the truncation anchor ------------------------------------------


def test_l1_report_detects_truncation_with_anchor():
    d = tempfile.mkdtemp()
    p = _mk(d, n=3)
    count, tip = ledger_tip(p)
    assert count == 3
    # drop the last entry (truncate the newest)
    lines = [x for x in open(p) if x.strip()]
    with open(p, "w") as fh:
        fh.write("".join(lines[:-1]))
    # without the anchor, a valid prefix still verifies
    assert ledger_report.build_report(p).chain.ok
    # WITH the anchor, report flags truncation (L1)
    rep = ledger_report.build_report(p, expected_entries=count, expected_tip=tip)
    assert not rep.chain.ok and "truncat" in rep.chain.reason.lower()


# --- L2: keyid is bound into the hash + signature -------------------------------------


def test_l2_keyid_relabel_breaks_verification():
    d = tempfile.mkdtemp()
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()
    p = _mk(d, sign_key=priv.private_bytes_raw(), keyid="operator-real")
    assert verify_chain(p, public_key=pub).ok
    # attacker relabels the signer on every entry
    lines = [json.loads(x) for x in open(p) if x.strip()]
    for obj in lines:
        obj["keyid"] = "operator-mallory"
    with open(p, "w") as fh:
        fh.write("\n".join(json.dumps(o) for o in lines) + "\n")
    # keyid is now bound into entry_hash, so the relabel is detected (hash mismatch)
    assert not verify_chain(p, public_key=pub).ok
