"""Regression tests for the second full audit, Batch 4 (perf / DoS).

H6 (per-response enforcement budget bounds total work), M3 (report streams a large ledger
with bounded memory + timeline), L4 (Ed25519 signer built once, signing still correct).
"""

from __future__ import annotations

import os
import tempfile

from mcp import types

from airlock.enforce import proxy
from airlock.ledger import Ledger, verify_chain
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


# --- H6: per-response enforcement budget --------------------------------------------


def _text_block(s: str) -> types.TextContent:
    return types.TextContent(type="text", text=s)


def test_h6_budget_exhausted_passes_through_and_taints():
    policy = proxy.ProxyPolicy()
    budget = [0]  # already exhausted
    block, applied = proxy._enforce_block_bounded(_text_block("héllo​ world"), policy, None, budget)
    # passthrough: block is returned unchanged (NOT sanitized) but still tainting (untrusted)
    assert applied is not None
    from airlock.models import Trust

    assert applied.enforcement.disposition is Trust.UNTRUSTED
    assert getattr(block, "text", None) == "héllo​ world"  # zero-width NOT stripped (skipped)


def test_h6_within_budget_enforces_and_decrements():
    policy = proxy.ProxyPolicy()
    budget = [proxy._MAX_ENFORCE_CHARS_PER_RESPONSE]
    text = "héllo​ world"  # contains a zero-width space to strip
    block, applied = proxy._enforce_block_bounded(_text_block(text), policy, None, budget)
    assert applied is not None
    assert budget[0] == proxy._MAX_ENFORCE_CHARS_PER_RESPONSE - len(text)
    # enforced path sanitizes: the zero-width space is gone from the framed presentation
    assert "​" not in getattr(block, "text", "")


def test_h6_many_blocks_bounded_total_work():
    """The cumulative budget caps total sanitized bytes across all blocks in one response,
    so N blocks cannot each pay the full per-item cost (the DoS)."""
    policy = proxy.ProxyPolicy()
    budget = [proxy._MAX_ENFORCE_CHARS_PER_RESPONSE]
    big = "é" * 1_000_000  # 1 MB non-ASCII per block
    enforced = 0
    for _ in range(10):
        _b, applied = proxy._enforce_block_bounded(_text_block(big), policy, None, budget)
        if budget[0] > 0 or applied.enforcement.disposition.value != "untrusted":
            enforced += 1
    # at most ceil(2MB / 1MB) blocks are fully enforced; the rest passthrough
    assert budget[0] <= 0
    assert enforced <= 3


# --- M3: streaming report -------------------------------------------------------------


def test_m3_report_streams_large_ledger_bounded_timeline():
    from airlock import ledger_report

    d = tempfile.mkdtemp()
    p = os.path.join(d, "big.jsonl")
    led = Ledger(p)
    n = ledger_report._MAX_NOTABLE_ROWS + 500
    for i in range(n):
        led.append("action_gate", surface="tool", ident=f"t{i}",
                    detail={"mode": "block", "gated": True, "side_effecting": True})
    rep = ledger_report.build_report(p)
    assert rep.summary.entries == n                       # aggregates are exact over the whole file
    assert rep.summary.actions_gated == n
    assert len(rep.notable) == ledger_report._MAX_NOTABLE_ROWS  # timeline is bounded
    assert rep.notable_total == n and rep.notable_truncated
    assert rep.entries == []                              # full list is NOT retained
    # renders without materializing everything
    out = ledger_report.render_human(rep)
    assert "showing the most recent" in out


# --- L4: signer built once, signatures still valid ------------------------------------


def test_l4_signer_cached_and_signatures_verify():
    priv = Ed25519PrivateKey.generate()
    key = priv.private_bytes_raw()
    pub = priv.public_key().public_bytes_raw()
    d = tempfile.mkdtemp()
    p = os.path.join(d, "l.jsonl")
    led = Ledger(p, sign_key=key, keyid="k1")
    assert led._signer is not None  # built once in __init__, not per append
    for i in range(5):
        led.append("enforce", ident=f"x{i}", disposition="untrusted")
    res = verify_chain(p, public_key=pub)
    assert res.ok and res.signed == 5  # every entry validly signed with the cached signer


def test_l4_bad_key_degrades_to_unsigned():
    d = tempfile.mkdtemp()
    led = Ledger(os.path.join(d, "l.jsonl"), sign_key=b"too-short", keyid="k")
    assert led._signer is None
    e = led.append("enforce", ident="x")
    assert e.sig is None  # never crashes; just unsigned
