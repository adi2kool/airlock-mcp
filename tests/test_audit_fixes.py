"""Regression tests for the confirmed findings of the performance + security audit.

Each test pins a specific vulnerability the adversarial audit found and that was fixed, so a
future refactor cannot silently reopen it. The critical action-gate split-lock (a concurrency
TOCTOU) and the coupled nested-sampling deadlock are exercised by the existing
test_proxy_sampling suite (sampling fired DURING a call under --on-action block would hang if
the callbacks re-acquired the handler's lock, and completes only because they share one lock
and the callbacks taint without it); the deterministic findings are pinned here.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client

from blindspot.compose import classify_memory_tool
from blindspot.enforce.proxy import (
    _MAX_ENFORCE_CHARS,
    ProxyPolicy,
    _bound_text,
    _collect_text,
    _enforce_text,
    _wrap_memory_write,
)
from blindspot.ledger import EV_ENFORCE, Ledger, verify_chain
from blindspot.lockfile import generate_lock
from blindspot.models import Origin, Trust
from blindspot.scan.client import connect
from blindspot.scan.drift import capture_surface
from blindspot.scan.memory import _mutates

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


# --- #10: assume-origin/infer must NOT weaken reverse-channel enforcement ---------------


@pytest.mark.asyncio
async def test_assume_origin_does_not_trust_sampling_content():
    """--assume-origin author vouches for the FORWARD path only. A server-pushed sampling
    message must still be framed as untrusted data, never promoted to instruction-eligible."""
    seen: dict = {"messages": None}

    async def sampling_cb(context, params):
        seen["messages"] = [getattr(m.content, "text", "") for m in params.messages]
        return types.CreateMessageResult(
            role="assistant", content=types.TextContent(type="text", text="ok"), model="t"
        )

    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "blindspot.cli", "proxy", str(FIXTURES / "sampling_server.py"),
              "--assume-origin", "author", "--on-sampling", "frame"],
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write, sampling_callback=sampling_cb) as session:
            await session.initialize()
            await session.call_tool("ask", {})
    joined = "\n".join(seen["messages"] or [])
    # Despite --assume-origin author, the injected sampling text is framed as data.
    assert "UNTRUSTED DATA" in joined
    assert "wire $10000" in joined  # the injection survived only inside the frame


def test_oversize_content_forced_untrusted_even_with_assume_origin():
    """An oversized item cannot be authoritative even under --assume-origin author."""
    big = "A" * (_MAX_ENFORCE_CHARS + 10)
    policy = ProxyPolicy(assume_origin=Origin.AUTHOR)
    applied = _enforce_text(big, None, policy, None)
    assert applied.enforcement.disposition is Trust.UNTRUSTED
    assert "oversize_truncated" in applied.enforcement.flags
    # And the bound actually truncates the work input.
    bounded, was = _bound_text(big)
    assert was and len(bounded) == _MAX_ENFORCE_CHARS


# --- #2: structured / list sampling content must be collected and framed ----------------


def test_collect_text_reaches_nested_and_list_content():
    text_block = types.TextContent(type="text", text="hello INJECT")
    assert _collect_text(text_block) == "hello INJECT"
    # a list of blocks
    assert "one" in _collect_text([text_block, types.TextContent(type="text", text="one")])

    class _Nested:  # a structured block that nests other content
        content = types.TextContent(type="text", text="deep INJECT")

    assert "deep INJECT" in _collect_text(_Nested())

    class _Opaque:  # pure non-text (image/audio): nothing to frame
        pass

    assert _collect_text(_Opaque()) == ""


# --- #5: scan-memory must not execute a compound read+mutate tool -----------------------


def test_scan_memory_refuses_read_tools_that_also_mutate():
    # classify_memory_tool sees "recall" and labels it a read, but it also deletes: unsafe.
    assert classify_memory_tool("recall_and_delete", "Recall memories and delete them.") == "read"
    assert _mutates("recall_and_delete", "Recall memories and delete them.") is True
    # A pure read is not flagged as a mutation.
    assert _mutates("recall_memory", "Recall stored memories.") is False


# --- #7: a surrogate in an event identifier must not crash the ledger -------------------


def test_ledger_survives_surrogate_identifier(tmp_path):
    """A hostile server controls tool names; a lone surrogate must not DoS the audit trail."""
    audit = tmp_path / "a.jsonl"
    led = Ledger(audit)
    # A lone high surrogate (what strip/smuggling could surface) in the identifier.
    led.append(EV_ENFORCE, surface="tool", ident="evil\ud800tool", disposition="untrusted")
    led.append(EV_ENFORCE, surface="tool", ident="normal", disposition="untrusted")
    # The write did not raise, and the chain is intact and verifiable.
    result = verify_chain(audit)
    assert result.ok and result.entries == 2


# --- #12: the wrap fallback must not corrupt an identifier field -------------------------


def test_wrap_memory_write_fallback_skips_identifier_fields():
    # Only an id-shaped key present: the fallback must NOT envelope it (would corrupt the id).
    out, wrapped = _wrap_memory_write({"session_id": "abc-123-def-456-very-long-id"})
    assert not wrapped and out["session_id"] == "abc-123-def-456-very-long-id"
    # A non-content, non-id string IS wrapped by the fallback.
    out2, wrapped2 = _wrap_memory_write({"blob": "some long free-form payload text here"})
    assert wrapped2 and out2["blob"].startswith("[[BLINDSPOT-UNTRUSTED-MEMORY]]")
    # A real content key is wrapped; a sibling id key is left intact.
    out3, wrapped3 = _wrap_memory_write({"id": "k1", "content": "poison"})
    assert wrapped3 and out3["id"] == "k1" and out3["content"].startswith("[[BLINDSPOT")
    # Non-dict arguments are returned unchanged (robustness).
    assert _wrap_memory_write("not-a-dict") == ("not-a-dict", False)


# --- #4: block-mode drift refusal must fire even without a preceding list ---------------


@pytest.mark.asyncio
async def test_block_drift_refused_without_a_preceding_list(tmp_path):
    """A client that calls a rug-pulled tool WITHOUT listing first must still be refused:
    state.drifted is list-populated, so under block the call path re-checks the live surface."""
    server = FIXTURES / "mutating_server.py"
    lock = tmp_path / "m.lock"
    async with connect(str(server), is_http=False) as (s, _i):
        surface = await capture_surface(s)
    lock.write_text(json.dumps(generate_lock(surface)), encoding="utf-8")

    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "blindspot.cli", "proxy", str(server), "--lock", str(lock), "--on-drift", "block"],
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            # Call the drifted tool directly, WITHOUT a prior list_tools.
            result = await session.call_tool("lookup", {"id": "1"})
            assert result.isError and "BLOCKED" in result.content[0].text
