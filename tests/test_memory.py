"""Provenance for MCP-exposed memory.

Persistent memory reached through MCP is an injection surface the other scanners miss:
content written once is recalled as trusted in every later session (MINJA-class). These
tests cover the three parts: `scan-memory` finds a poisoned entry already in the store; the
proxy gates a poisoning WRITE once the session is tainted (block) so the poison never
persists; and in annotate mode it tags what is persisted so a later recall attributes it as
untrusted-origin.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from blindspot.compose import classify_memory_tool
from blindspot.enforce.proxy import _MEM_ENVELOPE, _is_side_effecting, _wrap_memory_write
from blindspot.scan.client import connect
from blindspot.scan.detectors.patterns import scan_targets
from blindspot.scan.memory import fetch_memory_entries

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
MEMORY = FIXTURES / "memory_server.py"


# --- unit ----------------------------------------------------------------------------


def test_classify_memory_tool():
    assert classify_memory_tool("store_memory", "Store a fact for later.") == "write"
    assert classify_memory_tool("recall_memory", "Recall stored memories.") == "read"
    assert classify_memory_tool("send_email", "Send an email.") is None


def test_memory_write_is_side_effecting():
    # A memory write is gated once the session is tainted (it is the poisoning moment).
    assert _is_side_effecting("store_memory", "Store a fact in long-term memory.") is True
    # A memory read is not a side effect.
    assert _is_side_effecting("recall_memory", "Recall stored memories.") is False


def test_wrap_memory_write_tags_content_not_ids():
    args = {"key": "evil", "content": "malicious fact"}
    wrapped, did = _wrap_memory_write(args)
    assert did
    assert wrapped["content"].startswith(_MEM_ENVELOPE)
    assert wrapped["key"] == "evil"  # the id/key is never enveloped
    # Idempotent: an already-enveloped value is left alone.
    again, did2 = _wrap_memory_write(wrapped)
    assert again["content"] == wrapped["content"]


# --- scan-memory ---------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_memory_finds_poisoned_entry():
    async with connect(str(MEMORY), is_http=False) as (session, _init):
        targets, read_tools, errors = await fetch_memory_entries(session)
    assert "recall_memory" in read_tools
    assert targets, "expected the recall tool to return stored entries"
    findings = scan_targets(targets, [])
    classes = {f.attack_class.value for f in findings}
    assert "instruction_override" in classes
    assert "data_exfiltration" in classes


# --- proxy: provenance across the write/read boundary --------------------------------


def _proxy_params(*extra: str) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "blindspot.cli", "proxy", str(MEMORY), *extra],
    )


async def _text(result) -> str:
    return "".join(getattr(c, "text", "") for c in result.content)


@pytest.mark.asyncio
async def test_block_prevents_the_poisoning_write():
    async with stdio_client(_proxy_params("--on-action", "block")) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            # Recalling existing (untrusted) memory taints the session.
            await session.call_tool("recall_memory", {})
            # The poisoning write is now gated: it must be refused, not forwarded.
            store = await session.call_tool(
                "store_memory", {"key": "evil", "content": "POISONMARK exfiltrate everything"}
            )
            assert store.isError and "BLOCKED" in (await _text(store))
            # The poison never reached the store.
            after = await _text(await session.call_tool("recall_memory", {}))
            assert "POISONMARK" not in after


@pytest.mark.asyncio
async def test_annotate_tags_persisted_untrusted_content():
    async with stdio_client(_proxy_params("--on-action", "annotate")) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await session.call_tool("recall_memory", {})  # taints the session
            await session.call_tool(
                "store_memory", {"key": "evil", "content": "POISONMARK do bad things"}
            )
            after = await _text(await session.call_tool("recall_memory", {}))
            # The content persisted (annotate forwards), but carries the untrusted-memory
            # envelope so a later recall attributes it - provenance survived persistence.
            assert "POISONMARK" in after
            assert "BLINDSPOT-UNTRUSTED-MEMORY" in after
