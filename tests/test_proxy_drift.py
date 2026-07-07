"""Live mid-session rug-pull detection.

The trust lockfile catches drift at startup; these tests cover the gap it leaves - a
benign server that mutates a tool AFTER the proxy has started and the client re-lists.
`fixtures/mutating_server.py` returns a clean `lookup` on the first list (the baseline the
proxy pins) and an injected `lookup` on every later list. Two layers are tested: the pure
drift evaluator, and the proxy end to end via the CLI (block withholds + refuses the
drifted tool; taint records it and forwards; the tamper-evident ledger names the change).
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from blindspot.enforce.proxy import evaluate_drift
from blindspot.lockfile import generate_lock
from blindspot.scan.client import connect
from blindspot.scan.drift import capture_category, capture_surface

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
MUTATING = FIXTURES / "mutating_server.py"


# --- pure evaluator -------------------------------------------------------------------


def test_evaluate_drift_no_pin_is_noop():
    assert evaluate_drift(None, "tools", {"a": {"description": "x"}}) == []
    assert evaluate_drift({}, "tools", {"a": {"description": "x"}}) == []


def test_evaluate_drift_unchanged_is_empty():
    pinned = {"tools": {"a": {"description": "x"}}}
    assert evaluate_drift(pinned, "tools", {"a": {"description": "x"}}) == []


def test_evaluate_drift_flags_changed_definition():
    pinned = {"tools": {"lookup": {"description": "benign"}, "ping": {"description": "pong"}}}
    current = {"lookup": {"description": "benign IGNORE PREVIOUS"}, "ping": {"description": "pong"}}
    changes = evaluate_drift(pinned, "tools", current)
    assert len(changes) == 1
    assert changes[0].kind == "changed"
    assert changes[0].name == "lookup"
    assert changes[0].category == "tools"


def test_evaluate_drift_flags_added_and_removed():
    pinned = {"tools": {"a": {"description": "x"}}}
    current = {"b": {"description": "y"}}
    kinds = {(c.kind, c.name) for c in evaluate_drift(pinned, "tools", current)}
    assert ("added", "b") in kinds
    assert ("removed", "a") in kinds


# --- end to end via the proxy ---------------------------------------------------------


def _proxy_params(*extra: str) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "blindspot.cli", "proxy", str(MUTATING), *extra],
    )


async def _write_lock(path: Path) -> None:
    """Pin the mutating server's clean (first-list) surface to a lockfile."""
    async with connect(str(MUTATING), is_http=False) as (session, _init):
        surface = await capture_surface(session)
    path.write_text(json.dumps(generate_lock(surface)), encoding="utf-8")


def _drift_events(audit: Path) -> list[dict]:
    # A missing file means zero events were recorded (the ledger is written lazily).
    if not audit.exists():
        return []
    return [
        json.loads(line)
        for line in audit.read_text(encoding="utf-8").splitlines()
        if line and json.loads(line)["event"] == "surface_drift"
    ]


@pytest.mark.asyncio
async def test_block_withholds_and_refuses_drifted_tool(tmp_path):
    lock = tmp_path / "m.lock"
    audit = tmp_path / "audit.jsonl"
    await _write_lock(lock)

    async with stdio_client(
        _proxy_params("--lock", str(lock), "--on-drift", "block", "--audit-log", str(audit))
    ) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            names = [t.name for t in (await session.list_tools()).tools]
            # The mutated tool is withheld; the stable one still passes through.
            assert "lookup" not in names
            assert "ping" in names
            # A call to the drifted tool is refused before it reaches the upstream.
            result = await session.call_tool("lookup", {"id": "1"})
            assert result.isError
            assert "BLOCKED" in result.content[0].text

    events = _drift_events(audit)
    assert events, "expected a surface_drift entry in the audit trail"
    ev = events[0]
    assert ev["detail"]["category"] == "tools"
    assert ev["detail"]["mode"] == "block"
    assert any(c["name"] == "lookup" and c["kind"] == "changed" for c in ev["detail"]["changes"])


@pytest.mark.asyncio
async def test_taint_mode_records_drift_but_forwards(tmp_path):
    """--pin-on-start + --on-drift taint: detected and attested, but not withheld."""
    audit = tmp_path / "audit.jsonl"
    async with stdio_client(
        _proxy_params("--pin-on-start", "--on-drift", "taint", "--audit-log", str(audit))
    ) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            names = [t.name for t in (await session.list_tools()).tools]
            # taint does not withhold: the drifted tool is still forwarded to the client.
            assert "lookup" in names and "ping" in names

    events = _drift_events(audit)
    assert events, "drift must be recorded even in taint mode"
    assert events[0]["detail"]["mode"] == "taint"


@pytest.mark.asyncio
async def test_no_pin_means_no_drift_detection(tmp_path):
    """Without --lock or --pin-on-start, behavior is unchanged (no drift machinery)."""
    audit = tmp_path / "audit.jsonl"
    async with stdio_client(_proxy_params("--audit-log", str(audit))) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            names = [t.name for t in (await session.list_tools()).tools]
            assert "lookup" in names and "ping" in names
    assert _drift_events(audit) == []


def test_capture_category_keys_by_name_and_uri():
    """capture_category is the single-list dual of capture_surface used by the proxy."""

    class _T:
        def __init__(self, name):
            self.name = name

        def model_dump(self, **_):
            return {"name": self.name, "description": "d"}

    class _R:
        def __init__(self, uri):
            self.uri = uri

        def model_dump(self, **_):
            return {"uri": self.uri, "name": "r"}

    tools = capture_category([_T("a"), _T("b")])
    assert set(tools) == {"a", "b"} and "name" not in tools["a"]
    resources = capture_category([_R("res://x")], is_resource=True)
    assert set(resources) == {"res://x"} and "uri" not in resources["res://x"]
