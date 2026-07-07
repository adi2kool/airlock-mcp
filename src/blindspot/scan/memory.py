"""Scan MCP-exposed memory for injection.

Persistent memory reached through MCP - a memory server, a knowledge graph, a vector store -
is an injection surface the other scanners miss: content written once is recalled as trusted
in every later session (MINJA-class memory poisoning). Unlike `scan` (which never calls a
tool, only reads declared descriptions), this DELIBERATELY calls the memory READ tools to
retrieve what is already stored and runs the same injection detectors over it, so a poisoned
memory is caught before it is recalled into an agent's context and acted on.

It calls only tools classified as memory reads (`classify_memory_tool`), with a small set of
broad argument shapes, and never calls write/other tools.
"""

from __future__ import annotations

import re

from mcp import ClientSession

from blindspot.compose import _normalize, classify_memory_tool
from blindspot.models import ScanTarget

# Argument shapes tried, in order, to coax a recall/list tool into returning its entries.
# A memory server's read tool is usually a no-arg "list all" or a "query" search; trying a
# few broad shapes keeps the scanner server-agnostic without calling anything but reads.
_QUERY_ATTEMPTS: tuple[dict, ...] = ({}, {"query": ""}, {"query": "*"}, {"limit": 1000})

# A read tool may ALSO mutate (e.g. "recall_and_delete", "get_and_purge", "search then
# archive"). classify_memory_tool checks the write verbs first, but a destructive verb the
# memory-write taxonomy omits (delete/purge/clear/reset/...) would leave the tool classified
# "read" - and scan-memory would then EXECUTE the mutation. Refuse to call any read tool
# whose surface also matches a mutation verb; scanning must never change state.
_MUTATION_VERB = re.compile(
    r"\b(delete|remove|drop|purge|wipe|clear|erase|reset|truncate|forget|expire|evict|prune"
    r"|archive|update|overwrite|replace|set|write|store|save|add|create|insert|upsert"
    r"|increment|decrement|mark|flag|revoke)\b"
)


def _mutates(name: str, description: str) -> bool:
    """True if a tool's surface names a state-changing verb (so it is unsafe to call in a
    read-only scan even if it classified as a memory read)."""
    return bool(_MUTATION_VERB.search(_normalize(f"{name} {description or ''}")))


async def fetch_memory_entries(
    session: ClientSession,
) -> tuple[list[ScanTarget], list[str], list[str]]:
    """Return (targets, memory_read_tool_names, errors).

    Calls each memory-read tool with broad args and turns every returned text entry into a
    ScanTarget the detectors can scan. A tool that returns nothing for every arg shape is
    recorded in errors and skipped, so one uncooperative recall tool does not abort the scan.
    """
    targets: list[ScanTarget] = []
    read_tools: list[str] = []
    errors: list[str] = []
    try:
        tools = (await session.list_tools()).tools
    except Exception as exc:  # noqa: BLE001 - non-fatal, recorded
        return [], [], [f"list_tools failed: {exc}"]

    for t in tools:
        if classify_memory_tool(t.name, t.description or "") != "read":
            continue
        if _mutates(t.name, t.description or ""):
            # A compound read+mutate tool: reading it would change state. Never call it.
            errors.append(f"skipped {t.name!r}: classified as read but also matches a mutation verb")
            continue
        read_tools.append(t.name)
        entries = 0
        for args in _QUERY_ATTEMPTS:
            try:
                result = await session.call_tool(t.name, dict(args))
            except Exception:  # noqa: BLE001 - try the next arg shape
                continue
            texts = [
                getattr(c, "text", "")
                for c in getattr(result, "content", [])
                if getattr(c, "text", None) and getattr(c, "text").strip()
            ]
            if texts:
                for i, text in enumerate(texts):
                    targets.append(ScanTarget("memory", f"{t.name} entry[{i}]", text))
                entries = len(texts)
                break
        if entries == 0:
            errors.append(f"recall {t.name!r} returned no entries")

    if not read_tools:
        errors.append("no memory-read tool found (nothing classified as a memory recall)")
    return targets, read_tools, errors
