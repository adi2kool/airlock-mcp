"""Drift and rug-pull detection (convention Phase 2 item 5).

Capture a hashed baseline of a server's full surface - its tool, prompt, and
resource definitions - and alert when any definition silently changes between
sessions. A rug pull ships a benign server, waits for adoption, then mutates a tool
description or prompt to something malicious; comparing against a stored baseline
catches that.

The baseline carries an integrity hash over its canonical serialization. Signing
the baseline to a server identity is out of scope for v0 (no key distribution), the
same limit stated in the convention's integrity section.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from mcp import ClientSession

from blindspot.provenance.integrity import hash_body

BASELINE_VERSION = "x-mcp-provenance/v0"


@dataclass(frozen=True)
class SurfaceChange:
    kind: str  # "added" | "removed" | "changed"
    category: str  # "tools" | "prompts" | "resources"
    name: str
    detail: str = ""


def _dump(model) -> dict:
    """The full canonical definition of a capability, minus its own name/uri (which is the
    map key). Pinning the WHOLE definition - title, annotations (destructiveHint /
    readOnlyHint), outputSchema, _meta, arguments - means a rug pull that mutates any of
    those, not just description/inputSchema, changes the surface hash and is caught."""
    try:
        d = model.model_dump(mode="json", exclude_none=True, by_alias=True)
    except Exception:  # noqa: BLE001 - fall back to a minimal, stable view
        d = {"description": getattr(model, "description", "") or ""}
    d.pop("name", None)
    d.pop("uri", None)
    return d


def capture_category(items, *, is_resource: bool = False) -> dict:
    """Build the {name-or-uri: definition} map for one already-fetched capability list.

    The dual of `capture_surface` for a single category: it lets a caller that already
    holds a list result (e.g. the proxy's list handler) hash and diff that category
    without a second round-trip to the upstream. `is_resource` keys by `uri` rather than
    `name`, matching how `capture_surface` stores resources.
    """
    out: dict = {}
    for it in items:
        key = str(it.uri) if is_resource else it.name
        out[key] = _dump(it)
    return out


async def capture_surface(session: ClientSession) -> dict:
    """Capture the server's full tool, prompt, and resource definitions."""
    tools: dict = {}
    try:
        tools = capture_category((await session.list_tools()).tools)
    except Exception:  # noqa: BLE001 - absent surface is a valid (empty) capture
        pass

    prompts: dict = {}
    try:
        prompts = capture_category((await session.list_prompts()).prompts)
    except Exception:  # noqa: BLE001
        pass

    resources: dict = {}
    try:
        resources = capture_category((await session.list_resources()).resources, is_resource=True)
    except Exception:  # noqa: BLE001
        pass

    return {"tools": tools, "prompts": prompts, "resources": resources}


def surface_hash(surface: dict) -> str:
    """Integrity hash over the canonical serialization of the surface."""
    return hash_body(json.dumps(surface, sort_keys=True, ensure_ascii=False))


def make_baseline(surface: dict) -> dict:
    return {"version": BASELINE_VERSION, "surface": surface, "hash": surface_hash(surface)}


def diff_surfaces(old: dict, new: dict) -> list[SurfaceChange]:
    """Return the definition-level changes from old to new.

    Tolerant of a malformed (attacker-crafted) baseline: a category or per-name value
    that is not a dict is coerced rather than crashing the drift detector. An attacker
    can precompute a hash that matches a malformed surface, so this path must not raise.
    """
    changes: list[SurfaceChange] = []
    if not isinstance(old, dict):
        old = {}
    if not isinstance(new, dict):
        new = {}
    for category in ("tools", "prompts", "resources"):
        o = old.get(category, {})
        n = new.get(category, {})
        if not isinstance(o, dict):
            o = {}
        if not isinstance(n, dict):
            n = {}
        for name in sorted(n.keys() - o.keys()):
            changes.append(SurfaceChange("added", category, name))
        for name in sorted(o.keys() - n.keys()):
            changes.append(SurfaceChange("removed", category, name))
        for name in sorted(o.keys() & n.keys()):
            ov, nv = o[name], n[name]
            if ov == nv:
                continue
            if isinstance(ov, dict) and isinstance(nv, dict):
                fields = sorted(k for k in set(ov) | set(nv) if ov.get(k) != nv.get(k))
                detail = "fields: " + ", ".join(fields)
            else:
                detail = "definition changed"
            changes.append(SurfaceChange("changed", category, name, detail))
    return changes
