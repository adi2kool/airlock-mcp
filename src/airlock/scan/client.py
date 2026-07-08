"""The scanner client: connect to a target MCP server over stdio or streamable
HTTP, enumerate and fetch tool descriptions, prompts, and resources, and return the
fetched text for the detectors to scan.

Phase 1. Reuses the connection pattern proven by fixtures/scratch_client.py and
adds a streamable-HTTP branch. Tool descriptions and parameter descriptions are
scanned as the tool-poisoning vector (they are declared, model-visible text); tool
names are also collected so the shadowing detector can recognize redirect targets.
Tools are never CALLED, only their static declared schema is read.
"""

from __future__ import annotations

import sys
from contextlib import asynccontextmanager

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client

from airlock.models import ScanTarget


@asynccontextmanager
async def connect(
    target: str,
    is_http: bool,
    *,
    http_client_factory=None,
    stdio_command: str | None = None,
    stdio_args: list[str] | None = None,
    sampling_callback=None,
    elicitation_callback=None,
    message_handler=None,
):
    """Yield (session, init_result) for a stdio script or an HTTP URL.

    init_result carries the server's declared capabilities, used by the
    least-privilege auditor.

    `http_client_factory` (HTTP only) overrides how the underlying httpx client is
    built. The prevalence study passes a factory that disables redirect-following so a
    loopback server cannot bounce the connection to a remote host. Default is None,
    which preserves the SDK's client (redirects followed) for the scanner's own use.

    `stdio_command`/`stdio_args` (stdio only) launch an arbitrary local command (for
    example `npx -y @scope/server` or `uvx server`) instead of the default
    `python <target>`. Used by the prevalence study to run real servers distributed as
    console scripts; `target` is then just a label.

    `sampling_callback`/`elicitation_callback`/`message_handler` are the client-session
    callbacks the enforcing proxy installs so it can enforce the server-initiated
    sampling and elicitation channels and re-check the surface on `list_changed`
    notifications. Passing a sampling/elicitation callback also makes this session
    advertise that capability to the upstream, so the upstream will route those requests
    here. Default None (the scanner does not offer these capabilities).
    """
    cb = {
        "sampling_callback": sampling_callback,
        "elicitation_callback": elicitation_callback,
        "message_handler": message_handler,
    }
    if is_http:
        extra = {} if http_client_factory is None else {"httpx_client_factory": http_client_factory}
        async with streamablehttp_client(target, **extra) as (read, write, _get_session_id):
            async with ClientSession(read, write, **cb) as session:
                init_result = await session.initialize()
                yield session, init_result
    else:
        if stdio_command is not None:
            params = StdioServerParameters(command=stdio_command, args=list(stdio_args or []))
        else:
            params = StdioServerParameters(command=sys.executable, args=[target])
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write, **cb) as session:
                init_result = await session.initialize()
                yield session, init_result


def _param_descriptions(schema) -> list[tuple[str, str]]:
    """Extract (label, text) description-like strings from a tool inputSchema.

    Tool parameter text is declared, model-visible, and a poisoning vector. This follows
    local `$ref` into `$defs` (nested Pydantic models are the idiomatic FastMCP shape) and
    descends into object properties and array items, collecting `description`/`title` plus
    model-visible `enum`/`default`/`const` string values. Bounded depth and a visited-ref
    set guard against cycles and schema-bomb DoS; a malformed/absent schema yields nothing
    (a hostile server must not make enumeration crash)."""
    if not isinstance(schema, dict):
        return []
    defs = schema.get("$defs")
    defs = defs if isinstance(defs, dict) else {}
    out: list[tuple[str, str]] = []
    seen_refs: set[str] = set()

    def visit(node, label: str, depth: int) -> None:
        if depth > 8 or not isinstance(node, dict):
            return
        ref = node.get("$ref")
        if isinstance(ref, str):
            if ref in seen_refs:
                return
            seen_refs.add(ref)
            target = defs.get(ref.rsplit("/", 1)[-1])
            if isinstance(target, dict):
                visit(target, label, depth + 1)
            return
        for key in ("description", "title"):
            v = node.get(key)
            if isinstance(v, str) and v:
                out.append((label if key == "description" else f"{label}.{key}", v))
        enum = node.get("enum")
        if isinstance(enum, list):
            for e in enum:
                if isinstance(e, str) and e:
                    out.append((f"{label}.enum", e))
        for key in ("default", "const"):
            v = node.get(key)
            if isinstance(v, str) and v:
                out.append((f"{label}.{key}", v))
        props = node.get("properties")
        if isinstance(props, dict):
            for pname, pdef in props.items():
                visit(pdef, f"{label}.{pname}" if label else str(pname), depth + 1)
        items = node.get("items")
        if isinstance(items, dict):
            visit(items, f"{label}[]", depth + 1)
        elif isinstance(items, list):
            for it in items:
                visit(it, f"{label}[]", depth + 1)

    props = schema.get("properties")
    if isinstance(props, dict):
        for pname, pdef in props.items():
            visit(pdef, str(pname), 1)
    return out


async def fetch_targets(
    session: ClientSession,
    init_result=None,
) -> tuple[list[ScanTarget], list[str], list[str]]:
    """Enumerate and fetch tools (descriptions), prompts, and resources.

    Returns (targets, tool_names, errors). A failure on any single item is recorded
    in errors and skipped so it does not abort the whole scan. Tool DESCRIPTIONS are
    scanned (the tool-poisoning vector); tools are never CALLED.

    Every model-visible declared string is scanned: the server-level `instructions`
    (InitializeResult.instructions, injected into the model like a system prompt), tool and
    parameter descriptions, prompt descriptions AND prompt-argument descriptions, and the
    resource LISTING metadata (name/title/description) in addition to resource content - all
    fields a hostile server controls and the model reads, so a gap in any is a false negative.
    """
    targets: list[ScanTarget] = []
    tool_names: list[str] = []
    errors: list[str] = []

    # Server-level instructions: the single most model-visible tool-poisoning surface. Scanned
    # on a non-"tool" surface so it is not softened - an injection here is not documentation.
    inst = getattr(init_result, "instructions", None) if init_result is not None else None
    if isinstance(inst, str) and inst.strip():
        sname = getattr(getattr(init_result, "serverInfo", None), "name", "") or "server"
        targets.append(ScanTarget("server", f"{sname} (instructions)", inst))

    try:
        tools = await session.list_tools()
        tool_names = [t.name for t in tools.tools]
        # Tool descriptions and parameter descriptions are model-visible declared text
        # and the primary "tool poisoning" injection vector, so scan them like any other
        # surface. This reads only the static tools/list schema; no tool is ever called.
        for t in tools.tools:
            desc = getattr(t, "description", None)
            if isinstance(desc, str) and desc:
                targets.append(ScanTarget("tool", f"{t.name} (description)", desc))
            for label, ptext in _param_descriptions(getattr(t, "inputSchema", None)):
                targets.append(ScanTarget("tool", f"{t.name}.{label} (param)", ptext))
    except Exception as exc:  # noqa: BLE001 - non-fatal, recorded
        errors.append(f"list_tools failed: {exc}")

    try:
        prompts = await session.list_prompts()
    except Exception as exc:  # noqa: BLE001
        errors.append(f"list_prompts failed: {exc}")
        prompts = None

    if prompts is not None:
        for prompt in prompts.prompts:
            if prompt.description:
                targets.append(
                    ScanTarget("prompt", f"{prompt.name} (description)", prompt.description)
                )
            # Prompt-argument descriptions are model-visible when the client elicits values;
            # an injection here evades a scan that only reads the prompt body (audit M5).
            for a in prompt.arguments or []:
                adesc = getattr(a, "description", None)
                if isinstance(adesc, str) and adesc.strip():
                    targets.append(
                        ScanTarget("prompt", f"{prompt.name}.{a.name} (arg)", adesc)
                    )
            try:
                arguments = {a.name: "example" for a in (prompt.arguments or [])}
                result = await session.get_prompt(prompt.name, arguments=arguments)
                text = "\n".join(
                    getattr(m.content, "text", "") for m in result.messages
                )
                # Provenance may ride on the result or on a message's content.
                meta = getattr(result, "meta", None)
                if meta is None and result.messages:
                    meta = getattr(result.messages[0].content, "meta", None)
                targets.append(ScanTarget("prompt", prompt.name, text, meta=meta))
            except Exception as exc:  # noqa: BLE001
                errors.append(f"get_prompt {prompt.name!r} failed: {exc}")

    try:
        resources = await session.list_resources()
    except Exception as exc:  # noqa: BLE001
        errors.append(f"list_resources failed: {exc}")
        resources = None

    if resources is not None:
        for resource in resources.resources:
            # Resource LISTING metadata (name/title/description) is shown to the model when it
            # picks a resource to read, so an injection there is acted on WITHOUT the resource
            # ever being fetched. Scan it in addition to the content (audit M6).
            listing = " ".join(
                s for s in (
                    getattr(resource, "name", "") or "",
                    getattr(resource, "title", "") or "",
                    getattr(resource, "description", "") or "",
                ) if s
            ).strip()
            if listing:
                targets.append(ScanTarget("resource", f"{resource.uri} (listing)", listing))
            try:
                # Read using the uri object from list_resources to avoid AnyUrl
                # normalization mismatch.
                result = await session.read_resource(resource.uri)
                text = "".join(getattr(c, "text", "") for c in result.contents)
                meta = None
                if result.contents:
                    meta = getattr(result.contents[0], "meta", None)
                targets.append(ScanTarget("resource", str(resource.uri), text, meta=meta))
            except Exception as exc:  # noqa: BLE001
                errors.append(f"read_resource {resource.uri!r} failed: {exc}")

    # Resource TEMPLATES (resources/templates/list) carry the same model-visible listing
    # metadata as concrete resources, so an injection in a template description is the same
    # attack - and it is missed if only list_resources is scanned (audit M6, re-review). They
    # are parameterized (uriTemplate), so there is no static content to read; scan the metadata.
    try:
        templates = await session.list_resource_templates()
    except Exception:  # noqa: BLE001 - not all servers support templates; absence is not an error
        templates = None
    if templates is not None:
        for tmpl in getattr(templates, "resourceTemplates", []) or []:
            listing = " ".join(
                s for s in (
                    getattr(tmpl, "name", "") or "",
                    getattr(tmpl, "title", "") or "",
                    getattr(tmpl, "description", "") or "",
                ) if s
            ).strip()
            if listing:
                uri = getattr(tmpl, "uriTemplate", "") or getattr(tmpl, "name", "") or "template"
                targets.append(ScanTarget("resource", f"{uri} (template)", listing))

    return targets, tool_names, errors
