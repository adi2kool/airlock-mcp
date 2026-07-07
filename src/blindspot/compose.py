"""Cross-server composition analysis (Phase 3).

An agent rarely connects to one server. It connects to several at once, and the
danger is emergent: each server can be individually clean while the combination
enables the lethal trifecta - access to private data, exposure to untrusted content,
and a path to exfiltrate - so an injection carried by one server's untrusted content
can read another server's private data and send it out through a third. No single
server is malicious; the composition is.

This module classifies each connected server's surface (its tools and resources)
into the three trifecta legs using a deterministic local signal taxonomy, then flags
when the union across the connected set covers all three. It reuses the Phase 2
provenance signal where present: a server observed emitting external/untrusted-tagged
content is, by construction, an untrusted-content source.

$0 and local. The classifier is pure over a ServerSurface, so it is easy to test; a
live session is turned into a surface by `capture_surface`. This analysis is local
and synthetic. It is not the real-server prevalence study, which stays gated behind
responsible disclosure.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum

from blindspot.models import Severity
from blindspot.sanitize import strip_invisible


class TrifectaLeg(str, Enum):
    """The three capabilities whose co-presence is the lethal trifecta."""

    PRIVATE_DATA = "private_data"  # can read sensitive or private data
    UNTRUSTED_CONTENT = "untrusted_content"  # can pull in attacker-influenced content
    EXFIL = "exfil"  # can send data outward


_ALL_LEGS = (TrifectaLeg.PRIVATE_DATA, TrifectaLeg.UNTRUSTED_CONTENT, TrifectaLeg.EXFIL)


@dataclass(frozen=True)
class ToolInfo:
    name: str
    description: str = ""


@dataclass(frozen=True)
class ResourceInfo:
    uri: str
    name: str = ""
    description: str = ""


@dataclass
class ServerSurface:
    """One server's capability surface, as seen by a connecting client."""

    name: str
    tools: list[ToolInfo] = field(default_factory=list)
    resources: list[ResourceInfo] = field(default_factory=list)
    # True when the server was observed emitting external/untrusted provenance _meta
    # (a Phase 2 signal): definitionally an untrusted-content source.
    untrusted_emitter: bool = False


@dataclass(frozen=True)
class LegSignal:
    """Evidence that one capability supplies one trifecta leg."""

    server: str
    leg: TrifectaLeg
    kind: str  # "tool" | "resource" | "provenance"
    name: str  # the tool name or resource identifier
    evidence: str  # what matched


# Signal taxonomy. Each entry: (primary leg, extra legs, compiled regex, label). The
# regex runs over a lowercased "name description" string. `extra` lets one match
# assign several legs: an arbitrary-URL web tool both ingests untrusted content and,
# because the URL is attacker-influenceable, is an exfiltration channel (data rides
# out in the request), so it counts for both.
_Signal = tuple[TrifectaLeg, tuple[TrifectaLeg, ...], "re.Pattern[str]", str]

_PRIV = TrifectaLeg.PRIVATE_DATA
_UNTR = TrifectaLeg.UNTRUSTED_CONTENT
_EXFIL = TrifectaLeg.EXFIL


def _c(p: str) -> "re.Pattern[str]":
    return re.compile(p, re.IGNORECASE)


# Patterns run over a NORMALIZED text: name + description, lowercased, with
# underscores and hyphens turned into spaces. Normalizing first is what makes `\b`
# reliable: `_` is a word character, so `\bread\b` never matches inside `read_file`
# unless the underscore is a space. Reads that ingest attacker-influenceable content
# (mailbox/message reads, issue/comment reads) carry BOTH private_data and
# untrusted_content. Writes that publish to a shared place are exfil.
_TOOL_SIGNALS: list[_Signal] = [
    # --- private data: read sensitive, local, or internal data ---
    (_PRIV, (), _c(r"\b(read|open|load|cat|get|list|show|view|stat|search|head|tail)\b.{0,12}\b(file|files|directory|directories|dir|folder|folders|path)\b"), "file read"),
    (_PRIV, (), _c(r"\bfile (contents?|info|metadata)\b|\bfilesystem\b|\bfs read\b|\bimport (csv|file|data|json|xml|excel|spreadsheet)\b"), "filesystem read"),
    (_PRIV, (), _c(r"\b(query|select|read|fetch|get|list|scan|find|lookup)\b.{0,12}\b(row|rows|record|records|table|tables|database|collection|documents?|item|items|entry|entries|value|values|postgres|postgresql|mysql|sqlite|mongo|mongodb|redis|bigquery|snowflake|duckdb|dynamodb)\b"), "database read"),
    (_PRIV, (), _c(r"\b(execute|run) (a )?(query|sql)\b|\bget item\b|\bread values\b|\bquery (the )?(database|table|db)\b"), "database query"),
    (_PRIV, (), _c(r"\bgit (show|log|diff|status|blame)\b|\b(show|read|get|view|log|diff|blame)\b.{0,20}\b(commit|commits|diff|diffs|branch|branches|source|repository|repo)\b|\b(commit|diff) (contents?|history)\b"), "repository read"),
    (_PRIV, (), _c(r"\b(secret|secrets|credential|credentials|api key|apikey|access key|password|passwd|private key|ssh key)\b|\b(secret|key|credential|password) vault\b|\bkeyvault\b"), "secret or credential access"),
    (_PRIV, (), _c(r"\b(get|read|list) (env|environment)\b|\benvironment variable"), "environment access"),
    # Reading messages/mail is BOTH private data and untrusted content (the bodies are
    # attacker-influenceable).
    (_PRIV, (_UNTR,), _c(r"\b(read|get|list|fetch|search|retrieve) (my |the |all |recent )?(email|emails|inbox|mailbox|message|messages|mail|dm|dms|conversation|conversations|chat history|channel history|history|replies)\b|\bget messages\b|\bchannel history\b"), "mailbox or message read"),
    (_PRIV, (), _c(r"\b(get|read|list|search|open|fetch) (my |the |all )?(note|notes|memory|memories|journal|bookmark|bookmarks|calendar|event|events|contact|contacts|reminder|reminders)\b|\baddress book\b"), "personal data"),
    (_PRIV, (), _c(r"\b(read|get|open|search|list|query) (the )?(graph|node|nodes|entity|entities|observation|observations|relation|relations|knowledge)\b|\bread graph\b|\bopen nodes\b"), "knowledge store read"),
    (_PRIV, (), _c(r"\b(get|list|search|read) (all )?(user|users|member|members|profile|profiles|directory|team member)\b"), "directory or profile read"),
    (_PRIV, (), _c(r"\b(get|read|list|download|fetch) (build |job |the )?(log|logs|artifact|artifacts)\b"), "logs or artifacts read"),
    (_PRIV, (), _c(r"\b(get|read|download|list|open) (a |the )?(object|bucket|blob|s3|drive|document|doc|sheet|spreadsheet)\b|\bget object\b|\bread file\b"), "storage or document read"),
    (_PRIV, (), _c(r"\bsearch\b.{0,25}\b(vault|note|notes|file|files|document|documents|drive|repository|repo|codebase|code|database|graph|knowledge|workspace|obsidian|mailbox|inbox|email|emails|message|messages|record|records)\b"), "search over a private store"),
    (_PRIV, (), _c(r"\b(confidential|proprietary|restricted|classified|pii|sensitive)\b|\bprivate (data|info|information|key|repo|repository)\b"), "sensitive-data marker"),
    # --- untrusted content: pull in third-party / attacker-influenceable content ---
    # (Arbitrary-URL fetch, which is dual-use, is handled by _web_fetch_dual below.)
    (_UNTR, (), _c(r"\bweb search\b|\bsearch (the )?(web|internet)\b|\b(bing|duckduckgo|brave search|serp|kagi)\b|\bsearch engine\b"), "web search"),
    (_UNTR, (), _c(r"\b(rss|feed|feeds|news|headlines?|wikipedia|arxiv|reddit|hacker news)\b"), "external feed"),
    (_UNTR, (), _c(r"\b(get|read|list|fetch|view|receive) (an |a |the |all )?(issue|issues|comment|comments|review|reviews|ticket|tickets|pull request|pull requests|merge request|discussion|discussions|thread|threads|mention|mentions)\b|\bincoming\b|\buser (content|input|submission)\b|\bthird party (content|data)\b"), "inbound third-party content"),
    # --- exfil: send data outward ---
    (_EXFIL, (), _c(r"\b(send|post|deliver|dispatch|reply|respond) (an |a |the )?(email|e mail|mail|message|msg|sms|dm|text|notification|reply)\b|\bsend email\b|\bsendmail\b|\bsmtp\b"), "send message"),
    (_EXFIL, (_UNTR,), _c(r"\b(http request|https request|api call|rest call|make request|send request|curl|proxy request)\b"), "arbitrary outbound HTTP (exfil and ingest)"),
    (_EXFIL, (), _c(r"\b(http (post|put|patch)|post request|webhook|callback url|send webhook)\b"), "outbound HTTP write"),
    # Writing/publishing agent-authored data to a shared or public place is exfil.
    # Publishing agent-authored content to a shared place is exfil. `issue` is left
    # to the "post to external system" rule below so that a status-only update_issue
    # is not mistaken for publishing content.
    (_EXFIL, (), _c(r"\b(create|update|append|add|write|put|post|publish|submit|insert) (a |an |the |new )?(record|records|item|items|row|rows|value|values|comment|comments|pull request|merge request|gist|blob|object|spreadsheet|sheet|entry)\b|\bput item\b|\bput blob\b|\bupdate gist\b"), "publish to shared place"),
    (_EXFIL, (), _c(r"\b(upload|publish|export|share)\b|\bput object\b|\bs3 put\b"), "outbound upload or publish"),
    (_EXFIL, (), _c(r"\b(send|post|reply|dm|message|broadcast|announce|notify|publish) (to |a |an |the )?(slack|discord|telegram|whatsapp|channel|chat|thread|group)\b|\b(tweet|toot)\b|\bpost to\b|\bbroadcast\b|\bannounce\b"), "post to external channel"),
    (_EXFIL, (), _c(r"\b(create|open|file|submit) (an |a |the )?(issue|ticket|pull request|gist|paste)\b|\bpastebin\b"), "post to external system"),
]

# Resource signals run over normalized "uri name description". Resources are data
# sources, so they can only supply the private-data or untrusted-content legs.
_RESOURCE_SIGNALS: list[_Signal] = [
    (_PRIV, (), _c(r"\b(internal|private|confidential|proprietary|restricted|personal|pii|sensitive|secret|credential|password)\b"), "sensitive resource"),
    (_PRIV, (), _c(r"\b(notes?|memory|journal|inbox|mailbox|contacts?|calendar|database|records?)\b"), "private data resource"),
    (_UNTR, (), _c(r"\b(external|web|http|url|third party|feed|rss|public comment|user content)\b"), "external content resource"),
]

# Arbitrary caller-controlled URL fetch is dual-use: it ingests untrusted content AND
# is an exfiltration channel (data rides out in the URL/path/query). Detected as a
# web token co-present with a fetch verb, which catches the canonical `fetch` server,
# `*_extract`/`crawl`/`scrape`/`navigate` (including -ing forms), and explicit forms,
# while a plain local read (no web token) or a fixed-endpoint search does not qualify.
_WEB_TOKEN = _c(r"\b(url|uri|web|web page|webpage|website|internet|https?|online|hyperlink|link)\b")
_FETCH_VERB = _c(r"\b(fetch\w*|retriev\w*|extract\w*|scrap\w*|crawl\w*|download\w*|browse|browsing|navigat\w*|render\w*|visit\w*|load\w*|open\w*|read\w*|get|access\w*|map)\b")
_EXPLICIT_FETCH = _c(r"\bweb fetch\b|\bfetch url\b|\bhttp get\b|\bread webpage\b|\bopen url\b|\bget page\b|\brender page\b")


def _web_fetch_dual(text: str) -> bool:
    """True when the tool fetches an arbitrary caller-controlled URL (ingest + exfil)."""
    if _EXPLICIT_FETCH.search(text):
        return True
    return bool(_WEB_TOKEN.search(text) and _FETCH_VERB.search(text))


# Writing a file/document to a remote or shared store is exfil; the same verb on a
# purely local file is not. Distinguish by a cloud/shared marker so local filesystem
# writes are not flagged.
_CLOUD_TOKEN = _c(r"\b(drive|google|cloud|remote|s3|dropbox|onedrive|sharepoint|shared|online|bucket|gist|notion|confluence|wiki)\b")
_FILE_WRITE = _c(r"\b(create|update|write|upload|save|put|add|append) (a |an |the |new )?(file|document|doc|folder|page)\b")


def _cloud_write_exfil(text: str) -> bool:
    """True when the tool writes a file/document to a remote or shared store."""
    return bool(_CLOUD_TOKEN.search(text) and _FILE_WRITE.search(text))


def _normalize(text: str) -> str:
    """Lowercase and split word boundaries so `\\b` matches reliably.

    Turns underscores/hyphens into spaces AND splits camelCase/PascalCase, because a
    terse tool name like `sendEmail` is one `\\b`-token otherwise and would slip every
    verb+object rule. camelCase is the dominant JS/TS MCP naming style, so this closes a
    classifier blind spot (a `sendEmail` tool now normalizes to `send email` exactly
    like `send_email`). Acronym runs are handled too: `getHTTPResponse` -> `get http
    response`.

    Invisible characters are stripped and compatibility forms are NFKC-folded FIRST,
    matching the scanner. Without this the action-gate side-effect classifier is blind to
    a tool a hostile server names with a fullwidth verb ("DELETE all records" in fullwidth
    Latin) or a verb split by an invisible character ("de<ZWSP>lete") - which reads as the
    real verb to a human but slips the gate.
    """
    text = strip_invisible(text).text  # rejoin invisible-split verbs
    text = unicodedata.normalize("NFKC", text)  # fold fullwidth / compatibility forms
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text)  # sendEmail -> send Email
    text = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", " ", text)  # HTTPResponse -> HTTP Response
    return re.sub(r"[\s_\-]+", " ", text.lower()).strip()


# Memory taxonomy: MCP-exposed persistent memory (a memory server, a knowledge graph, a
# vector store) is a distinct injection surface. Poison written to memory once is recalled
# as trusted in every later session (MINJA-class), so the proxy must recognize a WRITE (to
# gate a poisoning persist and tag the stored content) and a READ (to attribute and enforce
# recalled content). Kept separate from the trifecta signals so classify_server is
# unchanged; a memory read is already covered there as private-data.
_MEMORY_WRITE = _c(
    r"\b(remember|memoriz\w*)\b"
    r"|\bupsert\b"
    r"|\b(store|save|persist|record|add|create|write|put|append|index|embed|ingest)\b"
    r".{0,20}\b(memor\w+|fact|facts|note|notes|knowledge|observation|observations"
    r"|entity|entities|relation|relations|node|nodes|context|graph)\b"
    r"|\b(store|save|write|add|put) (to|in|into) memory\b"
)
_MEMORY_READ = _c(
    r"\brecall\b"
    r"|\b(read|get|search|query|fetch|list|load|lookup|retriev\w*)\b"
    r".{0,20}\b(memor\w+|fact|facts|note|notes|knowledge|observation|observations"
    r"|entity|entities|relation|relations|node|nodes)\b"
    r"|\b(search|read|get|query) (from )?memory\b|\bopen nodes\b|\bread graph\b"
)


def classify_memory_tool(name: str, description: str = "") -> str | None:
    """Classify a tool as an MCP memory WRITE, memory READ, or neither.

    Returns "write" (persists content to a memory / knowledge / vector store), "read"
    (retrieves stored content), or None. Write is tested first: a tool that both stores and
    returns is treated as a write, since the persistence is the higher-consequence side an
    injection abuses. Pure and local, reusing the same normalization as the trifecta
    classifier so a camelCase / underscore tool name is matched the same way."""
    text = _normalize(f"{name} {description or ''}")
    if _MEMORY_WRITE.search(text):
        return "write"
    if _MEMORY_READ.search(text):
        return "read"
    return None


def _match_signals(text: str, signals: list[_Signal]) -> list[tuple[TrifectaLeg, str]]:
    """Return (leg, evidence) pairs for every taxonomy entry matching `text`."""
    out: list[tuple[TrifectaLeg, str]] = []
    for leg, extra, pattern, label in signals:
        m = pattern.search(text)
        if m:
            for lg in (leg, *extra):
                out.append((lg, f"{label}: {m.group(0).strip()!r}"))
    return out


def classify_server(surface: ServerSurface) -> list[LegSignal]:
    """Classify one server's surface into trifecta-leg signals."""
    signals: list[LegSignal] = []
    seen: set[tuple[str, TrifectaLeg]] = set()  # dedupe per (capability, leg)

    for tool in surface.tools:
        text = _normalize(f"{tool.name} {tool.description}")
        pairs = _match_signals(text, _TOOL_SIGNALS)
        if _web_fetch_dual(text):
            pairs.append((TrifectaLeg.UNTRUSTED_CONTENT, "arbitrary-URL fetch (ingest and URL-borne exfil)"))
            pairs.append((TrifectaLeg.EXFIL, "arbitrary-URL fetch (ingest and URL-borne exfil)"))
        if _cloud_write_exfil(text):
            pairs.append((TrifectaLeg.EXFIL, "write to remote or shared storage"))
        for leg, evidence in pairs:
            key = (f"tool:{tool.name}", leg)
            if key in seen:
                continue
            seen.add(key)
            signals.append(LegSignal(surface.name, leg, "tool", tool.name, evidence))

    for res in surface.resources:
        text = _normalize(f"{res.uri} {res.name} {res.description}")
        for leg, evidence in _match_signals(text, _RESOURCE_SIGNALS):
            key = (f"resource:{res.uri}", leg)
            if key in seen:
                continue
            seen.add(key)
            signals.append(LegSignal(surface.name, leg, "resource", str(res.uri), evidence))

    if surface.untrusted_emitter:
        signals.append(
            LegSignal(
                surface.name,
                TrifectaLeg.UNTRUSTED_CONTENT,
                "provenance",
                surface.name,
                "emits provenance-tagged external/untrusted content",
            )
        )

    return signals


@dataclass
class CompositionReport:
    """The result of analyzing a set of connected servers together."""

    servers: list[str]
    signals: list[LegSignal]
    legs_present: dict[TrifectaLeg, list[LegSignal]]
    trifecta_enabled: bool
    jointly_enabled: bool  # enabled, but no single server supplies all three legs
    single_server_culprits: list[str]  # servers that alone supply all three legs
    server_legs: dict[str, set[TrifectaLeg]]
    provenance_aware_sources: list[str]  # untrusted-content servers that tag provenance
    mitigations: list[str]
    errors: list[str] = field(default_factory=list)

    @property
    def severity(self) -> Severity:
        n = sum(1 for leg in _ALL_LEGS if self.legs_present.get(leg))
        if n >= 3:
            return Severity.ERROR
        if n == 2:
            return Severity.WARNING
        if n == 1:
            return Severity.NOTE
        return Severity.NONE


def analyze_composition(
    surfaces: list[ServerSurface], errors: list[str] | None = None
) -> CompositionReport:
    """Classify each server and flag whether the composition enables the trifecta."""
    all_signals: list[LegSignal] = []
    server_legs: dict[str, set[TrifectaLeg]] = {s.name: set() for s in surfaces}
    for surface in surfaces:
        for sig in classify_server(surface):
            all_signals.append(sig)
            server_legs.setdefault(sig.server, set()).add(sig.leg)

    legs_present: dict[TrifectaLeg, list[LegSignal]] = {
        leg: [s for s in all_signals if s.leg == leg] for leg in _ALL_LEGS
    }
    enabled = all(legs_present[leg] for leg in _ALL_LEGS)
    culprits = [name for name, legs in server_legs.items() if set(_ALL_LEGS) <= legs]
    jointly = enabled and not culprits

    provenance_aware = [s.name for s in surfaces if s.untrusted_emitter]
    mitigations = _mitigations(enabled, legs_present, provenance_aware, surfaces)

    return CompositionReport(
        servers=[s.name for s in surfaces],
        signals=all_signals,
        legs_present=legs_present,
        trifecta_enabled=enabled,
        jointly_enabled=jointly,
        single_server_culprits=culprits,
        server_legs=server_legs,
        provenance_aware_sources=provenance_aware,
        mitigations=mitigations,
        errors=errors or [],
    )


def _mitigations(
    enabled: bool,
    legs_present: dict[TrifectaLeg, list[LegSignal]],
    provenance_aware: list[str],
    surfaces: list[ServerSurface],
) -> list[str]:
    if not enabled:
        missing = [leg.value for leg in _ALL_LEGS if not legs_present[leg]]
        return [
            "The trifecta is not fully enabled by this set. Missing leg(s): "
            + ", ".join(missing)
            + ". Re-check if more servers are added."
        ]

    untrusted_servers = sorted({s.server for s in legs_present[TrifectaLeg.UNTRUSTED_CONTENT]})
    exfil_servers = sorted({s.server for s in legs_present[TrifectaLeg.EXFIL]})
    untagged = [s.name for s in surfaces if s.name in untrusted_servers and not s.untrusted_emitter]

    tips = [
        "This deployment enables the lethal trifecta: an injection in the "
        "untrusted-content leg can reach the private-data leg and leave through the "
        "exfil leg. Break at least one leg for this agent.",
        "Route the untrusted-content source(s) "
        + ", ".join(untrusted_servers)
        + " through the blindspot enforcer so injected instructions are demoted to "
        "data and never enter the instruction path.",
        "Gate the exfil tool(s) on "
        + ", ".join(exfil_servers)
        + " behind human approval whenever untrusted content is in context; the "
        "enforcer's action-gating does exactly this.",
    ]
    if untagged:
        tips.append(
            "Untrusted-content source(s) "
            + ", ".join(untagged)
            + " do not emit provenance. The enforcer treats them as untrusted and "
            "fails closed, but tagging them (Phase 2) makes the boundary precise."
        )
    if provenance_aware:
        tips.append(
            "Source(s) "
            + ", ".join(provenance_aware)
            + " already tag provenance; with the enforcer active their injected "
            "content is demoted to data, which materially reduces the trifecta risk."
        )
    return tips


async def capture_surface(session, name: str) -> ServerSurface:
    """Build a ServerSurface from a live session: tools, resources, and whether the
    server emits provenance-tagged untrusted content (a Phase 2 signal)."""
    from blindspot.enforce.middleware import parse_provenance
    from blindspot.models import Origin, Trust
    from blindspot.scan.client import fetch_targets

    tools: list[ToolInfo] = []
    resources: list[ResourceInfo] = []
    try:
        for t in (await session.list_tools()).tools:
            tools.append(ToolInfo(t.name, t.description or ""))
    except Exception:  # noqa: BLE001 - absent surface is a valid (empty) capture
        pass
    try:
        for r in (await session.list_resources()).resources:
            resources.append(ResourceInfo(str(r.uri), r.name or "", r.description or ""))
    except Exception:  # noqa: BLE001
        pass

    untrusted_emitter = False
    try:
        targets, _tools, _errs = await fetch_targets(session)
        for item in targets:
            prov = parse_provenance(item.meta)
            if prov is not None and (
                prov.trust in (Trust.UNTRUSTED, Trust.QUARANTINED)
                or prov.origin in (Origin.EXTERNAL, Origin.USER)
            ):
                untrusted_emitter = True
                break
    except Exception:  # noqa: BLE001 - provenance probe is best-effort
        pass

    return ServerSurface(
        name=name, tools=tools, resources=resources, untrusted_emitter=untrusted_emitter
    )


def render_human(report: CompositionReport) -> str:
    """Plain-text composition report."""
    r = report
    lines = [
        "blindspot compose: cross-server composition analysis",
        f"servers ({len(r.servers)}): {', '.join(r.servers) if r.servers else '(none)'}",
    ]
    if r.errors:
        lines.append(f"errors: {len(r.errors)}")
        for e in r.errors:
            lines.append(f"  ! {e}")
    lines.append("")

    verdict = "ENABLED" if r.trifecta_enabled else "not enabled"
    lines.append(f"lethal trifecta: {verdict}  [{r.severity.value}]")
    if r.trifecta_enabled:
        lines.append(
            "jointly enabled by the composition (no single server is the culprit)"
            if r.jointly_enabled
            else f"a single server alone enables it: {', '.join(r.single_server_culprits)}"
        )
    lines.append("")

    lines.append("legs:")
    for leg in _ALL_LEGS:
        sigs = r.legs_present[leg]
        mark = "present" if sigs else "ABSENT"
        lines.append(f"  {leg.value:18} {mark}")
        for s in sigs:
            lines.append(f"      - {s.server}: {s.kind} {s.name}  ({s.evidence})")
    lines.append("")

    lines.append("per-server legs:")
    for name in r.servers:
        legs = sorted(leg.value for leg in r.server_legs.get(name, set()))
        lines.append(f"  {name}: {', '.join(legs) if legs else '(none)'}")
    lines.append("")

    lines.append("mitigations:" if r.mitigations else "")
    for m in r.mitigations:
        lines.append(f"  - {m}")
    return "\n".join(lines).rstrip() + "\n"


def render_json(report: CompositionReport) -> str:
    """Machine-readable composition report."""
    import json

    r = report

    def sig(s: LegSignal) -> dict:
        return {
            "server": s.server,
            "leg": s.leg.value,
            "kind": s.kind,
            "name": s.name,
            "evidence": s.evidence,
        }

    doc = {
        "servers": r.servers,
        "trifecta_enabled": r.trifecta_enabled,
        "jointly_enabled": r.jointly_enabled,
        "single_server_culprits": r.single_server_culprits,
        "severity": r.severity.value,
        "legs": {leg.value: [sig(s) for s in r.legs_present[leg]] for leg in _ALL_LEGS},
        "server_legs": {k: sorted(v.value for v in vs) for k, vs in r.server_legs.items()},
        "provenance_aware_sources": r.provenance_aware_sources,
        "mitigations": r.mitigations,
        "errors": r.errors,
    }
    return json.dumps(doc, indent=2)
