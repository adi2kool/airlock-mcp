"""Render the flight-recorder ledger into something a human can read.

The proxy already records every enforcement / gate / egress / drift decision into a
hash-chained, optionally-signed JSONL ledger. That is the tamper-evident source of truth,
but it is unreadable: raw JSON lines. This module turns it into a legible report - a
summary of what Airlock did (how much untrusted content it demoted to data, how many
side-effecting calls it gated, how many secrets it stopped from leaving, whether a server
rug-pulled) plus the chain-integrity verdict, in three renderings:

  * human  - a terminal summary + a timeline of the notable decisions.
  * json   - the same aggregates, machine-readable.
  * html   - a self-contained, zero-dependency page (inline CSS, no network) for a
             screenshot / a shared proof-of-value artifact / a compliance reviewer.

Read-only and $0: it parses the ledger and calls verify_chain (the same integrity check
`airlock verify-log` uses). It never touches the enforce/proxy core.
"""

from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

# C0/C1 control characters (incl. ESC 0x1b, CR, LF, BEL). Ledger idents and detail come from
# a HOSTILE server (it controls tool names), so a value printed to a terminal could otherwise
# emit ANSI escape sequences or forge extra log lines. Strip them before rendering.
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _clean(s: object) -> str:
    """Strip terminal/log-forging control characters from a server-controlled string."""
    return _CONTROL.sub("", str(s))

from airlock import __version__ as _VERSION
from airlock.ledger import (
    EV_ACTION,
    EV_APPROVAL_DECISION,
    EV_APPROVAL_REQUEST,
    EV_DRIFT,
    EV_EGRESS,
    EV_ELICITATION,
    EV_ENFORCE,
    EV_LOCK,
    EV_SAMPLING,
    ChainResult,
    verify_chain,
)

# Human labels for the event types, for the timeline and legend.
_EVENT_LABEL = {
    EV_ENFORCE: "enforced",
    EV_ACTION: "action gate",
    EV_LOCK: "lock violation",
    EV_DRIFT: "surface drift",
    EV_SAMPLING: "sampling",
    EV_ELICITATION: "elicitation",
    EV_APPROVAL_REQUEST: "approval requested",
    EV_APPROVAL_DECISION: "approval decision",
    EV_EGRESS: "egress DLP",
}


@dataclass
class LedgerSummary:
    """Aggregate counts over a ledger, computed in one pass."""

    entries: int = 0
    events: dict = field(default_factory=dict)  # event -> count
    # Enforcement dispositions (what happened to content the proxy saw).
    trusted: int = 0
    demoted: int = 0  # untrusted or quarantined = "demoted to data"
    quarantined: int = 0
    # Action gating.
    actions_seen: int = 0
    actions_gated: int = 0
    # Egress DLP.
    egress_events: int = 0
    egress_blocked: int = 0
    egress_redacted: int = 0
    egress_detectors: dict = field(default_factory=dict)  # detector -> count
    # Supply-chain / rug-pull.
    drift_events: int = 0
    lock_violations: int = 0
    # Reverse channels.
    sampling: int = 0
    elicitation: int = 0
    # Approvals.
    approvals_requested: int = 0
    approvals_granted: int = 0
    approvals_denied: int = 0
    first_ts: str = ""
    last_ts: str = ""


# Cap the number of timeline rows the report renders/retains. A flight recorder is explicitly
# long-lived and append-only (one entry per enforced item), so loading the WHOLE file into
# memory to render it is O(entries) peak RSS and OOMs a large ledger on a small CI runner
# (audit M3). We stream the file and keep only the most-recent notable rows; the headline
# aggregates are exact (accumulated over the full stream), only the timeline is bounded.
_MAX_NOTABLE_ROWS = 1000


@dataclass
class LedgerReport:
    """A summarized ledger plus its chain-integrity verdict. `notable` holds only the most
    recent notable rows (bounded by _MAX_NOTABLE_ROWS); the summary aggregates cover ALL
    entries. `entries` is retained (empty) only for backward compatibility."""

    path: str
    chain: ChainResult
    summary: LedgerSummary
    notable: list = field(default_factory=list)  # most-recent notable entry dicts (bounded)
    notable_total: int = 0  # total notable entries across the whole ledger
    notable_truncated: bool = False  # True when older notable rows were elided
    entries: list = field(default_factory=list)  # deprecated; kept empty for compatibility


def load_entries(path: str | Path) -> list[dict]:
    """Parse the JSONL ledger into entry dicts, skipping blank/corrupt lines. The chain's
    integrity is verified separately by verify_chain; this is only for rendering.

    NOTE: this materializes the whole ledger in memory. The report path uses the streaming
    `build_report` instead (M3); this remains for callers that genuinely need every entry."""
    out: list[dict] = []
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


def _accumulate(s: LedgerSummary, e: dict) -> None:
    """Fold one entry into the running summary aggregates."""
    event = e.get("event", "")
    s.events[event] = s.events.get(event, 0) + 1
    ts = e.get("ts", "")
    if ts:
        if not s.first_ts:
            s.first_ts = ts
        s.last_ts = ts
    detail = e.get("detail") or {}
    disp = e.get("disposition")
    if event == EV_ENFORCE:
        if disp == "trusted":
            s.trusted += 1
        else:
            s.demoted += 1
            if disp == "quarantined":
                s.quarantined += 1
    elif event == EV_ACTION:
        s.actions_seen += 1
        if detail.get("gated"):
            s.actions_gated += 1
    elif event == EV_EGRESS:
        s.egress_events += 1
        if detail.get("blocked"):
            s.egress_blocked += 1
        if detail.get("redacted"):
            s.egress_redacted += 1
        for d in detail.get("detectors", []) or []:
            s.egress_detectors[d] = s.egress_detectors.get(d, 0) + 1
    elif event == EV_DRIFT:
        s.drift_events += 1
    elif event == EV_LOCK:
        s.lock_violations += 1
    elif event == EV_SAMPLING:
        s.sampling += 1
    elif event == EV_ELICITATION:
        s.elicitation += 1
    elif event == EV_APPROVAL_REQUEST:
        s.approvals_requested += 1
    elif event == EV_APPROVAL_DECISION:
        if detail.get("approved"):
            s.approvals_granted += 1
        else:
            s.approvals_denied += 1


def summarize(entries: list[dict]) -> LedgerSummary:
    """One pass over already-loaded entries producing the headline aggregates."""
    s = LedgerSummary(entries=len(entries))
    for e in entries:
        _accumulate(s, e)
    return s


def build_report(
    path: str | Path,
    public_key: bytes | None = None,
    *,
    expected_entries: int | None = None,
    expected_tip: str | None = None,
) -> LedgerReport:
    """Verify and summarize a ledger by STREAMING it line-by-line, so peak memory is O(1) in
    the ledger size (not O(entries)); only the headline counters and the most-recent
    `_MAX_NOTABLE_ROWS` notable rows are retained (audit M3).

    `expected_entries`/`expected_tip` are the out-of-band truncation anchor: passing them lets
    the report flag a log whose newest entries were dropped, the same as `verify-log` (audit
    L1)."""
    from collections import deque

    chain = verify_chain(
        path, public_key=public_key,
        expected_entries=expected_entries, expected_tip=expected_tip,
    )
    s = LedgerSummary()
    notable: deque = deque(maxlen=_MAX_NOTABLE_ROWS)
    notable_total = 0
    try:
        fh = Path(path).open("r", encoding="utf-8")
    except OSError:
        return LedgerReport(path=str(path), chain=chain, summary=s)
    with fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if not isinstance(e, dict):
                continue
            s.entries += 1
            _accumulate(s, e)
            if _is_notable(e):
                notable_total += 1
                notable.append(e)
    return LedgerReport(
        path=str(path), chain=chain, summary=s,
        notable=list(notable), notable_total=notable_total,
        notable_truncated=notable_total > len(notable),
    )


def _is_notable(e: dict) -> bool:
    """A clean trusted passthrough is not interesting; everything else is a decision worth
    showing (a demotion, a gate, an egress finding, a drift, an approval)."""
    if e.get("event") == EV_ENFORCE and e.get("disposition") == "trusted":
        return False
    return True


def _outcome(e: dict) -> str:
    """A short human phrase for what happened in this entry."""
    event = e.get("event", "")
    detail = e.get("detail") or {}
    disp = e.get("disposition")
    if event == EV_ENFORCE:
        if disp == "trusted":
            return "passed through (trusted)"
        return f"demoted to data ({disp or 'untrusted'})"
    if event == EV_ACTION:
        mode = detail.get("mode", "")
        return f"gated ({mode})" if detail.get("gated") else f"allowed ({mode})"
    if event == EV_EGRESS:
        dets = ", ".join(detail.get("detectors", []) or []) or "secret"
        if detail.get("blocked"):
            return f"BLOCKED egress: {dets}"
        if detail.get("redacted"):
            return f"redacted egress: {dets}"
        return f"flagged egress: {dets}"
    if event == EV_DRIFT:
        return f"surface drift ({detail.get('mode', '')})"
    if event == EV_LOCK:
        return f"lock violation: {detail.get('kind', 'surface drift')}"
    if event in (EV_SAMPLING, EV_ELICITATION):
        return f"reverse channel enforced ({detail.get('mode', '')})"
    if event == EV_APPROVAL_DECISION:
        return "approved" if detail.get("approved") else "denied"
    if event == EV_APPROVAL_REQUEST:
        return "held for approval"
    return _EVENT_LABEL.get(event, event)


# --- renderers ------------------------------------------------------------------------


def render_human(rep: LedgerReport) -> str:
    s = rep.summary
    c = rep.chain
    lines: list[str] = [f"airlock flight recorder: {rep.path}"]
    status = "INTACT" if c.ok else "BROKEN"
    # c.reason, the timestamps, and the detector names below all originate (directly or
    # indirectly) from a HOSTILE server that controls tool names / ledger idents / a forged
    # ledger file, so they are _clean()'d like every timeline field - otherwise a crafted value
    # could emit ANSI escapes or forge/overwrite report lines in the operator's terminal.
    lines.append(f"chain: {status}  ({c.entries} entries, {c.signed} signed)  {_clean(c.reason)}")
    if not c.ok and c.first_broken_seq is not None:
        lines.append(f"  ! first broken at seq {c.first_broken_seq}")
    if c.unsigned:
        lines.append("  ! UNSIGNED: keyless chain - 'intact' means no accidental corruption, "
                     "NOT tamper-proof against a file writer. Sign the proxy with --audit-key "
                     "and verify with --key for tamper-evidence.")
    if s.first_ts:
        lines.append(f"window: {_clean(s.first_ts)}  ..  {_clean(s.last_ts)}")
    lines.append("")
    lines.append("what airlock did:")
    lines.append(f"  content enforced      {s.trusted + s.demoted}  "
                 f"({s.demoted} demoted to data, {s.quarantined} quarantined, {s.trusted} trusted)")
    lines.append(f"  side-effect calls     {s.actions_seen} seen, {s.actions_gated} gated")
    egress_detail = ""
    if s.egress_detectors:
        egress_detail = "  [" + ", ".join(
            f"{_clean(k)}×{v}" for k, v in sorted(s.egress_detectors.items())
        ) + "]"
    lines.append(f"  egress DLP            {s.egress_events} finding(s), "
                 f"{s.egress_blocked} blocked, {s.egress_redacted} redacted{egress_detail}")
    lines.append(f"  supply chain          {s.drift_events} drift, {s.lock_violations} lock violation(s)")
    lines.append(f"  reverse channels      {s.sampling} sampling, {s.elicitation} elicitation")
    if s.approvals_requested:
        lines.append(f"  approvals             {s.approvals_requested} requested, "
                     f"{s.approvals_granted} granted, {s.approvals_denied} denied")

    notable = rep.notable  # already filtered + bounded to the most-recent rows (M3)
    lines.append("")
    if rep.notable_total == 0:
        lines.append("timeline: no notable decisions (all content passed through as trusted)")
    else:
        header = f"timeline ({rep.notable_total} notable of {s.entries}"
        if rep.notable_truncated:
            header += f"; showing the most recent {len(notable)}"
        lines.append(header + "):")
        for e in notable:
            ts = _clean((e.get("ts") or "")[11:19])  # HH:MM:SS
            ident = _clean(e.get("ident", ""))
            label = _clean(_EVENT_LABEL.get(e.get("event", ""), e.get("event", "")))
            ehash = _clean((e.get("entry_hash") or "")[:12])
            lines.append(f"  {ts}  {label:<16}  {ident:<28}  {_clean(_outcome(e))}   #{ehash}")
    return "\n".join(lines)


def render_json(rep: LedgerReport) -> str:
    s = rep.summary
    doc = {
        "path": rep.path,
        "chain": {
            "ok": rep.chain.ok, "entries": rep.chain.entries, "signed": rep.chain.signed,
            "reason": rep.chain.reason, "first_broken_seq": rep.chain.first_broken_seq,
            "unsigned": rep.chain.unsigned,
        },
        "window": {"first": s.first_ts, "last": s.last_ts},
        "summary": {
            "entries": s.entries,
            "events": s.events,
            "enforced": {"trusted": s.trusted, "demoted": s.demoted, "quarantined": s.quarantined},
            "actions": {"seen": s.actions_seen, "gated": s.actions_gated},
            "egress": {
                "findings": s.egress_events, "blocked": s.egress_blocked,
                "redacted": s.egress_redacted, "detectors": s.egress_detectors,
            },
            "supply_chain": {"drift": s.drift_events, "lock_violations": s.lock_violations},
            "reverse_channels": {"sampling": s.sampling, "elicitation": s.elicitation},
            "approvals": {
                "requested": s.approvals_requested, "granted": s.approvals_granted,
                "denied": s.approvals_denied,
            },
        },
    }
    return json.dumps(doc, indent=2)


_HTML_CSS = """
:root{--ink:#1f2328;--muted:#6b7280;--line:#e5e7eb;--bg:#fbfcfd;--card:#fff;
--ok:#1a7f4b;--bad:#b42318;--warn:#b45309;--accent:#2a5bd7;--mono:ui-monospace,SFMono-Regular,Menlo,monospace}
*{box-sizing:border-box}body{margin:0}
.wrap{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
color:var(--ink);background:var(--bg);padding:32px;max-width:960px;margin:0 auto;line-height:1.45}
h1{font-size:20px;margin:0 0 4px}.sub{color:var(--muted);font-size:13px;margin:0 0 20px;font-family:var(--mono)}
.badge{display:inline-block;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:600}
.badge.ok{background:#e7f6ee;color:var(--ok)}.badge.bad{background:#fdecea;color:var(--bad)}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin:20px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;min-width:150px;flex:1}
.card .n{font-size:26px;font-weight:700}.card .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.03em}
.card.hot .n{color:var(--bad)}
h2{font-size:14px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin:26px 0 8px}
.tl{width:100%;border-collapse:collapse;font-size:13px}
.tl th{text-align:left;color:var(--muted);font-weight:600;border-bottom:1px solid var(--line);padding:6px 8px}
.tl td{border-bottom:1px solid var(--line);padding:6px 8px;vertical-align:top}
.tl tr:hover{background:#f6f8fa}
.ev{font-weight:600}.mono{font-family:var(--mono);color:var(--muted);font-size:11px}
.o-bad{color:var(--bad);font-weight:600}.o-warn{color:var(--warn);font-weight:600}.o-ok{color:var(--ok)}
.scroll{overflow-x:auto}.foot{color:var(--muted);font-size:12px;margin-top:24px}
"""


def _stat_card(n, label, hot=False):
    cls = "card hot" if hot else "card"
    return f'<div class="{cls}"><div class="n">{n}</div><div class="l">{html.escape(label)}</div></div>'


def _outcome_class(e: dict) -> str:
    event = e.get("event", "")
    detail = e.get("detail") or {}
    if event == EV_EGRESS and detail.get("blocked"):
        return "o-bad"
    if event == EV_LOCK:
        return "o-bad"
    if event == EV_ACTION and detail.get("gated"):
        return "o-bad"
    if event in (EV_EGRESS, EV_DRIFT):
        return "o-warn"
    if event == EV_ENFORCE and e.get("disposition") != "trusted":
        return "o-warn"
    return ""


def render_html(rep: LedgerReport) -> str:
    s = rep.summary
    c = rep.chain
    badge = ('<span class="badge ok">chain intact</span>' if c.ok
             else '<span class="badge bad">chain BROKEN</span>')
    cards = "".join([
        _stat_card(s.demoted, "demoted to data"),
        _stat_card(s.actions_gated, "side-effect calls gated", hot=s.actions_gated > 0),
        _stat_card(s.egress_blocked + s.egress_redacted, "secrets stopped",
                   hot=(s.egress_blocked + s.egress_redacted) > 0),
        _stat_card(s.drift_events + s.lock_violations, "rug-pull / drift",
                   hot=(s.drift_events + s.lock_violations) > 0),
        _stat_card(s.entries, "ledger entries"),
    ])
    rows = []
    if rep.notable_truncated:
        rows.append(
            f'<tr><td colspan="5" class="mono">... {rep.notable_total - len(rep.notable)} '
            f'older notable row(s) elided; showing the most recent {len(rep.notable)}</td></tr>'
        )
    for e in rep.notable:  # already notable + bounded (M3)
        ts = html.escape(_clean((e.get("ts") or "")[:19].replace("T", " ")))
        label = html.escape(_clean(_EVENT_LABEL.get(e.get("event", ""), e.get("event", ""))))
        ident = html.escape(_clean(e.get("ident", "")))
        ehash = html.escape(_clean((e.get("entry_hash") or "")[:16]))
        outcome = html.escape(_clean(_outcome(e)))
        rows.append(
            f'<tr><td class="mono">{ts}</td><td class="ev">{label}</td>'
            f'<td>{ident}</td><td class="{_outcome_class(e)}">{outcome}</td>'
            f'<td class="mono">#{ehash}</td></tr>'
        )
    timeline = (
        '<table class="tl"><thead><tr><th>time</th><th>event</th><th>target</th>'
        '<th>outcome</th><th>entry hash</th></tr></thead><tbody>'
        + ("".join(rows) or '<tr><td colspan="5">no notable decisions</td></tr>')
        + "</tbody></table>"
    )
    window = ""
    if s.first_ts:
        # _clean before escape: html.escape neutralizes markup but not raw control bytes (ESC),
        # which a forged ledger's timestamp could otherwise leak into the page/terminal.
        window = f"{html.escape(_clean(s.first_ts))} &nbsp;..&nbsp; {html.escape(_clean(s.last_ts))}"
    reason = html.escape(_clean(c.reason))
    unsigned_banner = ""
    if c.unsigned:
        unsigned_banner = (
            '<p class="foot" style="color:var(--bad)"><strong>UNSIGNED.</strong> This chain was '
            'verified without a key, so its links are keyless and can be recomputed by anyone who '
            'can write the file: "chain intact" means no accidental corruption, NOT tamper-proof. '
            'Sign the proxy with <code>--audit-key</code> and verify with <code>--key</code> for '
            'tamper-evidence.</p>'
        )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Airlock flight recorder</title><style>{_HTML_CSS}</style></head>
<body><div class="wrap">
<h1>Airlock flight recorder &nbsp;{badge}</h1>
<p class="sub">{html.escape(rep.path)} &middot; {c.entries} entries, {c.signed} signed &middot; {reason}<br>{window}</p>
<div class="cards">{cards}</div>
<h2>What Airlock did</h2>
<div class="scroll">{timeline}</div>
{unsigned_banner}
<p class="foot">Generated by airlock {html.escape(_VERSION)}. Every row is anchored to its entry hash.
When the proxy SIGNS the trail (<code>--audit-key</code>) and this report is verified with the
public key (<code>--key</code>), editing, reordering, inserting, or removing any interior entry is
detected as a signature failure. An UNSIGNED chain's links are keyless and can be recomputed by
anyone who can write the file, so verify with a key for tamper-evidence against an adversary.
Detecting truncation of the most recent entries additionally requires anchoring the tip
(<code>--expect-tip</code> / <code>--expect-count</code>, supported by both <code>verify-log</code>
and <code>report</code>). This report is read-only and never contains secret values.</p>
</div></body></html>"""
