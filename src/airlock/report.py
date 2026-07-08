"""Report writers: human readable, JSON, and SARIF 2.1.0.

Renders the findings the scanner produced. SARIF is validated offline against a
compact self-contained JSON Schema covering the subset we emit, using jsonschema
(already available). Swapping in the full upstream SARIF schema is an optional
future upgrade and is not needed for $0 CI.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from jsonschema import Draft202012Validator

from airlock import __version__ as _VERSION
from airlock.models import (
    AttackClass,
    Finding,
    LeastPrivFinding,
    Report,
    Severity,
    severity_rank,
)
from airlock.sanitize import strip_control as _clean

_SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
_INFO_URI = "https://github.com/adi2kool/airlock-mcp"

# Typical default level per attack class, for SARIF rule metadata.
_DEFAULT_LEVEL = {
    AttackClass.INSTRUCTION_OVERRIDE: Severity.ERROR,
    AttackClass.DATA_EXFILTRATION: Severity.ERROR,
    AttackClass.TOOL_SHADOWING: Severity.ERROR,
    AttackClass.HIDDEN_UNICODE: Severity.ERROR,
    AttackClass.HOMOGLYPH: Severity.WARNING,
    AttackClass.CONDITIONAL_PAYLOAD: Severity.WARNING,
}


def render_human(report: Report) -> str:
    """Plain-text report. No dependencies. Covers both scan and audit output.

    Every field that originates from the scanned (hostile) server - tool/prompt/resource
    names, evidence, decoded text, error strings - is `_clean()`'d to strip C0/C1 control
    characters before it is interpolated, so a crafted tool name cannot inject ANSI escapes
    or forge extra output lines in the operator's terminal (audit H5). `report.target` is a
    CLI argument, cleaned defensively too."""
    lines: list[str] = [f"airlock: {_clean(report.target)}"]
    if report.items_scanned or report.judge_used or report.judge_available:
        judge = (
            "used"
            if report.judge_used
            else ("available, unused" if report.judge_available else "unavailable")
        )
        lines.append(f"items scanned: {report.items_scanned}   judge: {judge}")
    # The semantic judge was asked for but is not running: say so prominently so a clean
    # local-only scan is not mistaken for a clean semantic scan (audit M4). NOTE-level: it
    # does not fail CI, it just tells the operator coverage is reduced.
    if report.judge_requested and not report.judge_available:
        lines.append(
            "[NOTE] semantic judge unavailable: scan used local detectors only; an encoded "
            "or paraphrased injection may be missed. Configure a model (AIRLOCK_INFER_URL / "
            "Ollama) for semantic coverage."
        )
    if report.errors:
        lines.append(f"errors: {len(report.errors)}")
        for err in report.errors:
            lines.append(f"  ! {_clean(err)}")

    if report.findings:
        ordered = sorted(
            report.findings,
            key=lambda f: (f.target, -severity_rank(f.severity), f.attack_class.value),
        )
        lines.append("")
        counts: dict[Severity, int] = {}
        for f in ordered:
            counts[f.severity] = counts.get(f.severity, 0) + 1
            where = f"@chars {f.span.start}-{f.span.end}" if f.span else "@item"
            lines.append(
                f"[{f.severity.value.upper()}] {f.attack_class.value}  "
                f"{_clean(f.surface)} {_clean(f.target)}  {where}  {_clean(repr(f.evidence))}"
            )
            if f.decoded_text and f.detector != "unicode":
                lines.append(f"        hidden decode: {_clean(repr(f.decoded_text))}")
            elif f.decoded_text and f.attack_class == AttackClass.HIDDEN_UNICODE:
                lines.append(f"        decodes to: {_clean(repr(f.decoded_text))}")
        summary = ", ".join(f"{counts[s]} {s.value}" for s in Severity if s in counts)
        lines.append("")
        lines.append(f"{len(ordered)} finding(s): {summary}")

    if report.leastpriv:
        lines.append("")
        lines.append("capability audit:")
        for lp in report.leastpriv:
            detail = f" ({_clean(lp.detail)})" if lp.detail else ""
            lines.append(
                f"  [{lp.severity.value.upper()}] {lp.issue.value}  "
                f"{_clean(lp.capability)}  {_clean(lp.message)}{detail}"
            )

    if report.remediations:
        lines.append("")
        lines.append("remediation (sanitized rewrites available):")
        for r in report.remediations:
            hidden = f"  decoded: {_clean(repr(r.decoded_tag_text))}" if r.decoded_tag_text else ""
            lines.append(
                f"  {_clean(r.surface)} {_clean(r.target)}: stripped {r.removed_invisible} "
                f"invisible char(s){hidden}"
            )

    if not report.findings and not report.leastpriv:
        lines.append("")
        lines.append("No findings. (clean)")
    return "\n".join(lines)


def render_json(report: Report) -> str:
    """Machine-readable JSON with enums as their string values."""

    def finding_dict(f: Finding) -> dict:
        d = asdict(f)
        d["attack_class"] = f.attack_class.value
        d["severity"] = f.severity.value
        return d

    def lp_dict(lp: LeastPrivFinding) -> dict:
        return {
            "issue": lp.issue.value,
            "severity": lp.severity.value,
            "capability": lp.capability,
            "message": lp.message,
            "detail": lp.detail,
        }

    doc = {
        "target": report.target,
        "items_scanned": report.items_scanned,
        "judge_used": report.judge_used,
        "judge_available": report.judge_available,
        "judge_requested": report.judge_requested,
        "findings": [finding_dict(f) for f in report.findings],
        "least_privilege": [lp_dict(lp) for lp in report.leastpriv],
        "remediations": [
            {
                "target": r.target,
                "surface": r.surface,
                "removed_invisible": r.removed_invisible,
                "decoded_tag_text": r.decoded_tag_text,
                "sanitized": r.sanitized,
            }
            for r in report.remediations
        ],
        "errors": report.errors,
    }
    return json.dumps(doc, indent=2)


def render_sarif(report: Report) -> dict:
    """SARIF 2.1.0 document."""
    used_classes: list[AttackClass] = []
    seen: set[AttackClass] = set()
    for f in report.findings:
        if f.attack_class not in seen:
            seen.add(f.attack_class)
            used_classes.append(f.attack_class)

    rules = [
        {
            "id": ac.value,
            "name": ac.name,
            "shortDescription": {"text": ac.value.replace("_", " ")},
            "defaultConfiguration": {"level": _DEFAULT_LEVEL[ac].value},
        }
        for ac in used_classes
    ]

    results = []
    for f in report.findings:
        location = {"physicalLocation": {"artifactLocation": {"uri": _artifact_uri(f)}}}
        if f.span is not None and isinstance(f.span.start, int) and isinstance(f.span.end, int):
            location["physicalLocation"]["region"] = {
                "charOffset": f.span.start,
                "charLength": f.span.end - f.span.start,
                "snippet": {"text": f.span.text},
            }
        message = f.message
        if f.evidence:
            message = f"{f.message}: {f.evidence}"
        results.append(
            {
                "ruleId": f.attack_class.value,
                "level": f.severity.value,
                "message": {"text": message},
                "locations": [location],
            }
        )

    # Least-privilege findings become SARIF results too, anchored to a synthetic
    # capability URI (no text region).
    seen_issues: set[str] = set()
    for lp in report.leastpriv:
        if lp.issue.value not in seen_issues:
            seen_issues.add(lp.issue.value)
            rules.append(
                {
                    "id": lp.issue.value,
                    "name": lp.issue.name,
                    "shortDescription": {"text": lp.issue.value.replace("_", " ")},
                    "defaultConfiguration": {"level": lp.severity.value},
                }
            )
        message = lp.message + (f": {lp.detail}" if lp.detail else "")
        results.append(
            {
                "ruleId": lp.issue.value,
                "level": lp.severity.value,
                "message": {"text": message},
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": f"capability:{lp.capability}"}}}
                ],
            }
        )

    return {
        "$schema": _SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "airlock",
                        "informationUri": _INFO_URI,
                        "version": _VERSION,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def _artifact_uri(f: Finding) -> str:
    if f.surface in ("prompt", "tool"):
        return f"{f.surface}:{f.target}"
    return f.target


# Compact JSON Schema for the SARIF subset we emit. Enough to validate structure
# offline without fetching or vendoring the full 200KB upstream schema.
SARIF_SUBSET_SCHEMA: dict = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["version", "runs"],
    "properties": {
        "$schema": {"type": "string"},
        "version": {"const": "2.1.0"},
        "runs": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["tool", "results"],
                "properties": {
                    "tool": {
                        "type": "object",
                        "required": ["driver"],
                        "properties": {
                            "driver": {
                                "type": "object",
                                "required": ["name"],
                                "properties": {"name": {"type": "string"}},
                            }
                        },
                    },
                    "results": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["ruleId", "level", "message", "locations"],
                            "properties": {
                                "ruleId": {"type": "string"},
                                "level": {
                                    "enum": ["none", "note", "warning", "error"]
                                },
                                "message": {
                                    "type": "object",
                                    "required": ["text"],
                                    "properties": {"text": {"type": "string"}},
                                },
                                "locations": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "required": ["physicalLocation"],
                                        "properties": {
                                            "physicalLocation": {
                                                "type": "object",
                                                "required": ["artifactLocation"],
                                                "properties": {
                                                    "artifactLocation": {
                                                        "type": "object",
                                                        "required": ["uri"],
                                                        "properties": {
                                                            "uri": {"type": "string"}
                                                        },
                                                    },
                                                    "region": {
                                                        "type": "object",
                                                        "properties": {
                                                            "charOffset": {"type": "integer"},
                                                            "charLength": {"type": "integer"},
                                                        },
                                                    },
                                                },
                                            }
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
    },
}


def validate_sarif(doc: dict) -> None:
    """Validate a SARIF document against the subset schema. Raises on invalid."""
    Draft202012Validator(SARIF_SUBSET_SCHEMA).validate(doc)
