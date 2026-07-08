"""Shared data models: Finding, Severity, AttackClass, Span, ScanTarget, Report.

Phase 1 vocabulary. The scanner, the report writers, and later the Phase 2
sanitizer share these types. Enum string values are stable on purpose: Severity
values equal the SARIF level strings, and AttackClass values become SARIF ruleIds
and the Phase 2 sanitizer category names.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Finding severity. Values equal SARIF `level` strings, so no mapping table."""

    NONE = "none"
    NOTE = "note"
    WARNING = "warning"
    ERROR = "error"


# Ordering for rollups and exit-code thresholds.
_SEVERITY_ORDER = {
    Severity.NONE: 0,
    Severity.NOTE: 1,
    Severity.WARNING: 2,
    Severity.ERROR: 3,
}


def severity_rank(severity: Severity) -> int:
    return _SEVERITY_ORDER[severity]


class AttackClass(str, Enum):
    """The attack taxonomy. Values map onto the Phase 2 sanitizer categories."""

    INSTRUCTION_OVERRIDE = "instruction_override"
    DATA_EXFILTRATION = "data_exfiltration"
    TOOL_SHADOWING = "tool_shadowing"
    HIDDEN_UNICODE = "hidden_unicode"  # zero-width and unicode tag characters
    HOMOGLYPH = "homoglyph"  # mixed-script confusable tokens
    CONDITIONAL_PAYLOAD = "conditional_payload"  # sleeper / "when the user next..."


class LeastPrivIssue(str, Enum):
    """Capability-hygiene issues from the least-privilege auditor."""

    UNUSED_CAPABILITY = "unused_capability"  # declares a primitive, exposes none
    UNBACKED_SUBSCRIBE = "unbacked_subscribe"  # resources.subscribe with no resources
    UNBACKED_LIST_CHANGED = "unbacked_list_changed"  # listChanged with no primitive
    EXPERIMENTAL_CAPABILITY = "experimental_capability"  # undocumented surface
    UNBACKED_COMPLETIONS = "unbacked_completions"  # completions with nothing to complete


# The convention's namespace key (spec/convention.md section 10). Provenance lives
# under this key inside a content item's `_meta`.
PROVENANCE_NAMESPACE = "x-mcp-provenance/v0"


class Origin(str, Enum):
    """Where emitted content came from (convention section 4)."""

    AUTHOR = "author"  # written by the server operator
    USER = "user"  # supplied by the end user
    EXTERNAL = "external"  # fetched from a third party
    DERIVED = "derived"  # computed or transformed from other content


class Trust(str, Enum):
    """What the client enforces (convention section 4)."""

    TRUSTED = "trusted"  # the agent may act on it
    UNTRUSTED = "untrusted"  # data only
    QUARANTINED = "quarantined"  # actively suspicious; not shown to the model


# Strictness ordering: a tagging server MAY override toward stricter, MUST NOT
# override toward more permissive.
_TRUST_STRICTNESS = {Trust.TRUSTED: 0, Trust.UNTRUSTED: 1, Trust.QUARANTINED: 2}


def trust_strictness(trust: Trust) -> int:
    return _TRUST_STRICTNESS[trust]


# Default origin -> trust mapping (convention section 4).
_ORIGIN_TRUST = {
    Origin.AUTHOR: Trust.TRUSTED,
    Origin.USER: Trust.UNTRUSTED,
    Origin.EXTERNAL: Trust.UNTRUSTED,
    Origin.DERIVED: Trust.UNTRUSTED,  # derived inherits the lowest trust of its inputs
}


def default_trust(origin: Origin) -> Trust:
    return _ORIGIN_TRUST[origin]


@dataclass(frozen=True)
class Integrity:
    """Content integrity block (convention section 6)."""

    alg: str = "sha-256"
    hash: str = ""  # base64 of the hash over the emitted content body
    signature: str | None = None  # base64 keyed-MAC or Ed25519 signature over the label
    sig_alg: str | None = None  # "hmac-sha256" | "ed25519"; None means unsigned/legacy-hmac
    keyid: str | None = None  # optional key identifier for public-key discovery


@dataclass(frozen=True)
class Provenance:
    """Item-level provenance (convention section 5)."""

    origin: Origin
    trust: Trust
    source: str | None = None  # informational only; never used for trust decisions
    fenced: bool = False
    integrity: Integrity | None = None
    # SEP-1913-aligned hints (convention section 5.1). Mirror the MCP trust-annotation
    # vocabulary so a standard-aware client can read our provenance; None means unset.
    open_world_hint: bool | None = None  # untrusted / external data source
    sensitive_hint: str | None = None  # "low" | "medium" | "high"
    private_hint: bool | None = None  # content contains private data


@dataclass(frozen=True)
class Span:
    """A character range into the scanned text and the exact matched substring."""

    start: int
    end: int  # exclusive
    text: str


@dataclass(frozen=True)
class Finding:
    """One detection. `span` is the exact offending evidence span when available."""

    attack_class: AttackClass
    severity: Severity
    surface: str  # "resource" | "prompt"
    target: str  # the MCP identifier: resource URI or prompt name
    detector: str  # "unicode" | "pattern" | "judge"
    message: str
    evidence: str
    span: Span | None = None
    decoded_text: str | None = None  # recovered ASCII for smuggled unicode
    confidence: float | None = None  # judge only; local detectors leave None


@dataclass(frozen=True)
class LeastPrivFinding:
    """A capability a server advertises but does not appear to exercise."""

    issue: LeastPrivIssue
    severity: Severity
    capability: str  # e.g. "prompts", "resources.subscribe"
    message: str
    detail: str = ""


@dataclass
class ScanTarget:
    """A fetched item the detectors run on."""

    surface: str  # "resource" | "prompt" | "tool"
    identifier: str  # URI, prompt name, or tool name
    text: str
    meta: dict | None = None  # the item's `_meta`, when the server emitted one


@dataclass(frozen=True)
class Remediation:
    """A proposed sanitized rewrite for an item that carried invisible payloads."""

    target: str
    surface: str
    removed_invisible: int
    decoded_tag_text: list[str]
    sanitized: str


@dataclass
class Report:
    """The result of scanning or auditing one server."""

    target: str  # the scanned stdio script path or http URL
    findings: list[Finding] = field(default_factory=list)
    items_scanned: int = 0
    judge_used: bool = False
    judge_available: bool = False
    judge_requested: bool = False  # a semantic judge was asked for (mode != off)
    errors: list[str] = field(default_factory=list)
    leastpriv: list[LeastPrivFinding] = field(default_factory=list)
    remediations: list[Remediation] = field(default_factory=list)

    @property
    def worst_severity(self) -> Severity:
        worst = Severity.NONE
        severities = [f.severity for f in self.findings] + [
            f.severity for f in self.leastpriv
        ]
        for severity in severities:
            if severity_rank(severity) > severity_rank(worst):
                worst = severity
        return worst
