"""Local detectors: keyword patterns and invisible-unicode checks.

Pure functions over text, no I/O, no network. This is the always-free core of the
scanner. The taxonomy modeled here is exercised by fixtures/vulnerable_server.py:
instruction override, exfiltration, tool shadowing, hidden or invisible payloads
(zero-width, unicode tag chars, homoglyphs), and conditional or sleeper payloads.

The orchestrator (`scan_text`) runs the local detectors over the visible text, then
decodes any invisible unicode tag-character runs and re-runs the pattern detectors
over the recovered text, so an instruction smuggled through invisible characters is
caught by its meaning, not merely flagged as "invisible characters present".
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
from collections.abc import Iterable
from dataclasses import replace
from functools import lru_cache

from airlock.models import AttackClass, Finding, Severity, Span, severity_rank

# The invisible-unicode knowledge is owned by the shared sanitizer, so the scanner
# (detect) and the provenance library (strip) stay in lockstep.
from airlock.sanitize import TAG_END as _TAG_END
from airlock.sanitize import TAG_START as _TAG_START
from airlock.sanitize import _is_strippable_invisible, strip_invisible


def _is_invisible_nontag(cp: int, ch: str) -> bool:
    """An invisible/format character the sanitizer would strip, excluding the Unicode
    Tag block (decoded separately in step 2). Deriving detection from the sanitizer's
    own predicate keeps the scanner in lockstep with `strip_invisible` (all Cf + the
    variation selectors + surrogates), rather than a hand-picked subset that would let
    the scanner miss an invisible the emitter strips."""
    if _TAG_START <= cp < _TAG_END:
        return False
    return _is_strippable_invisible(ch, cp)


def _invisible_runs(text: str):
    """Yield (start, end, run) for each maximal run of invisible non-tag characters."""
    start: int | None = None
    for i, ch in enumerate(text):
        if _is_invisible_nontag(ord(ch), ch):
            if start is None:
                start = i
        elif start is not None:
            yield start, i, text[start:i]
            start = None
    if start is not None:
        yield start, len(text), text[start:]

# Incidental invisibles with legitimate everyday uses: emoji variation selectors and the
# soft hyphen. A short run made ONLY of these is not itself a smuggling signal (an emoji in a
# description, a discretionary hyphen); the strip-and-rescan path still catches a keyword split
# by one. Report only when a run also contains a genuinely suspicious invisible, or is long
# enough to be a variation-selector data payload.
_BENIGN_INVISIBLE = frozenset({0x00AD}) | frozenset(range(0xFE00, 0xFE10)) | frozenset(range(0xE0100, 0xE01F0))


def _run_reportable(run: str) -> bool:
    if any(ord(c) not in _BENIGN_INVISIBLE for c in run):
        return True
    return len(run) > 4  # a long run of variation selectors can encode a payload


# Scripts that are commonly confused with Latin. A token mixing any two of these
# is a homoglyph attack signal.
_CONFUSABLE_SCRIPTS = frozenset({"LATIN", "CYRILLIC", "GREEK"})

# Cyrillic / Greek code points that are visual LOOK-ALIKES of Latin letters (the real
# homoglyph attack surface). A mixed-script token is flagged only when it contains one of
# these, so a legitimate non-Latin symbol (a Greek delta used as a math sign) is not a FP.
_LATIN_CONFUSABLES = frozenset({
    # Cyrillic lowercase a e o p c y x s i j ...
    0x0430, 0x0435, 0x043E, 0x0440, 0x0441, 0x0443, 0x0445, 0x0455, 0x0456, 0x0458, 0x051B, 0x051D,
    # Cyrillic uppercase A B E K M H O P C T Y X S I J
    0x0410, 0x0412, 0x0415, 0x041A, 0x041C, 0x041D, 0x041E, 0x0420, 0x0421, 0x0422, 0x0423,
    0x0425, 0x0405, 0x0406, 0x0408,
    # Greek lowercase a o v p (lunate sigma) c
    0x03B1, 0x03BF, 0x03BD, 0x03C1, 0x03F2,
    # Greek uppercase A B E Z H I K M N O P T Y X (lunate sigma) C
    0x0391, 0x0392, 0x0395, 0x0396, 0x0397, 0x0399, 0x039A, 0x039C, 0x039D, 0x039F, 0x03A1,
    0x03A4, 0x03A5, 0x03A7, 0x03F9,
})

_WORD_RE = re.compile(r"\w+", re.UNICODE)


def _script_of(ch: str) -> str | None:
    """Coarse script bucket for a letter, or None for non-letters."""
    if not ch.isalpha():
        return None
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return None
    return name.split(" ", 1)[0]


def detect_unicode(text: str, surface: str, target: str) -> tuple[list[Finding], list[str]]:
    """Detect invisible and confusable unicode. Returns (findings, decoded_strings).

    decoded_strings are the ASCII recovered from tag-character runs, for the
    orchestrator to re-scan.
    """
    findings: list[Finding] = []
    decoded_strings: list[str] = []

    # 1. Zero-width / invisible format character runs (all Cf + variation selectors +
    # surrogates, in lockstep with the sanitizer, not a hand-picked subset).
    for start, end, run in _invisible_runs(text):
        if not _run_reportable(run):
            continue  # a lone emoji variation selector or soft hyphen is not smuggling
        names = " ".join(f"U+{ord(c):04X}" for c in run)
        findings.append(
            Finding(
                attack_class=AttackClass.HIDDEN_UNICODE,
                severity=Severity.WARNING,
                surface=surface,
                target=target,
                detector="unicode",
                message="invisible zero-width characters present",
                evidence=f"<{len(run)} zero-width chars: {names}>",
                span=Span(start, end, run),
            )
        )

    # 2. Unicode Tag character runs. Decode to the smuggled ASCII.
    tag_run_start: int | None = None
    for i, ch in enumerate(text):
        is_tag = _TAG_START <= ord(ch) < _TAG_END
        if is_tag and tag_run_start is None:
            tag_run_start = i
        elif not is_tag and tag_run_start is not None:
            _emit_tag_run(text, tag_run_start, i, surface, target, findings, decoded_strings)
            tag_run_start = None
    if tag_run_start is not None:
        _emit_tag_run(text, tag_run_start, len(text), surface, target, findings, decoded_strings)

    # 3. Homoglyphs: tokens that mix confusable scripts within one word.
    for match in _WORD_RE.finditer(text):
        token = match.group(0)
        scripts = {s for s in (_script_of(c) for c in token) if s is not None}
        mixed = scripts & _CONFUSABLE_SCRIPTS
        if len(mixed) >= 2:
            confusables = [
                c for c in token
                if _script_of(c) in _CONFUSABLE_SCRIPTS
                and _script_of(c) != "LATIN"
                and ord(c) in _LATIN_CONFUSABLES
            ]
            if not confusables:
                continue  # mixed scripts but no Latin look-alike (e.g. a Greek math symbol)
            offenders = " ".join(f"{c!r} U+{ord(c):04X}" for c in confusables)
            normalized = unicodedata.normalize("NFKC", token)
            findings.append(
                Finding(
                    attack_class=AttackClass.HOMOGLYPH,
                    severity=Severity.WARNING,
                    surface=surface,
                    target=target,
                    detector="unicode",
                    message="mixed-script (homoglyph) token",
                    evidence=f"{token!r} mixes {', '.join(sorted(mixed))}: {offenders}",
                    span=Span(match.start(), match.end(), token),
                    decoded_text=normalized,
                )
            )

    return findings, decoded_strings


def _emit_tag_run(
    text: str,
    start: int,
    end: int,
    surface: str,
    target: str,
    findings: list[Finding],
    decoded_strings: list[str],
) -> None:
    run = text[start:end]
    decoded = "".join(chr(ord(c) - _TAG_START) for c in run if 0x20 <= ord(c) - _TAG_START <= 0x7E)
    findings.append(
        Finding(
            attack_class=AttackClass.HIDDEN_UNICODE,
            severity=Severity.ERROR,
            surface=surface,
            target=target,
            detector="unicode",
            message="invisible Unicode Tag characters decode to hidden text",
            evidence=(decoded[:120] + "...") if len(decoded) > 120 else decoded,
            span=Span(start, end, run),
            decoded_text=decoded,
        )
    )
    if decoded:
        decoded_strings.append(decoded)


# Pattern rules. Each entry: (AttackClass, Severity, compiled regex, message).
_INSTRUCTION_OVERRIDE_RULES: list[tuple[AttackClass, Severity, re.Pattern[str], str]] = [
    (
        AttackClass.INSTRUCTION_OVERRIDE,
        Severity.ERROR,
        re.compile(
            r"ignore\s+(?:all\s+)?(?:previous|prior|above|the\s+following)\s+"
            r"(?:instructions|rules|prompts?)",
            re.IGNORECASE,
        ),
        "instruction override: 'ignore previous instructions'",
    ),
    (
        AttackClass.INSTRUCTION_OVERRIDE,
        Severity.ERROR,
        re.compile(r"disregard\s+.{0,20}?(?:instructions|rules|prompts?)", re.IGNORECASE | re.DOTALL),
        "instruction override: 'disregard ...'",
    ),
    (
        AttackClass.INSTRUCTION_OVERRIDE,
        Severity.ERROR,
        re.compile(r"system\s*override", re.IGNORECASE),
        "instruction override: 'system override'",
    ),
    (
        AttackClass.INSTRUCTION_OVERRIDE,
        Severity.WARNING,
        re.compile(r"from\s+now\s+on\b", re.IGNORECASE),
        "instruction override: 'from now on'",
    ),
    # NOTE on English paraphrases: broad paraphrase cues ("forget everything you ...", "do not
    # follow the ...", "override your ...") were tried here but collide with ordinary tool docs
    # ("forget everything you know about the old API", "override the rule with a custom
    # matcher", "do not follow redirects") and produced CI-failing false positives at the
    # DETERMINISTIC layer. Semantic paraphrase detection is the LLM judge's job (judge.py); when
    # the judge is configured 'auto' but unavailable, the report emits an explicit NOTE that a
    # paraphrased/encoded injection may be missed (audit M4), so the residual is signalled rather
    # than silently swallowed. The deterministic layer keeps only HIGH-PRECISION cues: the
    # explicit "ignore/disregard/system override/from now on" family above, encoded payloads
    # (decode-and-rescan, below), and the non-English DIRECT TRANSLATIONS of "ignore previous
    # instructions" (which do not appear in ordinary English tool docs, so they stay low-FP):
    (
        AttackClass.INSTRUCTION_OVERRIDE,
        Severity.ERROR,
        re.compile(
            r"\b(?:ignora|ignora\w*|ignorez|ignoriere?n?|olvida|oubli\w*|vergiss|esque\w+|"
            r"non\s+seguire|ignorare)\b.{0,40}?"
            r"\b(?:instrucciones|instructions|anweisungen|instru\w+|istruzioni|"
            r"reglas|r[eè]gles|regeln|regras|regole)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        "instruction override: non-English 'ignore previous instructions'",
    ),
]

_EXFIL_VERB = r"(?:forward|send|email|e-mail|bcc|post|upload|exfiltrate|leak|transmit)"
# The local part is bounded (RFC 5321 caps it at 64) and possessive (`{1,64}+`,
# Python 3.11+): once the run is consumed it is never re-tried char-by-char at every
# start position when the required `@` is absent. That backtracking is what made the
# old `[...]+@` pattern O(n^2) on a long alphanumeric body from a hostile server (a
# scan denial-of-service). The domain is matched as dot-delimited labels, so the `.`
# delimiter is outside the label class and no cross-dot backtracking is needed.
_EMAIL = r"[A-Za-z0-9._%+\-]{1,64}+@(?:[A-Za-z0-9\-]{1,63}\.){1,64}[A-Za-z]{2,24}"
# Bounded and possessive (Python 3.11+): in the address-first exfil rule the URL token
# sits before the lazy verb window, so a greedy `[^\s"'>]+` would be re-tried at every
# `http://` start in a whitespace-free run and backtrack O(n^2). Possessive prevents the
# re-try; the bound caps per-position work. (RFC 3986 has no hard URL length; 2048 is a
# generous practical cap.)
_URL = r"https?://[^\s\"'>]{1,2048}+"

# Exfiltration: an address or URL near an exfil verb (either order, ~80 chars apart).
_EXFIL_RULES: list[tuple[AttackClass, Severity, re.Pattern[str], str]] = [
    (
        AttackClass.DATA_EXFILTRATION,
        Severity.ERROR,
        re.compile(rf"{_EXFIL_VERB}\b.{{0,80}}?(?:{_EMAIL}|{_URL})", re.IGNORECASE | re.DOTALL),
        "exfiltration directive to an address or URL",
    ),
    (
        AttackClass.DATA_EXFILTRATION,
        Severity.ERROR,
        re.compile(rf"(?:{_EMAIL}|{_URL}).{{0,80}}?{_EXFIL_VERB}\b", re.IGNORECASE | re.DOTALL),
        "exfiltration directive to an address or URL",
    ),
]

_CONDITIONAL_RULES: list[tuple[AttackClass, Severity, re.Pattern[str], str]] = [
    (
        AttackClass.CONDITIONAL_PAYLOAD,
        Severity.WARNING,
        re.compile(r"when(?:ever)?\s+the\s+user\s+next\b", re.IGNORECASE),
        "conditional/sleeper: 'when the user next ...'",
    ),
    (
        AttackClass.CONDITIONAL_PAYLOAD,
        Severity.WARNING,
        re.compile(
            r"\bthe\s+next\s+time\s+.{0,40}?\b(?:summari[sz]e|call|ask|run)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        "conditional/sleeper: 'the next time ...'",
    ),
    (
        AttackClass.CONDITIONAL_PAYLOAD,
        Severity.WARNING,
        re.compile(
            r"when\s+the\s+user\s+.{0,40}?\b(?:summari[sz]e|request|ask)s?\b.{0,40}?\balso\b",
            re.IGNORECASE | re.DOTALL,
        ),
        "conditional/sleeper: 'when the user ... also ...'",
    ),
]


# The name-independent tool-shadowing rule is compiled once at import, not rebuilt on
# every detect_patterns call (which runs per raw body AND per decoded/normalized rescan).
_CALL_X_INSTEAD_RULE: tuple[AttackClass, Severity, re.Pattern[str], str] = (
    AttackClass.TOOL_SHADOWING,
    Severity.ERROR,
    re.compile(r"\bcall\s+\w+\s+instead\b", re.IGNORECASE),
    "tool shadowing: 'call X instead'",
)


@lru_cache(maxsize=256)
def _tool_shadowing_rules(
    tool_names: tuple[str, ...],
) -> tuple[tuple[AttackClass, Severity, re.Pattern[str], str], ...]:
    """Rules for redirecting to a known tool. Memoized on the tool-name set so the
    name-dependent alternation regex is compiled once per server, not once per rescan
    (which was O(body x tool_count) recompilation, a hostile-server scan amplifier)."""
    names = [n for n in tool_names if n]
    rules = [_CALL_X_INSTEAD_RULE]
    if names:
        alt = "|".join(re.escape(n) for n in names)
        rules.append(
            (
                AttackClass.TOOL_SHADOWING,
                Severity.ERROR,
                re.compile(
                    r"(?:instead\s+of|rather\s+than|whenever\s+you\s+would|"
                    r"when\s+.{0,40}?\bcall\b).{0,60}?\b(?:" + alt + r")\b",
                    re.IGNORECASE | re.DOTALL,
                ),
                "tool shadowing: redirect to a known tool",
            )
        )
    return tuple(rules)


def detect_patterns(
    text: str,
    surface: str,
    target: str,
    tool_names: Iterable[str] = (),
) -> list[Finding]:
    """Run the compiled pattern rules over `text` and return findings with spans."""
    findings: list[Finding] = []
    rules = [
        *_INSTRUCTION_OVERRIDE_RULES,
        *_EXFIL_RULES,
        *_CONDITIONAL_RULES,
        *_tool_shadowing_rules(tuple(tool_names)),
    ]
    for attack_class, severity, pattern, message in rules:
        for match in pattern.finditer(text):
            matched = match.group(0)
            findings.append(
                Finding(
                    attack_class=attack_class,
                    severity=severity,
                    surface=surface,
                    target=target,
                    detector="pattern",
                    message=message,
                    evidence=matched,
                    span=Span(match.start(), match.end(), matched),
                )
            )
    return findings


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse findings on (attack_class, span range), keeping the highest severity."""
    from airlock.models import severity_rank

    best: dict[tuple, Finding] = {}
    for finding in findings:
        span = finding.span
        key = (
            finding.attack_class,
            None if span is None else (span.start, span.end),
            finding.detector,
            # Distinct instructions smuggled in one hidden/normalized run share an anchor
            # span, so include their recovered text in the key to keep them separate.
            finding.evidence if finding.decoded_text is not None else None,
        )
        current = best.get(key)
        if current is None or severity_rank(finding.severity) > severity_rank(current.severity):
            best[key] = finding
    return list(best.values())


# Decode-and-rescan: an injection can hide as a base64 / hex / rot13 blob the model is told
# to decode and follow. Recover candidates and rescan them by MEANING (audit M4). Bounded and
# best-effort so a hostile body cannot turn this into a scan DoS.
_B64_RUN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_RUN = re.compile(r"(?:[0-9A-Fa-f]{2}){8,}")
_MAX_DECODE_CANDIDATES = 40
_MAX_DECODE_CHARS = 20_000


def _printable_ascii(raw: bytes) -> str | None:
    """Decode bytes to ASCII iff the result is text (no binary control chars but tab/CR/LF)."""
    try:
        t = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    if any(ord(c) < 0x20 and c not in "\t\r\n" for c in t):
        return None
    return t if any(c.isalpha() for c in t) else None


def _decode_candidates(text: str) -> list[str]:
    """Recovered plaintext from rot13 / base64 / hex encodings present in `text`. Bounded."""
    out: list[str] = []
    try:  # rot13: a single whole-text transform; only yields English if the source was rot13'd
        rot = codecs.encode(text, "rot_13")
        if rot != text:
            out.append(rot)
    except Exception:  # noqa: BLE001
        pass
    budget = _MAX_DECODE_CHARS
    n = 0
    for pat, decoder in ((_B64_RUN, "b64"), (_HEX_RUN, "hex")):
        for m in pat.finditer(text):
            if n >= _MAX_DECODE_CANDIDATES or budget <= 0:
                break
            cand = m.group(0)
            try:
                if decoder == "b64":
                    if len(cand) % 4:
                        continue
                    raw = base64.b64decode(cand, validate=True)
                else:
                    if len(cand) % 2:
                        continue
                    raw = bytes.fromhex(cand)
            except (binascii.Error, ValueError):
                continue
            dec = _printable_ascii(raw)
            if dec:
                dec = dec[:budget]
                out.append(dec)
                budget -= len(dec)
                n += 1
    return out


def scan_text(
    text: str,
    surface: str,
    target: str,
    tool_names: Iterable[str] = (),
) -> list[Finding]:
    """Layered local scan of one text: unicode + patterns, then decode-and-rescan."""
    tool_names = tuple(tool_names)
    unicode_findings, decoded_strings = detect_unicode(text, surface, target)
    findings = list(unicode_findings)
    findings.extend(detect_patterns(text, surface, target, tool_names))

    # Re-run pattern detection over any decoded hidden text. The recovered spans
    # index into the decoded string, so anchor them to the tag run in the original
    # text (the earliest tag-char finding) and mark them as hidden.
    tag_spans = [
        f.span
        for f in unicode_findings
        if f.attack_class == AttackClass.HIDDEN_UNICODE and f.decoded_text and f.span
    ]
    anchor = tag_spans[0] if tag_spans else None
    for decoded in decoded_strings:
        for hidden in detect_patterns(decoded, surface, target, tool_names):
            findings.append(
                Finding(
                    attack_class=hidden.attack_class,
                    severity=hidden.severity,
                    surface=surface,
                    target=target,
                    detector="pattern",
                    message="hidden: " + hidden.message,
                    evidence=hidden.evidence,
                    span=anchor,
                    decoded_text=decoded,
                )
            )

    # Normalized rescan. The raw regexes are ASCII-anchored, so an attacker defeats them
    # by splitting a keyword with an invisible character ("ig<ZWSP>nore") or by using
    # NFKC-normalizable homoglyphs (fullwidth, compatibility forms) that fold to the ASCII
    # an LLM acts on. Strip invisibles and NFKC-fold, and if that changes the text, rescan
    # by meaning so the attack is caught at full severity instead of a mere WARNING (or a
    # silent clean). Offsets in the folded copy do not map back to the raw body (NFKC is
    # not length-preserving), so these findings carry no raw span; decoded_text records
    # what was recovered.
    normalized = unicodedata.normalize("NFKC", strip_invisible(text).text)
    if normalized != text:
        for recovered in detect_patterns(normalized, surface, target, tool_names):
            findings.append(
                Finding(
                    attack_class=recovered.attack_class,
                    severity=recovered.severity,
                    surface=surface,
                    target=target,
                    detector="pattern",
                    message="normalized: " + recovered.message,
                    evidence=recovered.evidence,
                    span=None,
                    decoded_text=normalized,
                )
            )

    # Decode-and-rescan: recover base64 / hex / rot13 payloads and rescan them by meaning, so
    # an encoded injection is caught at the class it decodes to, not missed (audit M4).
    for decoded in _decode_candidates(text):
        for rec in detect_patterns(decoded, surface, target, tool_names):
            findings.append(
                Finding(
                    attack_class=rec.attack_class,
                    severity=rec.severity,
                    surface=surface,
                    target=target,
                    detector="pattern",
                    message="decoded: " + rec.message,
                    evidence=rec.evidence,
                    span=None,
                    decoded_text=decoded,
                )
            )

    if surface == "tool":
        findings = _soften_tool_surface(findings, text)
    return _dedupe(findings)


# On a tool DESCRIPTION (author-declared documentation) these two classes are legitimate:
# an email/upload/webhook tool documents its own destination address or URL, and a tool
# routinely points at a sibling tool ("use search_web instead"). So they are not
# injection there on their own.
_TOOL_SOFTEN_CLASSES = (AttackClass.DATA_EXFILTRATION, AttackClass.TOOL_SHADOWING)

# An http(s) URL inside the exfil evidence. A legitimate tool documents a recipient PARAM or
# its own address; a description that directs data to a hardcoded external URL is not ordinary
# documentation, so it is kept CI-visible (see _soften_tool_surface).
_URL_IN_EVIDENCE = re.compile(r"https?://", re.IGNORECASE)
# An exfil VERB near an external URL anywhere in the full text. Checking the whole text (not
# just one finding's captured evidence) is what defeats a decoy email token that would
# otherwise steal the DATA_EXFILTRATION match and let the URL directive be softened (audit M7
# re-review). Bounded/possessive URL, so no ReDoS.
_EXFIL_TO_URL_TEXT = re.compile(
    rf"{_EXFIL_VERB}\b.{{0,80}}?{_URL}|{_URL}.{{0,80}}?{_EXFIL_VERB}\b",
    re.IGNORECASE | re.DOTALL,
)


def _soften_tool_surface(findings: list[Finding], text: str = "") -> list[Finding]:
    """Down-rank exfil / tool-shadowing findings on the tool surface, UNLESS the same text
    carries a cue that this is real tool poisoning rather than benign documentation.

    A bare documented destination (a send_email tool's own recipient, a sibling-tool
    reference) is legitimate on a tool description and softens to NOTE. But two shapes are
    NOT ordinary documentation and stay CI-visible (scan exits nonzero at >= WARNING):
      * a HARD cue in the same text - an instruction-override phrase OR a conditional/sleeper
        payload ("when the user next ...") - keeps every finding at FULL severity; and
      * an exfil directive pointing at an external http(s) URL is kept at >= WARNING (not
        collapsed to NOTE), because a hardcoded external collector URL in a tool description
        is the audit's M7 tool-poisoning shape, not a documented recipient.
    Exfil-to-an-email and tool-shadowing without a hard cue still soften to NOTE, so an
    ordinary send_email/upload description does not fail CI or flip prevalence."""
    hard_cues = (AttackClass.INSTRUCTION_OVERRIDE, AttackClass.CONDITIONAL_PAYLOAD)
    if any(f.attack_class in hard_cues for f in findings):
        return findings
    # Whether the FULL text directs data to an external URL (checked over the whole text so a
    # decoy email token cannot steal the finding's evidence and get the URL directive softened).
    exfil_to_url = bool(text and _EXFIL_TO_URL_TEXT.search(text))
    out: list[Finding] = []
    warn = severity_rank(Severity.WARNING)
    for f in findings:
        if f.attack_class in _TOOL_SOFTEN_CLASSES and severity_rank(f.severity) > severity_rank(Severity.NOTE):
            if f.attack_class == AttackClass.DATA_EXFILTRATION and (
                exfil_to_url or _URL_IN_EVIDENCE.search(f.evidence or "")
            ):
                # exfil-to-URL: keep visible + CI-failing, but below ERROR
                out.append(f if severity_rank(f.severity) <= warn else replace(f, severity=Severity.WARNING))
            else:
                out.append(replace(f, severity=Severity.NOTE))
        else:
            out.append(f)
    return out


def scan_targets(targets: Iterable, tool_names: Iterable[str] = ()) -> list[Finding]:
    """Scan a sequence of ScanTarget items and return all findings."""
    tool_names = tuple(tool_names)
    findings: list[Finding] = []
    for item in targets:
        findings.extend(scan_text(item.text, item.surface, item.identifier, tool_names))
    return findings
