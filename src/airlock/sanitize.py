"""The shared invisible-unicode sanitizer.

One source of truth for the invisible-unicode knowledge, used by both the Phase 1
scanner (to detect) and the Phase 2 provenance library (to strip at emit time), so
the scanner and the tagger share one sanitizer.

`strip_invisible` removes every invisible/format character, not just a hand-picked
list: any Unicode `Cf` (format) character, plus the variation-selector ranges, plus
the Unicode Tag block. Tag characters are additionally decoded back to the ASCII
they carried, for reporting. This is deliberately aggressive: untrusted content has
no legitimate need for format controls (including ZWJ emoji sequences or bidi
marks), and letting any of them survive into the emitted body would let a hidden
instruction ride into the hash and the model's context. Homoglyphs are NOT rewritten
here: they are visible characters and silently normalizing them would corrupt
legitimate non-Latin text; homoglyphs are handled by detection and quarantine.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

# C0/C1 control characters (incl. ESC 0x1b, CR, LF, BEL). A hostile server controls tool /
# resource / prompt names and other declared strings; printed to a terminal or log unescaped
# they can emit ANSI escape sequences or forge extra output lines (terminal/log injection).
# Every human renderer strips them from every server-controlled field before display. One
# source of truth so a new renderer cannot silently miss the fix (audit H5).
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def strip_control(s: object) -> str:
    """Remove terminal/log-forging control characters from a server-controlled string."""
    return _CONTROL_CHARS.sub("", str(s))

# Well-known zero-width and invisible characters, named for the scanner's detection
# and evidence labeling. `strip_invisible` removes a strictly larger set (all Cf).
ZERO_WIDTH: frozenset[int] = frozenset(
    {
        0x200B,  # ZERO WIDTH SPACE
        0x200C,  # ZERO WIDTH NON-JOINER
        0x200D,  # ZERO WIDTH JOINER
        0xFEFF,  # ZERO WIDTH NO-BREAK SPACE (BOM)
        0x2060,  # WORD JOINER
        0x00AD,  # SOFT HYPHEN
        0x180E,  # MONGOLIAN VOWEL SEPARATOR
        0x2061,  # FUNCTION APPLICATION
        0x2062,  # INVISIBLE TIMES
        0x2063,  # INVISIBLE SEPARATOR
        0x2064,  # INVISIBLE PLUS
        0x200E,  # LEFT-TO-RIGHT MARK
        0x200F,  # RIGHT-TO-LEFT MARK
        0x061C,  # ARABIC LETTER MARK
        0x202A,  # LEFT-TO-RIGHT EMBEDDING
        0x202B,  # RIGHT-TO-LEFT EMBEDDING
        0x202C,  # POP DIRECTIONAL FORMATTING
        0x202D,  # LEFT-TO-RIGHT OVERRIDE
        0x202E,  # RIGHT-TO-LEFT OVERRIDE
        0x2066,  # LEFT-TO-RIGHT ISOLATE
        0x2067,  # RIGHT-TO-LEFT ISOLATE
        0x2068,  # FIRST STRONG ISOLATE
        0x2069,  # POP DIRECTIONAL ISOLATE
    }
)

# Unicode Tag characters: printable ASCII smuggled invisibly. The block spans
# U+E0000..U+E007F; U+E0020..U+E007E map to ASCII 0x20..0x7E via -0xE0000.
TAG_START = 0xE0000
TAG_END = 0xE0080  # exclusive

# Variation selectors (Mn, not Cf) can carry smuggled data and are invisible.
_VS_RANGES = ((0xFE00, 0xFE0F), (0xE0100, 0xE01EF))


def decode_tag_char(codepoint: int) -> str | None:
    """Return the ASCII a tag codepoint carries, or None if not a printable tag."""
    if TAG_START <= codepoint < TAG_END:
        ascii_cp = codepoint - TAG_START
        if 0x20 <= ascii_cp <= 0x7E:
            return chr(ascii_cp)
    return None


def _is_variation_selector(cp: int) -> bool:
    return any(lo <= cp <= hi for lo, hi in _VS_RANGES)


def _is_strippable_invisible(ch: str, cp: int) -> bool:
    """True for any invisible/format char to strip (excluding the tag block, which is
    handled separately so its ASCII can be decoded).

    Also strips lone surrogates (category Cs): they are invalid, invisible, and would
    make the emitted body non-UTF-8-encodable. A legitimate astral character is a
    single non-surrogate code point in a Python str, so this only removes garbage.
    """
    if _is_variation_selector(cp):
        return True
    return unicodedata.category(ch) in ("Cf", "Cs")


@dataclass
class SanitizeResult:
    """The cleaned text plus a record of what was stripped."""

    text: str
    removed_zero_width: int = 0  # count of all stripped invisible/format chars
    decoded_tag_text: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return self.removed_zero_width > 0 or bool(self.decoded_tag_text)

    @property
    def had_smuggled_instructions(self) -> bool:
        """True when tag-character smuggling (a decoded instruction channel) was found."""
        return bool(self.decoded_tag_text)


def strip_invisible(text: str) -> SanitizeResult:
    """Remove every invisible/format and tag character. Return cleaned text + record.

    Tag runs separated only by other invisible characters are merged into one decoded
    string, so an instruction smuggled via tag characters cannot evade the decode by
    interposing a zero-width character.
    """
    # Fast path: pure-ASCII text has nothing to strip or decode. Every strippable code
    # point - the whole Cf/Cs categories, the variation-selector ranges, the Tag block, and
    # SOFT HYPHEN (U+00AD) - is >= U+0080, so no character in 0x00..0x7F is ever removed or
    # tag-decoded. `str.isascii()` is a single C-level scan, which collapses the common case
    # (English / JSON / code) from a per-character Python loop (~325 us/KB) to ~sub-us/KB.
    # This returns a result byte-identical to the full path for any ASCII input (proven by
    # the fuzz test in tests/test_resilience.py), so it changes performance, not behavior.
    if text.isascii():
        return SanitizeResult(text=text)
    out: list[str] = []
    removed = 0
    decoded_runs: list[str] = []
    current_tag_run: list[str] = []

    def flush_tag_run() -> None:
        if current_tag_run:
            decoded_runs.append("".join(current_tag_run))
            current_tag_run.clear()

    for ch in text:
        cp = ord(ch)
        # Tag block: strip, and decode the ASCII it carries. Do not flush, so runs
        # split by other invisibles still decode as one message.
        if TAG_START <= cp < TAG_END:
            decoded = decode_tag_char(cp)
            if decoded is not None:
                current_tag_run.append(decoded)
            continue
        # Any other invisible/format character: strip. Do not flush (see above).
        if _is_strippable_invisible(ch, cp):
            removed += 1
            continue
        # A visible character ends any pending tag run and is kept.
        flush_tag_run()
        out.append(ch)
    flush_tag_run()

    return SanitizeResult(
        text="".join(out),
        removed_zero_width=removed,
        decoded_tag_text=decoded_runs,
    )
