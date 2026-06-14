# -*- coding: utf-8 -*-
"""Text normalisation: NFKC fold, strip/flag invisible characters, lowercase.

Regex scanning happens on the normalised text so that zero-width / bidi smuggled
characters cannot break a pattern. We still REPORT that such characters were
present (a detection signal in its own right).
"""

import re
import unicodedata

# Invisible / control code points used for prose smuggling & instruction
# injection. Range-based so it also covers the Unicode TAG block
# (U+E0000-U+E007F), which is invisible and a known way to hide agent
# instructions inside an otherwise-clean SKILL.md.
_ZERO_WIDTH_RE = re.compile(
    "["
    "­"                 # SOFT HYPHEN
    "​-‏"          # ZWSP ZWNJ ZWJ LRM RLM
    "‪-‮"          # LRE RLE PDF LRO RLO
    "⁠-⁤"          # WORD-JOINER, invisible operators
    "⁦-⁯"          # LRI RLI FSI PDI + deprecated format chars
    "﻿"                 # BOM / ZWNBSP
    "\U000e0000-\U000e007f"  # Unicode TAG block (instruction smuggling)
    "]")


class NormalizedText(object):
    """Holds the cleaned scanning view plus invisible-character flags."""

    __slots__ = ("text", "has_zero_width", "n_invisible")

    def __init__(self, text, has_zero_width, n_invisible):
        self.text = text
        self.has_zero_width = has_zero_width
        self.n_invisible = n_invisible


def normalize(raw):
    """Return a NormalizedText for ``raw`` (a str).

    - NFKC normalisation folds homoglyphs / full-width forms.
    - Invisible characters are counted, flagged, then removed from the scan view.
    - Result is safe to feed to case-insensitive regexes.
    """
    if not raw:
        return NormalizedText("", False, 0)
    try:
        folded = unicodedata.normalize("NFKC", raw)
    except (TypeError, ValueError):
        folded = raw
    invisible = _ZERO_WIDTH_RE.findall(folded)
    n_invisible = len(invisible)
    if n_invisible:
        folded = _ZERO_WIDTH_RE.sub("", folded)
    return NormalizedText(folded, n_invisible > 0, n_invisible)


_WS_RE = re.compile(r"\s+")


def collapse_ws(s):
    """Collapse all runs of whitespace to single spaces and strip."""
    return _WS_RE.sub(" ", s).strip()


# A run of letters drawn from Latin + Cyrillic + Greek blocks. A homoglyph
# attack mixes scripts WITHIN one token (e.g. "cur1" written with a Cyrillic
# "с"/"а") so the token looks like an English command/URL but evades a Latin
# regex. NFKC does NOT fold cross-script confusables, so we detect them here.
_MIXED_LETTER_RE = re.compile(r"[A-Za-zЀ-ӿͰ-Ͽ‐-―]{2,}")
_MAX_HOMOGLYPH_SCAN = 50000     # cap tokens scanned (ReDoS / perf guard)


# Cyrillic / Greek look-alikes -> their Latin twin, so a homoglyph'd command
# ("сurl ... | bаsh") can be re-scanned by the Latin execution-primitive regexes.
_CONFUSABLE_MAP = {
    "а": "a", "е": "e", "о": "o", "с": "c", "р": "p", "х": "x", "у": "y",
    "ѕ": "s", "і": "i", "ј": "j", "к": "k", "м": "m", "н": "h", "т": "t",
    "в": "b", "ԁ": "d", "ѵ": "v", "ӏ": "l", "ԛ": "q", "ԝ": "w", "г": "r",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X", "Υ": "Y",
    "ο": "o", "ρ": "p", "ν": "v", "α": "a", "ε": "e", "ι": "i", "κ": "k",
}
_CONFUSABLE_TRANS = {ord(k): v for k, v in _CONFUSABLE_MAP.items()}


def deconfuse(text):
    """Map common Cyrillic/Greek confusables to their Latin look-alike."""
    if not text:
        return text
    return text.translate(_CONFUSABLE_TRANS)


def find_homoglyph(text):
    """Return the first token mixing Latin with Cyrillic/Greek look-alikes.

    Pure-Latin and pure-Cyrillic tokens (legitimate multilingual content) are
    NOT flagged — only intra-token script mixing, which is the smuggling signal.
    Returns the offending token, or None.
    """
    if not text:
        return None
    scanned = 0
    for m in _MIXED_LETTER_RE.finditer(text):
        scanned += 1
        if scanned > _MAX_HOMOGLYPH_SCAN:
            break
        tok = m.group(0)
        has_latin = False
        has_confusable = False
        for ch in tok:
            o = ord(ch)
            if o < 128 and (("a" <= ch <= "z") or ("A" <= ch <= "Z")):
                has_latin = True
            elif 0x0400 <= o <= 0x04FF or 0x0370 <= o <= 0x03FF:
                has_confusable = True
            if has_latin and has_confusable:
                return tok
    return None
