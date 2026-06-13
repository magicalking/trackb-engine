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
