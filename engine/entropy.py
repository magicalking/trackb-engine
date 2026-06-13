# -*- coding: utf-8 -*-
"""Shannon entropy + long high-entropy (base64/hex) blob detection.

A single long, high-entropy token is a weak obfuscation modifier on its own
(benign skills legitimately embed base64 images / config). It only matters when
combined with decode-and-execute behaviour, which the scoring layer handles via
the synergy bonus.
"""

import math
import re

# Contiguous base64/hex-ish token (the alphabet that long encoded blobs use).
_BLOB_RE = re.compile(r"[A-Za-z0-9+/=_-]{120,}")


def shannon_entropy(s):
    """Shannon entropy in bits/char for the string ``s``."""
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    h = 0.0
    for c in counts.values():
        p = c / n
        h -= p * math.log2(p)
    return h


def find_high_entropy_blob(text, min_len, min_bits):
    """Return the first (snippet) of a long high-entropy blob, or None.

    Only the first qualifying blob is returned; scanning is bounded by the regex
    itself so this is cheap and ReDoS-safe.
    """
    for m in _BLOB_RE.finditer(text):
        token = m.group(0)
        if len(token) >= min_len and shannon_entropy(token) >= min_bits:
            return token
    return None
