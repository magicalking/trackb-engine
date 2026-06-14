# -*- coding: utf-8 -*-
"""Shannon entropy + long high-entropy (base64/hex) blob detection.

A single long, high-entropy token is a weak obfuscation modifier on its own
(benign skills legitimately embed base64 images / config). It only matters when
combined with decode-and-execute behaviour, which the scoring layer handles via
the synergy bonus.
"""

import base64
import math
import re

# Contiguous base64/hex-ish token (the alphabet that long encoded blobs use).
_BLOB_RE = re.compile(r"[A-Za-z0-9+/=_-]{120,}")

# Candidate encoded blobs for recursive decode-and-rescan (shorter threshold:
# a hidden "curl x|bash" base64 is only ~40-80 chars).
_B64_CAND_RE = re.compile(r"[A-Za-z0-9+/=_-]{40,}")
_HEX_CAND_RE = re.compile(r"\b[0-9a-fA-F]{40,}\b")


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


def iter_decoded_candidates(text, max_blobs=24, max_decode_bytes=8192):
    """Yield UTF-8 views of base64/hex-decoded blobs found in ``text`` (bounded).

    Used to recover a payload hidden inside an encoded blob (decode-and-rescan).
    Decoding never raises; non-decodable / tiny blobs are skipped. Total work is
    capped by ``max_blobs`` and ``max_decode_bytes`` so this stays cheap.
    """
    if not text:
        return
    seen = 0
    for m in _B64_CAND_RE.finditer(text):
        if seen >= max_blobs:
            break
        s = m.group(0).replace("-", "+").replace("_", "/")
        s = re.sub(r"[^A-Za-z0-9+/]", "", s)
        if len(s) < 40:
            continue
        s += "=" * ((-len(s)) % 4)
        try:
            raw = base64.b64decode(s, validate=False)[:max_decode_bytes]
        except (ValueError, TypeError):
            continue
        if not raw:
            continue
        seen += 1
        yield raw.decode("utf-8", "replace")
    for m in _HEX_CAND_RE.finditer(text):
        if seen >= max_blobs:
            break
        h = m.group(0)
        if len(h) % 2:
            h = h[:-1]
        try:
            raw = bytes.fromhex(h)[:max_decode_bytes]
        except ValueError:
            continue
        if not raw:
            continue
        seen += 1
        yield raw.decode("utf-8", "replace")
