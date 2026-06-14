# -*- coding: utf-8 -*-
"""Signal detection: compile the behaviour-class catalogue and scan a SkillDoc.

Each fired signal is a Signal(id, weight, tier, category, snippet). Snippets are
the REAL matched substring (collapsed, truncated) so evidence can be verified
against the file. Regex compilation is defensive: a bad pattern is skipped, never
crashes the engine.
"""

import re
import sys

from engine import constants as C
from engine import entropy
from engine import normalize


class Signal(object):
    __slots__ = ("id", "weight", "tier", "category", "snippet")

    def __init__(self, sid, weight, tier, category, snippet):
        self.id = sid
        self.weight = weight
        self.tier = tier
        self.category = category
        self.snippet = snippet


_FLAGS = re.IGNORECASE
_COMPILED = []          # list of (spec, compiled_or_pair)
_PRIMITIVE_RE = None


def _compile_all():
    global _PRIMITIVE_RE
    for spec in C.SIGNALS:
        try:
            if spec["kind"] == "single":
                comp = re.compile(spec["pattern"], _FLAGS)
                _COMPILED.append((spec, comp))
            else:  # cooccur
                a = re.compile(spec["pattern_a"], _FLAGS)
                b = re.compile(spec["pattern_b"], _FLAGS)
                _COMPILED.append((spec, (a, b)))
        except re.error as exc:  # pragma: no cover - defensive
            sys.stderr.write("WARN: bad signal %s: %s\n" % (spec.get("id"), exc))
    try:
        _PRIMITIVE_RE = re.compile(C.PRIMITIVE_PATTERN, _FLAGS)
    except re.error as exc:  # pragma: no cover
        sys.stderr.write("WARN: bad PRIMITIVE_PATTERN: %s\n" % exc)
        _PRIMITIVE_RE = None


_compile_all()


def _text_for_scope(doc, scope):
    if scope == "md":
        return doc.md
    if scope == "code":
        return doc.code
    return doc.all_text


def _cooccur_snippet(text, a_re, b_re, window):
    """Return the matched A-substring if an A match co-occurs with a B match.

    window=None means "anywhere in the same text". Otherwise the two matches must
    start within ``window`` characters of each other.
    """
    a_matches = list(a_re.finditer(text))
    if not a_matches:
        return None
    b_matches = list(b_re.finditer(text))
    if not b_matches:
        return None
    if window is None:
        return a_matches[0].group(0)
    b_starts = [m.start() for m in b_matches]
    for am in a_matches:
        for bs in b_starts:
            if abs(am.start() - bs) <= window:
                return am.group(0)
    return None


def scan(doc):
    """Return a list of fired Signals for the SkillDoc (deterministic order)."""
    fired = []

    # --- regex catalogue --------------------------------------------------- #
    for spec, comp in _COMPILED:
        text = _text_for_scope(doc, spec.get("scope", "all"))
        if not text:
            continue
        snippet = None
        if spec["kind"] == "single":
            m = comp.search(text)
            if m:
                snippet = m.group(0)
        else:
            a_re, b_re = comp
            snippet = _cooccur_snippet(text, a_re, b_re, spec.get("window"))
        if snippet is not None:
            fired.append(Signal(spec["id"], spec["weight"], spec["tier"],
                                spec["category"], normalize.collapse_ws(snippet)))

    # --- dynamic / non-regex signals -------------------------------------- #
    # Zero-width / bidi smuggling.
    if doc.has_zero_width:
        d = C.DYN_SIGNALS["S_zero_width"]
        fired.append(Signal("S_zero_width", d["weight"], d["tier"],
                            d["category"], "(invisible characters)"))

    # Long high-entropy obfuscation blob.
    blob = entropy.find_high_entropy_blob(doc.all_text, C.ENTROPY_MIN_LEN,
                                          C.ENTROPY_MIN_BITS)
    if blob is not None:
        d = C.DYN_SIGNALS["S_high_entropy_blob"]
        snip = blob[:40] + "…" if len(blob) > 40 else blob
        fired.append(Signal("S_high_entropy_blob", d["weight"], d["tier"],
                            d["category"], snip))

    # Bundled raw executable.
    if doc.bundled_binaries:
        d = C.DYN_SIGNALS["S_bundled_binary"]
        fired.append(Signal("S_bundled_binary", d["weight"], d["tier"],
                            d["category"], ", ".join(doc.bundled_binaries[:3])))

    # Split logic: malicious primitive in helper code but NOT in the prose.
    if _PRIMITIVE_RE is not None and doc.code:
        cm = _PRIMITIVE_RE.search(doc.code)
        if cm and not _PRIMITIVE_RE.search(doc.md):
            d = C.DYN_SIGNALS["S_split_logic"]
            fired.append(Signal("S_split_logic", d["weight"], d["tier"],
                                d["category"], normalize.collapse_ws(cm.group(0))))

    # Homoglyph / mixed-script smuggling (Cyrillic/Greek look-alikes in a
    # would-be-Latin command or URL).
    hg = normalize.find_homoglyph(doc.all_text)
    if hg is not None:
        d = C.DYN_SIGNALS["S_homoglyph"]
        fired.append(Signal("S_homoglyph", d["weight"], d["tier"],
                            d["category"], normalize.collapse_ws(hg)[:60]))
        # Deconfuse and re-run the catalogue: a homoglyph'd "сurl|bash" becomes
        # a real "curl|bash" the execution-primitive patterns can now catch.
        deconf = normalize.deconfuse(doc.all_text)
        for spec, comp in _COMPILED:
            if spec["kind"] == "single":
                m = comp.search(deconf)
                snip = m.group(0) if m else None
            else:
                a_re, b_re = comp
                snip = _cooccur_snippet(deconf, a_re, b_re, spec.get("window"))
            if snip is not None:
                fired.append(Signal(spec["id"], spec["weight"], spec["tier"],
                                    spec["category"], normalize.collapse_ws(snip)))

    # Recursive decode: a real execution/exfil primitive hidden inside a
    # base64/hex blob (decode-and-rescan).
    if _PRIMITIVE_RE is not None:
        for decoded in entropy.iter_decoded_candidates(doc.all_text):
            pm = _PRIMITIVE_RE.search(decoded)
            if pm:
                d = C.DYN_SIGNALS["S_decoded_payload"]
                fired.append(Signal("S_decoded_payload", d["weight"], d["tier"],
                                    d["category"],
                                    normalize.collapse_ws(pm.group(0))[:60]))
                break

    # Manifest / structural signals (AST03/04/06/07/10): parsed from
    # manifest.json + frontmatter, independent of the prose/code regex layer.
    # Lazy import avoids a circular dependency (manifest imports Signal here).
    from engine import manifest
    for sig in manifest.scan(doc):
        fired.append(sig)

    return fired
