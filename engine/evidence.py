# -*- coding: utf-8 -*-
"""Build the Chinese evidence string from a ScoreResult.

Structure: framing clause + top 1-3 fired signals (each with a real, quoted
matched snippet) + kill-chain note + suppression note. Benign verdicts get an
honest short note and never fabricate indicators. Hard length cap applied.
"""

from engine import constants as C


def _snip(text):
    t = text.strip()
    if len(t) > C.SNIPPET_MAX_CHARS:
        t = t[:C.SNIPPET_MAX_CHARS] + "…"
    return "「" + t + "」"


def _signal_clause(sig):
    tmpl = C.EVIDENCE_TEMPLATES.get(sig.id, C.GENERIC_POSITIVE_TEMPLATE)
    return tmpl.format(snip=_snip(sig.snippet))


def build(doc, res, category):
    """Return the evidence string."""
    if res.verdict == "benign":
        parts = []
        if doc.empty:
            return C.EMPTY_EVIDENCE
        if res.fired:
            parts.append(C.FRAME_BENIGN_WEAK)
            # Mention the single weak signal honestly.
            parts.append(_signal_clause(res.fired[0]))
        else:
            parts.append(C.FRAME_BENIGN_CLEAN)
        if res.suppress_notes:
            parts.append(res.suppress_notes[0])
        return _truncate(" ".join(parts))

    # Positive verdicts.
    parts = []
    parts.append(C.FRAME_MALICIOUS if res.verdict == "malicious"
                 else C.FRAME_SUSPICIOUS)

    top = res.fired[:3]
    for sig in top:
        parts.append(_signal_clause(sig))

    if res.synergy and res.verdict == "malicious":
        parts.append(C.CHAIN_NOTE)

    if res.ml_boosted and len(top) < 2:
        parts.append(C.ML_NOTE)
    elif res.ml_score >= C.ML_VERYHIGH:
        parts.append(C.ML_NOTE)

    for note in res.suppress_notes:
        parts.append(note)

    # Map note about category for explainability.
    title = C.AST_TITLES.get(category)
    if title:
        parts.append("归类：%s。" % title)

    return _truncate(" ".join(parts))


def _truncate(text):
    if len(text) > C.EVIDENCE_MAX_CHARS:
        return text[:C.EVIDENCE_MAX_CHARS - 1] + "…"
    return text
