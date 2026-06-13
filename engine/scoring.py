# -*- coding: utf-8 -*-
"""Score fusion and verdict banding.

r = clamp( sum(unique signal weights) + synergy_bonus - suppression_penalty )
A confirmed Tier-A chain pins r >= MAL_MIN. The frozen ML model only *boosts*
the verdict by one band (never single-handedly convicts), protecting specificity
against ML over-fitting to a single campaign.
"""

from engine import constants as C
from engine import ml
from engine import suppress


class ScoreResult(object):
    __slots__ = ("verdict", "r", "ml_score", "fired", "synergy",
                 "suppress_notes", "ml_boosted")

    def __init__(self):
        self.verdict = "benign"
        self.r = 0
        self.ml_score = 0.0
        self.fired = []           # deduped Signals, priority-sorted
        self.synergy = False
        self.suppress_notes = []
        self.ml_boosted = False


def _dedupe(fired):
    """Keep one Signal per id (first occurrence wins, stable)."""
    seen = {}
    out = []
    for s in fired:
        if s.id in seen:
            continue
        seen[s.id] = True
        out.append(s)
    return out


def _band(r):
    if r >= C.MAL_MIN:
        return "malicious"
    if r >= C.BENIGN_MAX:
        return "suspicious"
    return "benign"


_BAND_ORDER = {"benign": 0, "suspicious": 1, "malicious": 2}
_ORDER_BAND = {0: "benign", 1: "suspicious", 2: "malicious"}


def score(doc, fired):
    """Combine fired signals + ML into a ScoreResult. Never raises."""
    res = ScoreResult()

    # Suppression first (may drop spurious signals).
    penalty, notes, drop_ids, cap_suspicious = suppress.compute(doc, fired)
    fired = [s for s in fired if s.id not in drop_ids]

    fired = _dedupe(fired)

    base = sum(s.weight for s in fired)

    tiers = set(s.tier for s in fired if s.tier in C.SYNERGY_TIERS)
    synergy = len(tiers) >= 2
    if synergy:
        base += C.SYNERGY_BONUS

    r = base - penalty
    if r < 0:
        r = 0
    if r > 100:
        r = 100

    # Confirmed-chain floor: strong Tier-A signals cannot be suppressed below
    # malicious.
    fired_ids = set(s.id for s in fired)
    if fired_ids & set(C.CONFIRMED_CHAIN_SIGNALS) and r < C.MAL_MIN:
        r = C.MAL_MIN

    # Security-tool soft cap: an analytical context quoting a payload primitive,
    # with NO real-infrastructure corroboration, is capped at suspicious (the
    # dataset's real malware always corroborates, so recall is unaffected).
    if cap_suspicious and r >= C.MAL_MIN \
            and not (fired_ids & set(C.STRONG_INFRA_SIGNALS)):
        r = C.MAL_MIN - 1
        if C.SUPPRESS_SECTOOL_NOTE not in notes:
            notes.append(C.SUPPRESS_SECTOOL_NOTE)

    verdict = _band(r)

    # ML recall booster: bump up exactly one band on high confidence.
    ml_score = ml.predict(doc.all_text)
    ml_boosted = False
    if ml_score >= C.ML_HIGH and verdict != "malicious":
        verdict = _ORDER_BAND[_BAND_ORDER[verdict] + 1]
        ml_boosted = True

    # Final security-tool clamp: never call an analytical context with no real
    # infrastructure "malicious", even via the ML boost.
    if cap_suspicious and verdict == "malicious" \
            and not (fired_ids & set(C.STRONG_INFRA_SIGNALS)):
        verdict = "suspicious"
        ml_boosted = False

    # Priority-sort fired signals for evidence (by AST priority, then weight).
    prio = {c: i for i, c in enumerate(C.AST_PRIORITY)}
    fired.sort(key=lambda s: (prio.get(s.category, 99), -s.weight, s.id))

    res.verdict = verdict
    res.r = r
    res.ml_score = ml_score
    res.fired = fired
    res.synergy = synergy
    res.suppress_notes = notes
    res.ml_boosted = ml_boosted
    return res


def _clamp01(x):
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


# Confidence reflects certainty in the VERDICT (not the raw risk score): a clean
# benign skill and a strong malicious chain are both high-confidence; the gray
# zone and boundary cases are deliberately low-confidence. Always in [0, 1].
CONF_SAT_RISK = 90      # risk score at which malicious confidence saturates


def confidence(res):
    """Map a ScoreResult to a 0.0-1.0 confidence for the §3 output field."""
    r = res.r
    v = res.verdict
    if v == "malicious":
        span = max(1, CONF_SAT_RISK - C.MAL_MIN)
        c = 0.60 + 0.39 * _clamp01((r - C.MAL_MIN) / span)
    elif v == "benign":
        c = 0.55 + 0.40 * _clamp01((C.BENIGN_MAX - r) / max(1, C.BENIGN_MAX))
    else:  # suspicious: inherently the uncertain gray zone
        c = 0.45
    # An ML-driven band bump means the model corroborated a positive -> firmer.
    if res.ml_boosted and v != "benign":
        c = max(c, 0.65)
    return round(_clamp01(c), 3)
