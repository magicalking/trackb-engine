# -*- coding: utf-8 -*-
"""Pick the single AST category from the fired signal set.

Deterministic: highest-severity AST in AST_PRIORITY wins. AST09 (No Governance)
is never emitted as a standalone category. Benign verdict -> "benign". A positive
verdict with no rule signal (ML-only) falls back to the default malicious bucket.
"""

from engine import constants as C


def categorize(verdict, fired):
    if verdict == "benign":
        return "benign"
    best = None
    best_rank = 999
    for s in fired:
        cat = s.category
        if cat == "ast09":          # never standalone
            continue
        rank = C.AST_PRIORITY.index(cat) if cat in C.AST_PRIORITY else 998
        if rank < best_rank:
            best_rank = rank
            best = cat
    if best is None:
        return C.DEFAULT_MALICIOUS_CATEGORY
    return best
