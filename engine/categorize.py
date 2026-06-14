# -*- coding: utf-8 -*-
"""Pick the single AST category from the fired signal set.

The main-category must reflect the DOMINANT evidence, not merely the most severe
label that happens to be present. The old "highest AST_PRIORITY wins" rule
collapsed almost everything to AST01 (any single ast01 signal beat a strong
cluster of ast02/03/05 evidence), which is why category accuracy stalled at ~0.50.

New rule: the category of the highest-WEIGHT fired signal wins; ties are broken
by AST_PRIORITY (more severe first) then signal id (determinism). This surfaces
supply-chain (AST02), over-privilege (AST03), metadata (AST04), deserialization
(AST05), isolation/drift/reuse (AST06/07/10) and prose-only injection (AST08)
when they are the strongest evidence, while a genuine high-weight RCE/exfil
signal still wins AST01. AST09 (No Governance) is never emitted standalone; a
benign verdict -> "benign"; an ML-only positive falls back to the default bucket.
"""

from engine import constants as C


def categorize(verdict, fired):
    if verdict == "benign":
        return "benign"
    best = None
    best_key = None
    for s in fired:
        cat = s.category
        if cat == "ast09":          # never standalone (governance modifier)
            continue
        rank = C.AST_PRIORITY.index(cat) if cat in C.AST_PRIORITY else 998
        # Sort key: highest weight first, then most severe, then stable by id.
        key = (-s.weight, rank, s.id)
        if best_key is None or key < best_key:
            best_key = key
            best = cat
    if best is None:
        return C.DEFAULT_MALICIOUS_CATEGORY
    return best
