# -*- coding: utf-8 -*-
"""Measure malicious RECALL on held-out diverse attack types.

Evaluates the engine on:
  * malicious_synth_eval.jsonl.gz  — held-out synthetic attack archetypes
    (NOT used in training), grouped by attack type, to show cross-AST coverage.
  * malicious_real.jsonl.gz        — real toxicskills-goof samples (independent
    second campaign), an out-of-distribution real check.

Recall uses the half-credit rule: malicious=1.0, suspicious=0.5, benign=0.0.

Usage:  python selftest/eval_malicious.py
"""

import gzip
import json
import os
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from engine import loader, run_engine  # noqa: E402

CREDIT = {"malicious": 1.0, "suspicious": 0.5, "benign": 0.0}


def _load(path):
    rows = []
    if os.path.exists(path):
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    rows.append(json.loads(line))
    return rows


def _eval(rows, label):
    if not rows:
        print("%s: (no data)" % label)
        return
    by_attack = defaultdict(lambda: [0, 0.0])  # count, credit
    dist = {"benign": 0, "suspicious": 0, "malicious": 0}
    misses = []
    for r in rows:
        doc = loader.doc_from_text(str(r["id"]), r.get("content", ""))
        out = run_engine.analyze_doc(doc)
        v = out["verdict"]
        dist[v] += 1
        atk = r.get("attack", "real")
        by_attack[atk][0] += 1
        by_attack[atk][1] += CREDIT[v]
        if v == "benign":
            misses.append((r["id"], out["category"]))
    n = len(rows)
    recall = sum(CREDIT[v] * c for v, c in dist.items()) / n
    print("== %s (%d samples) ==" % (label, n))
    print("verdict dist: %s" % json.dumps(dist))
    print("recall (half-credit): %.4f   full-miss(benign): %d" % (recall, dist["benign"]))
    print("by attack type (recall):")
    for atk in sorted(by_attack):
        c, cr = by_attack[atk]
        print("  %-8s n=%-4d recall=%.3f" % (atk, c, cr / c))
    if misses:
        print("missed (benign) examples: %s" % misses[:8])
    print("")


def main():
    _eval(_load(os.path.join(HERE, "data", "malicious_synth_eval.jsonl.gz")),
          "Held-out SYNTHETIC malicious (diverse AST types)")
    _eval(_load(os.path.join(HERE, "data", "malicious_real.jsonl.gz")),
          "Real malicious (toxicskills-goof, independent campaign)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
