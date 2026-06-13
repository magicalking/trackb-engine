# -*- coding: utf-8 -*-
"""Measure the engine's false-positive rate on a held-out DIVERSE benign set.

The self-test corpus benign samples are all from one campaign; this evaluates
specificity on 1000 unrelated real SKILL.md files (LittleDinoC/agent-skills).
Any non-benign verdict here is a false positive. Also tallies which signals fire
on the false positives, to guide rule tightening.

Usage:  python selftest/eval_benign.py
"""

import gzip
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from engine import loader, scoring, signals  # noqa: E402

EVAL_GZ = os.path.join(HERE, "data", "benign_diverse_eval.jsonl.gz")


def main():
    if not os.path.exists(EVAL_GZ):
        sys.stderr.write("missing %s. Run: python selftest/fetch_extra.py\n" % EVAL_GZ)
        return 1
    rows = []
    with gzip.open(EVAL_GZ, "rt", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                rows.append(json.loads(line))

    dist = {"benign": 0, "suspicious": 0, "malicious": 0}
    sig_counts = {}
    fp_examples = []
    for r in rows:
        doc = loader.doc_from_text(str(r["id"]), r.get("content", ""))
        if doc.empty:
            dist["benign"] += 1
            continue
        fired = signals.scan(doc)
        res = scoring.score(doc, fired)
        dist[res.verdict] += 1
        if res.verdict != "benign":
            for s in res.fired:
                sig_counts[s.id] = sig_counts.get(s.id, 0) + 1
            if len(fp_examples) < 15:
                fp_examples.append((r.get("skill_name", "")[:32], res.verdict,
                                    [s.id for s in res.fired[:4]]))

    n = sum(dist.values())
    fp = dist["suspicious"] + dist["malicious"]
    print("== Held-out diverse benign eval (%d real SKILL.md) ==" % n)
    print("verdict distribution: %s" % json.dumps(dist))
    print("false positives: %d (%.2f%%)  [suspicious=%d, malicious=%d]"
          % (fp, 100.0 * fp / max(1, n), dist["suspicious"], dist["malicious"]))
    print("specificity (TN/n, full-credit): %.4f" % (dist["benign"] / max(1, n)))
    # Half-credit specificity (suspicious counts half against benign truth).
    tn = dist["benign"] + 0.5 * dist["suspicious"]
    print("specificity (half-credit rule): %.4f" % (tn / max(1, n)))
    print("")
    print("signals firing on false positives (desc):")
    for sid, c in sorted(sig_counts.items(), key=lambda kv: -kv[1]):
        print("  %-24s %d" % (sid, c))
    print("")
    print("sample false positives:")
    for name, v, sigs in fp_examples:
        print("  %-34s %-10s %s" % (name, v, sigs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
