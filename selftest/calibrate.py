# -*- coding: utf-8 -*-
"""Threshold calibration sweep for F2 (recall-weighted), hedged across the two
plausible "suspicious" scoring rules.

The official rubric is F2 over black/white/gray, but how a "suspicious" verdict
is credited is unknown. We therefore sweep (BENIGN_MAX, MAL_MIN) and report:
  * F2_A  -- positive = malicious only (strict; gray excluded from positives)
  * F2_B  -- positive = malicious OR suspicious (gray credited)
  * spec  -- benign specificity (precision guard)
and pick the setting maximising a blended, recall-leaning objective.

Signals are scanned ONCE per doc; only the banding thresholds change per setting,
so the sweep is cheap. In-memory only (Defender-safe).

Usage:  python selftest/calibrate.py
"""

import gzip
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from engine import constants as C  # noqa: E402
from engine import loader, scoring, signals  # noqa: E402

DATA = os.path.join(HERE, "data")
SOURCES = [
    ("malicious_synth_eval.jsonl.gz", "malicious"),
    ("gray_synth_eval.jsonl.gz", "suspicious"),
    ("benign_diverse_eval.jsonl.gz", "benign"),
    ("malicious_real.jsonl.gz", "malicious"),
    ("inject_real_eval.jsonl.gz", "malicious"),
]
BMAX_GRID = (8, 10, 12, 15, 18, 20)
MMIN_GRID = (35, 40, 45, 50)


def _load():
    rows = []
    for path, lab in SOURCES:
        full = os.path.join(DATA, path)
        if not os.path.exists(full):
            continue
        with gzip.open(full, "rt", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    r = json.loads(line)
                    r.setdefault("label", lab)
                    rows.append(r)
    return rows


def _f2(tp, fp, fn):
    if tp == 0:
        return 0.0
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    return (5 * prec * rec / (4 * prec + rec)) if (4 * prec + rec) else 0.0


def main():
    rows = _load()
    if not rows:
        sys.stderr.write("no eval data\n")
        return 1
    # Scan once; store (truth, doc, fired).
    cache = []
    t0 = time.monotonic()
    for r in rows:
        truth = (r.get("label") or "benign").lower()
        if truth not in ("benign", "suspicious", "malicious"):
            truth = "benign"
        doc = loader.doc_from_text(str(r.get("id", "x")), r.get("content", "") or "")
        cache.append((truth, doc, signals.scan(doc)))
    sys.stderr.write("scanned %d docs in %.1fs\n" % (len(cache), time.monotonic() - t0))

    results = []
    for bmax in BMAX_GRID:
        for mmin in MMIN_GRID:
            if mmin <= bmax:
                continue
            C.BENIGN_MAX, C.MAL_MIN = bmax, mmin
            conf = {t: {"benign": 0, "suspicious": 0, "malicious": 0}
                    for t in ("benign", "suspicious", "malicious")}
            for truth, doc, fired in cache:
                v = scoring.score(doc, fired).verdict
                conf[truth][v] += 1
            mb, ms = conf["malicious"], conf["suspicious"]
            bn = conf["benign"]
            tpA = mb["malicious"]
            fnA = mb["benign"] + mb["suspicious"]
            fpA = bn["malicious"]
            f2A = _f2(tpA, fpA, fnA)
            tpB = (mb["malicious"] + mb["suspicious"]
                   + ms["malicious"] + ms["suspicious"])
            fnB = mb["benign"] + ms["benign"]
            fpB = bn["malicious"] + bn["suspicious"]
            f2B = _f2(tpB, fpB, fnB)
            nben = sum(bn.values())
            spec = (bn["benign"] / nben) if nben else 1.0
            obj = 0.5 * f2A + 0.3 * f2B + 0.2 * spec
            results.append((obj, f2A, f2B, spec, bmax, mmin))

    results.sort(reverse=True)
    print("== threshold sweep (top 12 by blended objective) ==")
    print("  obj    F2_A   F2_B   spec   BMAX MMIN")
    for obj, f2A, f2B, spec, bmax, mmin in results[:12]:
        print("  %.4f %.4f %.4f %.4f  %3d  %3d" % (obj, f2A, f2B, spec, bmax, mmin))
    best = results[0]
    print("\nrecommended: BENIGN_MAX=%d MAL_MIN=%d  (F2_A=%.4f F2_B=%.4f spec=%.4f)"
          % (best[4], best[5], best[1], best[2], best[3]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
