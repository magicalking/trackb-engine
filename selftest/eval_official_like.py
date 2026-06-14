# -*- coding: utf-8 -*-
"""Official-style held-out evaluation: F2 + category accuracy + gray handling.

Mirrors the Track B rubric as closely as we can offline:
  * three-class ground truth (benign / suspicious / malicious = 白/灰/黑),
  * F2 (recall weighted x4) under two reasonable "suspicious" scoring rules,
  * category exact-match accuracy among correctly-judged positives (= the
    explainability metric),
  * completion rate + per-skill latency (perf / robustness sanity).

All samples are analysed IN MEMORY (loader.doc_from_text) so real-malware
plaintext never lands on disk (Windows Defender). Sources are the held-out
slices only (training never saw them).

Usage:  python selftest/eval_official_like.py
"""

import gzip
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from engine import categorize, loader, scoring, signals  # noqa: E402
from engine import run_engine  # noqa: E402

DATA = os.path.join(HERE, "data")

# (file, default-label-if-missing) — held-out only.
SOURCES = [
    ("malicious_synth_eval.jsonl.gz", "malicious"),
    ("gray_synth_eval.jsonl.gz", "suspicious"),
    ("benign_diverse_eval.jsonl.gz", "benign"),
    ("malicious_real.jsonl.gz", "malicious"),
    ("inject_real_eval.jsonl.gz", "malicious"),
]


def _load(path, default_label):
    rows = []
    full = os.path.join(DATA, path)
    if not os.path.exists(full):
        return rows
    with gzip.open(full, "rt", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            r.setdefault("label", default_label)
            rows.append(r)
    return rows


def _truth_ast(row):
    a = (row.get("attack") or "").upper()
    return a if a.startswith("AST") else ""


def _analyze(row, max_chars=20000):
    content = row.get("content", "") or ""
    doc = loader.doc_from_text(str(row.get("id", "x")), content)
    res = scoring.score(doc, signals.scan(doc))
    cat = categorize.categorize(res.verdict, res.fired)
    return res.verdict, run_engine._to_ast_label(cat)


def _f2(tp, fp, fn):
    if tp == 0:
        return 0.0, 0.0, 0.0
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    if prec + rec == 0:
        return 0.0, prec, rec
    f2 = 5 * prec * rec / (4 * prec + rec) if (4 * prec + rec) else 0.0
    return f2, prec, rec


def main():
    rows = []
    for path, lab in SOURCES:
        rows.extend(_load(path, lab))
    if not rows:
        sys.stderr.write("no eval data found; run gen_malicious.py / fetchers\n")
        return 1

    n = len(rows)
    # Confusion over 3 classes.
    classes = ("benign", "suspicious", "malicious")
    conf = {t: {p: 0 for p in classes} for t in classes}
    # Category accuracy bookkeeping (positives correctly judged).
    cat_total = 0
    cat_hit = 0
    cat_by_attack = {}
    t0 = time.monotonic()
    errors = 0
    for r in rows:
        truth = (r.get("label") or "benign").lower()
        if truth not in classes:
            truth = "malicious" if truth in ("mal", "black") else \
                    ("suspicious" if truth in ("gray", "grey") else "benign")
        try:
            verdict, ast = _analyze(r)
        except Exception:  # noqa: BLE001
            errors += 1
            verdict, ast = "suspicious", "AST08"
        conf[truth][verdict] += 1
        # Category accuracy: truth positive, judged positive (lenient), has label.
        t_ast = _truth_ast(r)
        if truth in ("malicious", "suspicious") and t_ast:
            judged_pos = verdict in ("malicious", "suspicious")
            if judged_pos:
                cat_total += 1
                bucket = cat_by_attack.setdefault(t_ast, [0, 0])
                bucket[1] += 1
                if ast == t_ast:
                    cat_hit += 1
                    bucket[0] += 1
    dt = time.monotonic() - t0

    # ---- F2 under two "suspicious" rules -------------------------------- #
    # truth positive = malicious (black). Specificity over benign (white).
    def cell(t, p):
        return conf[t][p]

    # Rule A (strict): only verdict==malicious counts as a positive detection.
    tpA = cell("malicious", "malicious")
    fnA = cell("malicious", "benign") + cell("malicious", "suspicious")
    fpA = cell("benign", "malicious")
    f2A, precA, recA = _f2(tpA, fpA, fnA)

    # Rule B (lenient): verdict in {malicious,suspicious} counts as positive;
    # truth positive = {malicious, suspicious}; truth negative = benign.
    tpB = (cell("malicious", "malicious") + cell("malicious", "suspicious")
           + cell("suspicious", "malicious") + cell("suspicious", "suspicious"))
    fnB = cell("malicious", "benign") + cell("suspicious", "benign")
    fpB = cell("benign", "malicious") + cell("benign", "suspicious")
    f2B, precB, recB = _f2(tpB, fpB, fnB)

    n_benign = sum(conf["benign"].values())
    spec = (cell("benign", "benign") / n_benign) if n_benign else 1.0

    cat_acc = (cat_hit / cat_total) if cat_total else 0.0

    print("== Official-like eval (held-out, in-memory) ==")
    print("samples: %d  (benign=%d suspicious=%d malicious=%d)"
          % (n, sum(conf["benign"].values()), sum(conf["suspicious"].values()),
             sum(conf["malicious"].values())))
    print()
    print("confusion (rows=truth, cols=verdict):")
    print("            %-9s %-10s %-9s" % classes)
    for t in classes:
        print("  %-9s %-9d %-10d %-9d"
              % (t, conf[t]["benign"], conf[t]["suspicious"], conf[t]["malicious"]))
    print()
    print("F2 (rule A, strict malicious): F2=%.4f prec=%.4f rec=%.4f"
          % (f2A, precA, recA))
    print("F2 (rule B, positive=mal+susp): F2=%.4f prec=%.4f rec=%.4f"
          % (f2B, precB, recB))
    print("benign specificity            : %.4f" % spec)
    print("category exact-match (expl.)  : %.4f  (%d/%d positives)"
          % (cat_acc, cat_hit, cat_total))
    print("per-attack category accuracy  :")
    for a in sorted(cat_by_attack):
        hit, tot = cat_by_attack[a]
        print("    %-7s %d/%d = %.2f" % (a, hit, tot, hit / tot if tot else 0))
    print()
    print("completion: %d/%d (errors=%d)  time=%.2fs  %.2f ms/skill"
          % (n - errors, n, errors, dt, 1000.0 * dt / max(1, n)))
    # Rough total-score projection (assuming perf=1.0, robustness~completion).
    expl = cat_acc
    for tag, f2 in (("A", f2A), ("B", f2B)):
        total = 10 * (0.55 * f2 + 0.10 * 1.0 + 0.20 * expl + 0.15 * 1.0)
        print("projected total (rule %s, perf=1, robust=1): %.2f" % (tag, total))
    return 0


if __name__ == "__main__":
    sys.exit(main())
