# -*- coding: utf-8 -*-
"""End-to-end self-test (in-memory) -> validate -> measure -> sweep.

Runs the ACTUAL shipped pipeline (rules + frozen ML) on every corpus sample,
building each skill document in memory so real-malware plaintext never touches
the disk (Windows Defender quarantines it; the Linux ranking container has no
such constraint). Writes selftest/work/metrics.json and a gzipped result dump.

Usage:  python selftest/run_selftest.py
"""

import gzip
import json
import os
import sys
import time
import tracemalloc

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

from engine import constants as C            # noqa: E402
from engine import loader, ml, scoring, signals  # noqa: E402
from engine import run_engine                # noqa: E402
import materialize as materialize_mod        # noqa: E402
import metrics as metrics_mod                # noqa: E402

WORK = os.path.join(HERE, "work")
METRICS_OUT = os.path.join(WORK, "metrics.json")
RESULTS_GZ = os.path.join(WORK, "results.jsonl.gz")

VALID_VERDICTS = {"benign", "suspicious", "malicious"}
# §3 output tokens: uppercase ASTxx for positives, "" for benign. AST09 (No
# Governance) is a policy modifier and is NEVER emitted standalone.
VALID_CATEGORIES = {"AST01", "AST02", "AST03", "AST04", "AST05", "AST06",
                    "AST07", "AST08", "AST10", ""}
RESULT_KEYS = {"skill_id", "verdict", "confidence", "category", "evidence"}


def schema_check(results):
    problems = []
    for i, obj in enumerate(results, 1):
        if set(obj.keys()) != RESULT_KEYS:
            problems.append("row %d: keys=%s" % (i, sorted(obj.keys())))
        if obj.get("verdict") not in VALID_VERDICTS:
            problems.append("row %d: bad verdict %r" % (i, obj.get("verdict")))
        conf = obj.get("confidence")
        if not isinstance(conf, (int, float)) or not (0.0 <= conf <= 1.0):
            problems.append("row %d: bad confidence %r" % (i, conf))
        if obj.get("category") not in VALID_CATEGORIES:
            problems.append("row %d: bad category %r" % (i, obj.get("category")))
        if not (obj.get("evidence") or "").strip():
            problems.append("row %d: empty evidence" % i)
    return (len(problems) == 0), problems


def analyze_all(docs):
    """Return list of result dicts (engine output) for the given docs."""
    return [run_engine.analyze_doc(doc) for doc in docs]


def rescore_verdict(doc, fired, benign_max, mal_min):
    old_b, old_m = C.BENIGN_MAX, C.MAL_MIN
    C.BENIGN_MAX, C.MAL_MIN = benign_max, mal_min
    try:
        return scoring.score(doc, fired).verdict
    finally:
        C.BENIGN_MAX, C.MAL_MIN = old_b, old_m


def sweep(ids, docs, gold, fired_cache):
    results = []
    for bmax in (15, 20, 25):
        for mmin in (40, 45, 50):
            if mmin <= bmax:
                continue
            pairs = []
            for sid, doc in zip(ids, docs):
                v = rescore_verdict(doc, fired_cache[sid], bmax, mmin)
                pairs.append((gold[sid], v))
            m = metrics_mod.compute(pairs)
            obj = (C.SWEEP_WEIGHTS["f2"] * m["f2"]
                   + C.SWEEP_WEIGHTS["specificity"] * m["specificity"]
                   + C.SWEEP_WEIGHTS["gray_handling"]
                   * (1.0 - abs(m["suspicious_on_benign"] - m["suspicious_on_malicious"])
                      / max(1, m["n_total"])))
            results.append({"benign_max": bmax, "mal_min": mmin,
                            "f2": m["f2"], "specificity": m["specificity"],
                            "recall": m["recall"], "precision": m["precision"],
                            "objective": round(obj, 4)})
    results.sort(key=lambda d: -d["objective"])
    return results


def main():
    rows, corpus_path = materialize_mod.load_corpus()
    if not rows:
        sys.stderr.write("corpus empty/missing. Run: python selftest/fetch_dataset.py\n")
        return 1
    os.makedirs(WORK, exist_ok=True)

    ids = [str(r["id"]) for r in rows]
    gold = {str(r["id"]): (r.get("label") or "").strip().lower() for r in rows}
    contents = {str(r["id"]): (r.get("content") or "") for r in rows}

    # Build docs in memory (mirrors the on-disk loader normalisation).
    docs = [loader.doc_from_text(sid, contents[sid]) for sid in ids]

    if not ml.is_available():
        sys.stderr.write("WARN: engine/model.json missing -> rule-only mode.\n")

    # Timed + memory-profiled analysis (the shipped pipeline).
    tracemalloc.start()
    t0 = time.perf_counter()
    results = analyze_all(docs)
    elapsed = time.perf_counter() - t0
    _cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Determinism: a second pass must be byte-identical.
    results2 = analyze_all(docs)
    s1 = "\n".join(run_engine._dump_line(o) for o in results)
    s2 = "\n".join(run_engine._dump_line(o) for o in results2)
    deterministic = (s1 == s2)

    ok, problems = schema_check(results)
    lines_equals_skills = (len(results) == len(ids))

    pairs = [(gold[o["skill_id"]], o["verdict"]) for o in results]
    m = metrics_mod.compute(pairs)

    cat_dist = {}
    for o in results:
        key = o["category"] or "benign"
        cat_dist[key] = cat_dist.get(key, 0) + 1

    # Threshold sweep (cache fired signals once).
    fired_cache = {sid: (signals.scan(doc) if not doc.empty else [])
                   for sid, doc in zip(ids, docs)}
    sweep_results = sweep(ids, docs, gold, fired_cache)

    report = {
        "engine_version": "1.0.0",
        "corpus_path": os.path.basename(corpus_path),
        "ml_available": ml.is_available(),
        "n_skills": len(ids),
        "n_output_lines": len(results),
        "lines_equals_skills": lines_equals_skills,
        "schema_ok": ok,
        "schema_problems": problems[:20],
        "deterministic": deterministic,
        "timing_seconds": round(elapsed, 3),
        "ms_per_skill": round(1000.0 * elapsed / max(1, len(ids)), 3),
        "peak_memory_mib": round(peak / (1024 * 1024), 2),
        "metrics_default": m,
        "category_distribution": cat_dist,
        "threshold_sweep": sweep_results,
        "default_thresholds": {"benign_max": C.BENIGN_MAX, "mal_min": C.MAL_MIN},
    }
    with open(METRICS_OUT, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    # Result dump kept gzipped (evidence quotes malware fragments).
    with gzip.open(RESULTS_GZ, "wt", encoding="utf-8") as fh:
        for o in results:
            fh.write(run_engine._dump_line(o) + "\n")

    # ---- human summary ---------------------------------------------------- #
    print(metrics_mod.format_report(m, "Track B self-test (default %d/%d)"
                                     % (C.BENIGN_MAX, C.MAL_MIN)))
    print("")
    print("corpus                 : %s (%d rows)" % (os.path.basename(corpus_path), len(ids)))
    print("output lines == skills : %s" % lines_equals_skills)
    print("schema valid           : %s (%d problems)" % (ok, len(problems)))
    print("deterministic (2 runs) : %s" % deterministic)
    print("ml model available     : %s" % ml.is_available())
    print("time                   : %.3fs total, %.3f ms/skill"
          % (elapsed, report["ms_per_skill"]))
    print("peak memory (tracemalloc): %.2f MiB" % report["peak_memory_mib"])
    print("category distribution  : %s" % json.dumps(cat_dist, ensure_ascii=False))
    print("")
    print("threshold sweep (top 5 by objective):")
    for row in sweep_results[:5]:
        print("  bmax=%2d mmin=%2d  F2=%.4f spec=%.4f rec=%.4f prec=%.4f obj=%.4f"
              % (row["benign_max"], row["mal_min"], row["f2"], row["specificity"],
                 row["recall"], row["precision"], row["objective"]))
    if problems:
        print("\nschema problems (first few):")
        for p in problems[:5]:
            print("  " + p)
    print("\nfull report -> %s" % METRICS_OUT)
    return 0 if (ok and deterministic and lines_equals_skills) else 2


if __name__ == "__main__":
    sys.exit(main())
