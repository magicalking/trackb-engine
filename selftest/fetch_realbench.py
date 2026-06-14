# -*- coding: utf-8 -*-
"""Fetch real labelled agent-skill benchmarks for honest validation / retraining.

Sources (best-effort; the eval network is isolated, so this runs ONLY on the dev
machine / CI to PRE-BUILD the gzipped corpora that ship in selftest/data):
  * protectskills/MaliciousAgentSkillsBench  -> data/malicious_skills.csv
    (3-class labels: safe/suspicious/malicious + Pattern/Severity). Note: the
    confirmed-malicious skill BODIES are redacted ([REDACTED]) in the public
    repo, so we keep the pattern/category labels for calibration, not full text.

Everything is processed IN MEMORY and written gzip (Windows Defender quarantines
plaintext malware). Network is flaky here -> each GET retries with backoff.

Usage:  python selftest/fetch_realbench.py
"""

import csv
import gzip
import io
import json
import os
import ssl
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "data", "malicious_real_bench.jsonl.gz")
_CTX = ssl.create_default_context()

CSV_URLS = [
    "https://raw.githubusercontent.com/protectskills/MaliciousAgentSkillsBench/main/data/malicious_skills.csv",
    "https://raw.githubusercontent.com/protectskills/MaliciousAgentSkillsBench/master/data/malicious_skills.csv",
    "https://raw.githubusercontent.com/protectskills/MaliciousAgentSkillsBench/main/malicious_skills.csv",
]

# Map a free-text Pattern token -> our internal AST category (best effort).
PATTERN_AST = [
    ("prompt inject", "ast08"), ("instruction", "ast08"), ("jailbreak", "ast08"),
    ("deserial", "ast05"), ("pickle", "ast05"), ("yaml", "ast05"),
    ("supply", "ast02"), ("dependenc", "ast02"), ("typosquat", "ast04"),
    ("impersonat", "ast04"), ("metadata", "ast04"),
    ("privileg", "ast03"), ("permission", "ast03"),
    ("isolation", "ast06"), ("sandbox", "ast06"),
    ("update", "ast07"), ("version", "ast07"),
    ("cross-platform", "ast10"), ("reuse", "ast10"),
    ("exfil", "ast01"), ("credential", "ast01"), ("reverse shell", "ast01"),
    ("rce", "ast01"), ("malware", "ast01"), ("download", "ast01"),
]


def _get(url, retries=4, timeout=25):
    last = None
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "trackb-fetch"})
            with urllib.request.urlopen(req, timeout=timeout, context=_CTX) as r:
                return r.read()
        except Exception as exc:  # noqa: BLE001
            last = exc
            sys.stderr.write("  retry %d/%d %s: %s\n"
                             % (i + 1, retries, url.rsplit("/", 1)[-1],
                                type(exc).__name__))
            time.sleep(1.5 * (i + 1))
    raise last


def _ast_for(pattern):
    p = (pattern or "").lower()
    for needle, ast in PATTERN_AST:
        if needle in p:
            return ast
    return "ast01"


def main():
    raw = None
    for url in CSV_URLS:
        try:
            raw = _get(url)
            sys.stderr.write("fetched %s (%d bytes)\n" % (url, len(raw)))
            break
        except Exception:  # noqa: BLE001
            continue
    if raw is None:
        sys.stderr.write("could not fetch MaliciousAgentSkillsBench CSV "
                         "(network isolated / moved). Skipping; synthetic + "
                         "existing real corpora remain in use.\n")
        return 1

    text = raw.decode("utf-8", "replace")
    rows = []
    reader = csv.DictReader(io.StringIO(text))
    for rec in reader:
        # Column names are tolerant: skill_name / Pattern / classification.
        name = (rec.get("skill_name") or rec.get("name") or "").strip()
        pattern = (rec.get("Pattern") or rec.get("pattern") or "").strip()
        cls = (rec.get("classification") or rec.get("label")
               or "malicious").strip().lower()
        # Body is redacted in the public repo; use name + pattern as the text
        # surrogate so it still informs ML token stats / category mapping.
        content = "%s\n%s" % (name, pattern)
        rows.append({"id": "realbench-%04d" % len(rows),
                     "skill_name": name, "content": content,
                     "label": "malicious" if "mal" in cls else
                              ("suspicious" if "susp" in cls else "benign"),
                     "attack": _ast_for(pattern)})
    if not rows:
        sys.stderr.write("CSV parsed but no rows; skipping write.\n")
        return 1
    with gzip.open(OUT, "wt", encoding="utf-8", newline="\n") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    from collections import Counter
    sys.stderr.write("wrote %d rows -> %s\n" % (len(rows), OUT))
    sys.stderr.write("label dist: %s\n" % dict(Counter(r["label"] for r in rows)))
    sys.stderr.write("ast dist:   %s\n" % dict(Counter(r["attack"] for r in rows)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
