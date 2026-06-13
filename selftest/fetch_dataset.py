# -*- coding: utf-8 -*-
"""Download the self-test corpus (the ONLY networked script in this repo).

Pulls yoonholee/agent-skill-malware via the Hugging Face datasets-server rows
API and writes selftest/data/dataset.jsonl with one {id, skill_name, content,
label} object per line. The engine never imports this module.

Usage:  python selftest/fetch_dataset.py
"""

import gzip
import json
import os
import sys
import time
import urllib.request

DATASET = "yoonholee/agent-skill-malware"
CONFIG = "default"
SPLIT = "train"
PAGE = 100
BASE = ("https://datasets-server.huggingface.co/rows"
        "?dataset=%s&config=%s&split=%s&offset=%d&length=%d")

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "data")
# Stored GZIPPED on purpose: the corpus is real malware; a plaintext .jsonl on a
# Windows dev box gets quarantined by Defender on-access scanning. Gzip keeps the
# signatures off-disk-in-the-clear; the self-test decompresses in memory only.
OUT_PATH = os.path.join(OUT_DIR, "dataset.jsonl.gz")


def _fetch_page(offset, retries=6):
    url = BASE % (DATASET.replace("/", "%2F"), CONFIG, SPLIT, offset, PAGE)
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "trackb-selftest"})
            with urllib.request.urlopen(req, timeout=90) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as exc:  # noqa: BLE001 - transient proxy/SSL flakiness
            last = exc
            sys.stderr.write("  page@%d attempt %d failed: %r; retrying...\n"
                             % (offset, attempt + 1, exc))
            time.sleep(2.0 * (attempt + 1))
    raise last


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    rows = []
    offset = 0
    total = None
    while True:
        data = _fetch_page(offset)
        if total is None:
            total = data.get("num_rows_total") or data.get("num_rows_total_visible")
        page_rows = data.get("rows", [])
        if not page_rows:
            break
        for item in page_rows:
            r = item.get("row", {})
            rows.append({
                "id": r.get("id") or ("row-%d" % len(rows)),
                "skill_name": r.get("skill_name", ""),
                "content": r.get("content", ""),
                "label": (r.get("label") or "").strip().lower(),
            })
        sys.stderr.write("fetched %d rows...\n" % len(rows))
        offset += PAGE
        if total and offset >= total:
            break
        if len(page_rows) < PAGE:
            break
        time.sleep(0.3)

    with gzip.open(OUT_PATH, "wt", encoding="utf-8", newline="\n") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False))
            fh.write("\n")
    sys.stderr.write("wrote %d rows to %s\n" % (len(rows), OUT_PATH))


if __name__ == "__main__":
    main()
