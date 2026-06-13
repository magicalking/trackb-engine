# -*- coding: utf-8 -*-
"""Fetch EXTRA training/validation data to break single-campaign overfit.

Primary source: LittleDinoC/agent-skills (61k real, diverse, benign SKILL.md on
Hugging Face, MIT). We sample a slice via the rows API and store it gzipped
(consistent with the rest of the harness). Split into a train-augmentation slice
and a held-out diverse-benign validation slice (disjoint offsets).

Usage:  python selftest/fetch_extra.py [n_total]
        default n_total=3000  (2000 train-aug + 1000 held-out eval)

Only networked script besides fetch_dataset.py; the engine never imports it.
"""

import gzip
import json
import os
import sys
import time
import urllib.request

DATASET = "LittleDinoC/agent-skills"
CONFIG = "default"
SPLIT = "train"
PAGE = 100
BASE = ("https://datasets-server.huggingface.co/rows"
        "?dataset=%s&config=%s&split=%s&offset=%d&length=%d")

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "data")
TRAIN_OUT = os.path.join(OUT_DIR, "benign_diverse_train.jsonl.gz")
EVAL_OUT = os.path.join(OUT_DIR, "benign_diverse_eval.jsonl.gz")


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


def _row_to_obj(r, idx):
    # LittleDinoC schema: id, name, description, owner, repo, skill_md_path,
    # content. No label column -> all benign.
    content = r.get("content") or r.get("skill_md") or ""
    sid = (r.get("id") or r.get("name") or ("benign-%d" % idx))
    return {"id": "ld-%s" % str(sid)[:40], "skill_name": r.get("name", ""),
            "content": content, "label": "benign"}


def main():
    n_total = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
    os.makedirs(OUT_DIR, exist_ok=True)
    rows = []
    offset = 0
    while len(rows) < n_total:
        data = _fetch_page(offset)
        page = data.get("rows", [])
        if not page:
            break
        for item in page:
            obj = _row_to_obj(item.get("row", {}), len(rows))
            if obj["content"].strip():
                rows.append(obj)
        sys.stderr.write("fetched %d benign rows...\n" % len(rows))
        offset += PAGE
        if len(page) < PAGE:
            break
        time.sleep(0.2)

    rows = rows[:n_total]
    # Held-out eval is ALWAYS the first 1000 rows so it stays comparable across
    # runs with different n_total; the remainder is train-augmentation.
    n_eval = min(1000, max(1, n_total // 3))
    eval_rows = rows[:n_eval]
    train_rows = rows[n_eval:]

    for path, part in ((TRAIN_OUT, train_rows), (EVAL_OUT, eval_rows)):
        with gzip.open(path, "wt", encoding="utf-8", newline="\n") as fh:
            for r in part:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    sys.stderr.write("wrote %d train-aug -> %s\n" % (len(train_rows), TRAIN_OUT))
    sys.stderr.write("wrote %d held-out eval -> %s\n" % (len(eval_rows), EVAL_OUT))


if __name__ == "__main__":
    main()
