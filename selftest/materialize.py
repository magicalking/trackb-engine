# -*- coding: utf-8 -*-
"""Corpus loading + optional on-disk materialisation.

`load_corpus` decompresses the gzipped corpus into a list of row dicts (kept in
memory only — the preferred path on Windows, where Defender quarantines plaintext
malware). `materialize` writes the /data/skills/{id}/SKILL.md layout to disk and
is intended for in-container / Linux testing (on Windows it will trip Defender).
"""

import gzip
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_GZ = os.path.join(HERE, "data", "dataset.jsonl.gz")
DATA_PLAIN = os.path.join(HERE, "data", "dataset.jsonl")


def _open_corpus(path):
    if path is None:
        path = DATA_GZ if os.path.exists(DATA_GZ) else DATA_PLAIN
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8"), path
    return open(path, "r", encoding="utf-8"), path


def load_corpus(path=None):
    """Return (rows, path). Each row: {id, skill_name, content, label}."""
    fh, used = _open_corpus(path)
    rows = []
    with fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows, used


def materialize(path=None, out_root=None):
    """Write <out>/skills/{id}/SKILL.md + labels.json. Returns (skills_dir, labels).

    NOTE: writes real-malware plaintext to disk -> on Windows add a Defender
    exclusion or run inside the Linux container. The self-test does NOT use this;
    it analyses in memory via load_corpus.
    """
    rows, _ = load_corpus(path)
    if out_root is None:
        out_root = os.path.join(HERE, "work")
    skills_dir = os.path.join(out_root, "skills")
    os.makedirs(skills_dir, exist_ok=True)
    labels = {}
    for row in rows:
        sid = str(row["id"])
        sdir = os.path.join(skills_dir, sid)
        os.makedirs(sdir, exist_ok=True)
        with open(os.path.join(sdir, "SKILL.md"), "w",
                  encoding="utf-8", newline="\n") as out:
            out.write(row.get("content", "") or "")
        labels[sid] = (row.get("label") or "").strip().lower()
    with open(os.path.join(out_root, "labels.json"), "w", encoding="utf-8") as fh:
        json.dump(labels, fh, ensure_ascii=False, indent=0)
    return skills_dir, labels


if __name__ == "__main__":
    rs, p = load_corpus()
    print("loaded %d rows from %s" % (len(rs), p))
