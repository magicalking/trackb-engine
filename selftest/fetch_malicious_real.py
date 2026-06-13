# -*- coding: utf-8 -*-
"""Fetch REAL malicious agent-skill samples from snyk-labs/toxicskills-goof.

These are a handful of public, deliberately-malicious demo skills (env-var
exfiltration, unicode/ASCII smuggling, fake-prerequisite lures) — a second,
INDEPENDENT campaign used to sanity-check malicious recall beyond the synthetic
set. Stored gzipped. Only a networked helper; the engine never imports it.

Usage:  python selftest/fetch_malicious_real.py
"""

import gzip
import json
import os
import sys
import time
import urllib.request

REPO = "snyk-labs/toxicskills-goof"
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "data", "malicious_real.jsonl.gz")


def _get(url, retries=5, raw=False):
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "trackb-selftest",
                "Accept": "application/vnd.github+json"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = resp.read()
                return data if raw else json.loads(data.decode("utf-8"))
        except Exception as exc:  # noqa: BLE001 - transient proxy/SSL
            last = exc
            sys.stderr.write("  %s attempt %d: %r\n" % (url, attempt + 1, exc))
            time.sleep(2.0 * (attempt + 1))
    raise last


def _tree(branch):
    return _get("https://api.github.com/repos/%s/git/trees/%s?recursive=1"
                % (REPO, branch))


def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    branch = "main"
    try:
        tree = _tree("main")
    except Exception:
        branch = "master"
        tree = _tree("master")

    md_paths = [n["path"] for n in tree.get("tree", [])
                if n.get("type") == "blob" and n["path"].lower().endswith(".md")
                and ("skill" in n["path"].lower() or "/skills/" in n["path"].lower())]
    # Fall back to any markdown if no SKILL.md-looking paths.
    if not md_paths:
        md_paths = [n["path"] for n in tree.get("tree", [])
                    if n.get("type") == "blob" and n["path"].lower().endswith(".md")]

    rows = []
    for path in md_paths:
        url = "https://raw.githubusercontent.com/%s/%s/%s" % (
            REPO, branch, urllib.request.quote(path))
        try:
            content = _get(url, raw=True).decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write("skip %s: %r\n" % (path, exc))
            continue
        if content.strip():
            rows.append({"id": "toxic-%s" % path.replace("/", "_")[:48],
                         "skill_name": path, "content": content,
                         "label": "malicious"})

    with gzip.open(OUT, "wt", encoding="utf-8", newline="\n") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    sys.stderr.write("wrote %d real malicious samples -> %s\n" % (len(rows), OUT))


if __name__ == "__main__":
    main()
