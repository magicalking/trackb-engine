# -*- coding: utf-8 -*-
"""Fetch REAL prompt-injection / jailbreak corpora and wrap them as SKILL.md.

Why: the only public *malicious agent-skill* full-text data is one campaign, and
our synthetic malicious set is rule-generated (the rules trivially catch it).
The dominant real-world skill attack is natural-language instruction injection
(91% of confirmed malicious skills combine injection prose with code — Snyk).
Public corpora of real injection / jailbreak *language* exist on Hugging Face;
we use them to teach the frozen ML model genuine attack phrasing instead of a
synthetic fingerprint.

KEY DESIGN — avoid style/length leakage: these corpora are bare NL prompts, not
skills. Fed raw, the model would learn "short imperative text == malicious"
(a length/style artifact), not behaviour. So every prompt — injection AND benign
— is WRAPPED in the SAME de-branded SKILL.md scaffold (reusing gen_malicious's
pools), so the wrapper is label-neutral and the model must learn the prose.

Sources (all HF rows API, no auth, MIT/Apache):
  * deepset/prompt-injections            (text/label; 1 = injection)
  * jackhhao/jailbreak-classification     (prompt/type; "jailbreak" = positive)
  * TrustAIRLab/in-the-wild-jailbreak-prompts (config name: jailbreak_* = pos,
                                               regular_* = negative)

Outputs (gzip, memory-processed so Defender never sees plaintext):
  * data/inject_real_train.jsonl.gz   malicious + benign wrapped (ML training)
  * data/inject_real_eval.jsonl.gz    held-out POSITIVE-only (recall/F2 holdout)

Usage:  python selftest/fetch_inject.py
Networked dev-only script; the engine never imports it.
"""

import gzip
import json
import os
import random
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "data")
TRAIN_OUT = os.path.join(OUT_DIR, "inject_real_train.jsonl.gz")
EVAL_OUT = os.path.join(OUT_DIR, "inject_real_eval.jsonl.gz")

sys.path.insert(0, HERE)
import gen_malicious as gm  # noqa: E402  (reuse the de-branded SKILL.md scaffold)

SPLITS_URL = "https://datasets-server.huggingface.co/splits?dataset=%s"
ROWS_URL = ("https://datasets-server.huggingface.co/rows"
            "?dataset=%s&config=%s&split=%s&offset=%d&length=%d")
PAGE = 100
MAX_TEXT = 2000          # cap wrapped prose length (keep skills realistic)
MIN_TEXT = 15            # skip trivially short prompts

# Per-source extraction config. label_mode "field" reads a row column; "config"
# derives the label from the HF config name (date-snapshot configs).
SOURCES = [
    dict(name="deepset-pi", dataset="deepset/prompt-injections",
         label_mode="field", label_field="label",
         is_pos=lambda v: str(v).strip().lower() in ("1", "1.0", "true",
                                                      "injection"),
         text_fields=["text", "prompt"], pos_cap=400, neg_cap=400,
         fallback=[("default", "train"), ("default", "test")]),
    dict(name="jackhhao-jb", dataset="jackhhao/jailbreak-classification",
         label_mode="field", label_field="type",
         is_pos=lambda v: "jailbreak" in str(v).strip().lower(),
         text_fields=["prompt", "text"], pos_cap=700, neg_cap=700,
         fallback=[("default", "train"), ("default", "test")]),
    dict(name="inthewild-jb",
         dataset="TrustAIRLab/in-the-wild-jailbreak-prompts",
         label_mode="config",
         is_pos_config=lambda c: c.lower().startswith("jailbreak"),
         is_neg_config=lambda c: c.lower().startswith("regular"),
         text_fields=["prompt", "text"], pos_cap=900, neg_cap=600,
         fallback=[("jailbreak_2023_12_25", "train"),
                   ("regular_2023_12_25", "train")]),
]


def _get_json(url, retries=10):
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent":
                                                       "trackb-selftest"})
            with urllib.request.urlopen(req, timeout=90) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as exc:  # noqa: BLE001 - transient proxy/SSL flakiness
            last = exc
            sys.stderr.write("  GET attempt %d failed: %r; retrying...\n"
                             % (attempt + 1, exc))
            time.sleep(min(2.0 * (attempt + 1), 12.0))
    raise last


def _splits(src):
    """Return [(config, split), ...]; fall back to hard-coded list on failure."""
    try:
        data = _get_json(SPLITS_URL % src["dataset"].replace("/", "%2F"))
        pairs = [(s["config"], s["split"]) for s in data.get("splits", [])]
        if pairs:
            return pairs
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write("  splits discovery failed for %s: %r; using fallback\n"
                         % (src["name"], exc))
    return src["fallback"]


def _first_text(row, fields):
    for f in fields:
        v = row.get(f)
        if isinstance(v, str) and v.strip():
            return v
    return None


def _iter_rows(dataset, config, split, hard_cap):
    """Yield row dicts for a (config, split), paginated, up to hard_cap."""
    offset = 0
    seen = 0
    while seen < hard_cap:
        url = ROWS_URL % (dataset.replace("/", "%2F"), config, split, offset,
                          PAGE)
        data = _get_json(url)
        page = data.get("rows", [])
        if not page:
            return
        for item in page:
            yield item.get("row", {})
            seen += 1
            if seen >= hard_cap:
                return
        offset += PAGE
        if len(page) < PAGE:
            return
        time.sleep(0.2)


def _label_of(src, config, row):
    """Return True (positive), False (negative), or None (skip)."""
    if src["label_mode"] == "field":
        if src["label_field"] not in row:
            return None
        return bool(src["is_pos"](row[src["label_field"]]))
    # config mode
    if src["is_pos_config"](config):
        return True
    if src.get("is_neg_config") and src["is_neg_config"](config):
        return False
    return None


def _collect(src):
    """Collect (positives, negatives) deduped text lists for one source."""
    pos, neg = [], []
    seen = set()
    pos_cap, neg_cap = src["pos_cap"], src["neg_cap"]
    for config, split in _splits(src):
        # config-mode: skip configs that are neither positive nor negative.
        if src["label_mode"] == "config":
            is_p = src["is_pos_config"](config)
            is_n = src.get("is_neg_config") and src["is_neg_config"](config)
            if not (is_p or is_n):
                continue
        if len(pos) >= pos_cap and len(neg) >= neg_cap:
            break
        try:
            for row in _iter_rows(src["dataset"], config, split,
                                  pos_cap + neg_cap + 200):
                if len(pos) >= pos_cap and len(neg) >= neg_cap:
                    break
                lab = _label_of(src, config, row)
                if lab is None:
                    continue
                text = _first_text(row, src["text_fields"])
                if not text:
                    continue
                text = text.strip()
                if len(text) < MIN_TEXT:
                    continue
                if len(text) > MAX_TEXT:
                    text = text[:MAX_TEXT]
                key = text[:120].lower()
                if key in seen:
                    continue
                seen.add(key)
                if lab and len(pos) < pos_cap:
                    pos.append(text)
                elif (not lab) and len(neg) < neg_cap:
                    neg.append(text)
        except Exception as exc:  # noqa: BLE001 - one bad config shouldn't abort
            sys.stderr.write("  %s %s/%s failed: %r; continuing\n"
                             % (src["name"], config, split, exc))
            continue
    sys.stderr.write("  %s: %d positive, %d negative collected\n"
                     % (src["name"], len(pos), len(neg)))
    return pos, neg


_INTROS = ["This skill helps with everyday tasks.",
           "Use this skill to streamline your workflow.",
           "A lightweight helper for common operations.",
           "Handy utilities for your project.",
           "Assists with routine document work."]


def _wrap(rng, text):
    """Embed NL ``text`` in a de-branded SKILL.md (label-neutral scaffold)."""
    tool = rng.choice(gm.TOOLS)
    desc = rng.choice(gm.BENIGN_DESC)
    body = gm._frontmatter(tool, "%s — %s." % (tool, desc))
    body += rng.choice(_INTROS) + "\n\n"
    placement = rng.randint(0, 2)
    if placement == 0:
        body += "## Notes\n\n" + text + "\n"
    elif placement == 1:
        body += "<!-- " + text + " -->\n"
    else:
        body += "> " + text.replace("\n", "\n> ") + "\n"
    return body


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    rng = random.Random(20260614)
    all_pos, all_neg = [], []
    for src in SOURCES:
        sys.stderr.write("== %s (%s) ==\n" % (src["name"], src["dataset"]))
        try:
            pos, neg = _collect(src)
        except Exception as exc:  # noqa: BLE001 - skip a fully-unreachable source
            sys.stderr.write("  %s unreachable: %r; skipping source\n"
                             % (src["name"], exc))
            continue
        all_pos.extend((src["name"], t) for t in pos)
        all_neg.extend((src["name"], t) for t in neg)

    if not all_pos:
        sys.stderr.write("ERROR: no positive injection samples fetched "
                         "(network down?). No files written.\n")
        return 1

    # Deterministic shuffle so train/eval slices are stable across runs.
    rng.shuffle(all_pos)
    rng.shuffle(all_neg)

    # Hold out ~20% of positives (cap 300) as a malicious-only eval slice.
    n_eval = min(300, max(1, len(all_pos) // 5))
    eval_pos = all_pos[:n_eval]
    train_pos = all_pos[n_eval:]

    def _row(idx, name, text, label):
        return {"id": "inj-%s-%05d" % (name, idx), "skill_name": "",
                "content": _wrap(rng, text), "label": label}

    train_rows = []
    for i, (name, t) in enumerate(train_pos):
        train_rows.append(_row(i, name, t, "malicious"))
    for i, (name, t) in enumerate(all_neg):
        train_rows.append(_row(i, name, t, "benign"))
    rng.shuffle(train_rows)

    eval_rows = [_row(i, name, t, "malicious")
                 for i, (name, t) in enumerate(eval_pos)]

    for path, part in ((TRAIN_OUT, train_rows), (EVAL_OUT, eval_rows)):
        with gzip.open(path, "wt", encoding="utf-8", newline="\n") as fh:
            for r in part:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    n_mal = sum(1 for r in train_rows if r["label"] == "malicious")
    n_ben = sum(1 for r in train_rows if r["label"] == "benign")
    sys.stderr.write("wrote %d train (%d malicious + %d benign) -> %s\n"
                     % (len(train_rows), n_mal, n_ben, TRAIN_OUT))
    sys.stderr.write("wrote %d held-out positive eval -> %s\n"
                     % (len(eval_rows), EVAL_OUT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
