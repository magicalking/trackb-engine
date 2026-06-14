# -*- coding: utf-8 -*-
"""Offline trainer: fit TF-IDF + Logistic Regression, freeze to engine/model.json.

Runs ONLY on the developer machine (needs scikit-learn). The shipped engine never
imports sklearn — it re-implements inference in pure stdlib from the exported
weights (engine/ml.py).

Key anti-overfit measures (the corpus is a single 2026-02 campaign):
  * brand-scrub: campaign-specific tokens are blanked BEFORE vectorising, so the
    model learns behaviour words (curl, bash, base64, password, prerequisite...)
    not the brand string. The identical scrub list is embedded in model.json so
    runtime applies it the same way.
  * GroupKFold by skill family: cross-validation never trains and tests on the
    same near-duplicate family, giving an honest generalisation estimate.

Usage:  python selftest/train_model.py
"""

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import materialize as materialize_mod  # noqa: E402

MODEL_OUT = os.path.join(ROOT, "engine", "model.json")

NGRAM_MAX = 2
MAX_FEATURES = 3000
MIN_DF = 2

# Brand / campaign-specific tokens to blank before vectorising. These are the
# ONLY place campaign strings appear in the whole project, and they are used to
# REMOVE (not detect) brand signal so the model generalises.
SCRUB = [
    r"openclaw[\w-]*",
    r"clawhub[\w-]*",
    r"clawdbot[\w-]*",
    r"\bddoy\d+\b",
    r"\bdenboss\d+\b",
    r"\bhedefbari\b",
    r"glot\.io",
    r"setup-service\.com",
    r"\b\d{1,3}(?:\.\d{1,3}){3}\b",      # bare IP literals
    r"[0-9a-f]{12,}",                     # long hex ids / hashes
]
_SCRUB_RES = [re.compile(p, re.IGNORECASE) for p in SCRUB]


def _preproc(text):
    text = text.lower()
    for rx in _SCRUB_RES:
        text = rx.sub(" ", text)
    return text


def _family(skill_name):
    """Group near-duplicate skills (strip a trailing random suffix)."""
    name = (skill_name or "").lower()
    name = re.sub(r"[-_][0-9a-z]{3,8}$", "", name)  # drop random suffix token
    name = re.sub(r"\d+$", "", name)
    return name or (skill_name or "x")


def load_rows():
    """Campaign corpus + (if present) diverse benign augmentation.

    The diverse benign slice (LittleDinoC/agent-skills) breaks the single-campaign
    overfit: it teaches the model what a *normal* skill looks like so it stops
    treating routine install/config prose as malicious.
    """
    rows, _ = materialize_mod.load_corpus()
    n_campaign = len(rows)
    import gzip
    counts = {}
    for fname in ("benign_diverse_train.jsonl.gz", "malicious_synth_train.jsonl.gz",
                  "inject_real_train.jsonl.gz"):
        path = os.path.join(HERE, "data", fname)
        c = 0
        if os.path.exists(path):
            with gzip.open(path, "rt", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        rows.append(json.loads(line))
                        c += 1
        counts[fname] = c
    sys.stderr.write("loaded %d campaign + %d diverse-benign + %d synth-malicious"
                     " + %d inject-real\n"
                     % (n_campaign, counts["benign_diverse_train.jsonl.gz"],
                        counts["malicious_synth_train.jsonl.gz"],
                        counts.get("inject_real_train.jsonl.gz", 0)))
    return rows


def main():
    try:
        import numpy as np
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.model_selection import GroupKFold
        from sklearn.metrics import precision_recall_fscore_support
    except ImportError:
        sys.stderr.write("scikit-learn not installed. Run: pip install scikit-learn\n")
        return 1

    rows = load_rows()
    texts = [r.get("content", "") or "" for r in rows]
    y = np.array([1 if (r.get("label", "").lower() == "malicious") else 0
                  for r in rows])
    groups = [_family(r.get("skill_name", "")) for r in rows]
    sys.stderr.write("loaded %d rows, %d malicious, %d benign, %d families\n"
                     % (len(rows), int(y.sum()), int((1 - y).sum()),
                        len(set(groups))))

    vec = TfidfVectorizer(
        lowercase=False,            # preprocessor already lowercases
        preprocessor=_preproc,
        token_pattern=r"(?u)\b\w\w+\b",
        ngram_range=(1, NGRAM_MAX),
        min_df=MIN_DF,
        max_features=MAX_FEATURES,
        norm="l2",
        use_idf=True,
        smooth_idf=True,
        sublinear_tf=False,
    )

    # ---- GroupKFold cross-validation (honest generalisation estimate) ----- #
    gkf = GroupKFold(n_splits=5)
    f1s, precs, recs = [], [], []
    for tr, te in gkf.split(texts, y, groups):
        Xtr = vec.fit_transform([texts[i] for i in tr])
        Xte = vec.transform([texts[i] for i in te])
        clf = LogisticRegression(max_iter=2000, C=4.0, class_weight="balanced",
                                 random_state=0)
        clf.fit(Xtr, y[tr])
        pred = clf.predict(Xte)
        p, r, f, _ = precision_recall_fscore_support(
            y[te], pred, average="binary", zero_division=0)
        precs.append(p); recs.append(r); f1s.append(f)
    sys.stderr.write(
        "GroupKFold(5) ML-only: precision=%.3f recall=%.3f f1=%.3f\n"
        % (float(np.mean(precs)), float(np.mean(recs)), float(np.mean(f1s))))

    # ---- Fit final model on ALL data, then freeze --------------------------#
    X = vec.fit_transform(texts)
    clf = LogisticRegression(max_iter=2000, C=4.0, class_weight="balanced",
                             random_state=0)
    clf.fit(X, y)

    vocab = {term: int(idx) for term, idx in vec.vocabulary_.items()}
    model = {
        "version": "1.0.0",
        "ngram_max": NGRAM_MAX,
        "scrub": SCRUB,
        "vocabulary": vocab,
        "idf": [float(v) for v in vec.idf_],
        "coef": [float(v) for v in clf.coef_[0]],
        "intercept": float(clf.intercept_[0]),
        "cv_group_kfold": {
            "precision": round(float(np.mean(precs)), 4),
            "recall": round(float(np.mean(recs)), 4),
            "f1": round(float(np.mean(f1s)), 4),
            "n_splits": 5,
        },
        "n_features": len(vocab),
        "trained_on": {"n": len(rows), "malicious": int(y.sum()),
                       "benign": int((1 - y).sum())},
    }
    with open(MODEL_OUT, "w", encoding="utf-8") as fh:
        json.dump(model, fh, ensure_ascii=False)
    sys.stderr.write("wrote %s (%d features)\n" % (MODEL_OUT, len(vocab)))

    # ---- Parity check: pure-Python inference must match sklearn ----------- #
    _parity_check(vec, clf, texts[:25], y[:25])
    return 0


def _parity_check(vec, clf, texts, y):
    """Confirm engine/ml.py reproduces sklearn probabilities closely."""
    try:
        sys.path.insert(0, ROOT)
        from engine import ml as engine_ml
        engine_ml._load()  # force reload of freshly-written model
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write("parity check skipped: %r\n" % exc)
        return
    import numpy as np
    proba = clf.predict_proba(vec.transform(texts))[:, 1]
    diffs = []
    for t, p in zip(texts, proba):
        q = engine_ml.predict(t)
        diffs.append(abs(p - q))
    sys.stderr.write("parity: max|Δ|=%.4g mean|Δ|=%.4g (sklearn vs pure-python)\n"
                     % (float(np.max(diffs)), float(np.mean(diffs))))


if __name__ == "__main__":
    sys.exit(main())
