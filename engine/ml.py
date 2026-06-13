# -*- coding: utf-8 -*-
"""Frozen ML model inference in PURE standard library.

The model is trained offline with scikit-learn (selftest/train_model.py) and
exported to model.json as: vocabulary (token->index), idf array, logistic
coefficients, intercept, the brand-scrub regex list, and the ngram range. At
runtime we re-implement TfidfVectorizer(norm='l2', use_idf=True) + Logistic
Regression decision in pure Python, so the shipped image needs no third-party
dependency and inference is fully deterministic.

If model.json is absent or malformed, predict() returns 0.0 and the engine
degrades gracefully to rule-only (still fully functional).
"""

import json
import math
import os
import re

_MODEL = None
_LOADED = False
_TOKEN_RE = re.compile(r"\b\w\w+\b", re.UNICODE)
_SCRUB_RES = []

_MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.json")


def _load():
    global _MODEL, _LOADED, _SCRUB_RES
    _LOADED = True
    try:
        with open(_MODEL_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        _MODEL = None
        return
    # Basic shape validation.
    if not all(k in data for k in ("vocabulary", "idf", "coef", "intercept")):
        _MODEL = None
        return
    _MODEL = data
    _SCRUB_RES = []
    for pat in data.get("scrub", []):
        try:
            _SCRUB_RES.append(re.compile(pat, re.IGNORECASE))
        except re.error:
            pass


def _scrub(text):
    for rx in _SCRUB_RES:
        text = rx.sub(" ", text)
    return text


def _features(text, ngram_max):
    """Replicate sklearn word n-gram tokenisation (lowercase, \\b\\w\\w+\\b)."""
    text = _scrub(text.lower())
    toks = _TOKEN_RE.findall(text)
    counts = {}
    n = len(toks)
    for i in range(n):
        counts[toks[i]] = counts.get(toks[i], 0) + 1
    if ngram_max >= 2:
        for i in range(n - 1):
            g = toks[i] + " " + toks[i + 1]
            counts[g] = counts.get(g, 0) + 1
    return counts


def predict(text):
    """Return P(malicious) in [0,1] for ``text``. Never raises."""
    if not _LOADED:
        _load()
    if _MODEL is None or not text:
        return 0.0
    try:
        vocab = _MODEL["vocabulary"]
        idf = _MODEL["idf"]
        coef = _MODEL["coef"]
        intercept = float(_MODEL["intercept"])
        ngram_max = int(_MODEL.get("ngram_max", 2))

        counts = _features(text, ngram_max)
        # Build sparse tf-idf vector (index -> value) then L2-normalise.
        vec = {}
        norm_sq = 0.0
        for term, cnt in counts.items():
            idx = vocab.get(term)
            if idx is None:
                continue
            val = cnt * idf[idx]
            vec[idx] = val
            norm_sq += val * val
        if norm_sq <= 0.0:
            return _sigmoid(intercept)
        inv_norm = 1.0 / math.sqrt(norm_sq)
        decision = intercept
        for idx, val in vec.items():
            decision += (val * inv_norm) * coef[idx]
        return _sigmoid(decision)
    except (KeyError, IndexError, TypeError, ValueError):
        return 0.0


def _sigmoid(x):
    if x >= 0:
        z = math.exp(-x)
        return 1.0 / (1.0 + z)
    z = math.exp(x)
    return z / (1.0 + z)


def is_available():
    if not _LOADED:
        _load()
    return _MODEL is not None
