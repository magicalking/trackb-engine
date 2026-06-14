# -*- coding: utf-8 -*-
"""Gray-zone semantic layer (gated, optional, upward-only, exception-safe).

Runs ONLY on a SUSPICIOUS verdict (the gray zone) and can only PROMOTE it to
malicious — it never downgrades a verdict and never convicts a clear case. This
mirrors the SkillSieve L1->L2 design: the cheap deterministic layer triages the
~85-90% obvious cases; the semantic layer adjudicates only the residual gray.

Two adjudicators, both safe to ship:
  1. Intent-vs-capability mismatch (pure Python, always available). A skill that
     *describes itself* as innocuous (formatter / notes / converter) while
     carrying a STRONG dangerous capability (reverse shell, decode-pipe-shell,
     credential egress, instruction-level exfil, hidden decoded payload) is the
     "disguised malware" pattern that static suppression and the bag-of-words ML
     both miss. This is MalSkillBench's strongest discriminator.
  2. Optional ONNX prompt-injection classifier. If a model is bundled at
     engine/models/ AND onnxruntime is importable, its probability on the prose
     can also promote a gray verdict. Absent either, this is a silent no-op, so
     the engine stays 100% deterministic and the performance score is unaffected.

Any error anywhere -> return None (no promotion). The deterministic path is never
put at risk.
"""

import os

from engine import constants as C

# Strong dangerous-capability signals: their presence in a merely-"suspicious"
# skill is the tell that suppression (security-tool / DeFi context) or the ML
# under-counted a real threat.
_STRONG_CAP = (
    "S_reverse_shell", "S_decode_pipe_shell", "S_decode_exec_call",
    "S_cred_harvest_egress", "S_cmd_output_exfil", "S_data_exfil_instruction",
    "S_decoded_payload", "S_pipe_to_shell", "S_external_binary_run",
)
_BENIGN_TERMS = (
    "format", "convert", "lint", "style", "note", "todo", "markdown", "summar",
    "translat", "spell", "grammar", "emoji", "color", "theme", "template",
    "snippet", "calendar", "reminder", "weather", "unit", "todo", "wallpaper",
)
_SECURITY_TERMS = (
    "security", "forensic", "malware", "pentest", "penetration", "exploit",
    "reverse engineer", "incident", "threat", "red team", "blue team", "ctf",
    "sandbox", "honeypot", "yara", "detection", "audit",
)


def _benign_intent(doc):
    """True if the skill describes itself as innocuous (and not a security tool)."""
    man = getattr(doc, "manifest", None)
    desc = (getattr(man, "description", "") or "") if man else ""
    name = (getattr(man, "name", "") or "") if man else ""
    blob = (desc + " " + name).lower().strip()
    if not blob:
        return False
    if any(t in blob for t in _SECURITY_TERMS):
        return False
    return any(t in blob for t in _BENIGN_TERMS)


# --------------------------------------------------------------------------- #
# Optional ONNX prompt-injection classifier (lazy, fully degradable).          #
# --------------------------------------------------------------------------- #
_ONNX = None
_ONNX_TRIED = False
_MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")


def _load_onnx():
    global _ONNX, _ONNX_TRIED
    _ONNX_TRIED = True
    try:
        model_path = os.path.join(_MODEL_DIR, "prompt_injection.onnx")
        vocab_path = os.path.join(_MODEL_DIR, "vocab.txt")
        if not (os.path.exists(model_path) and os.path.exists(vocab_path)):
            _ONNX = None
            return
        import onnxruntime  # noqa: F401  (only if bundled)
        from engine import wordpiece  # tiny bundled tokenizer (optional)
        sess = onnxruntime.InferenceSession(
            model_path, providers=["CPUExecutionProvider"])
        tok = wordpiece.Tokenizer(vocab_path)
        _ONNX = (sess, tok)
    except Exception:  # noqa: BLE001 - any failure => disabled
        _ONNX = None


def _onnx_injection_prob(text):
    if not text:
        return 0.0
    if not _ONNX_TRIED:
        _load_onnx()
    if _ONNX is None:
        return 0.0
    try:
        sess, tok = _ONNX
        ids, mask = tok.encode(text, max_len=512)
        import numpy as np
        out = sess.run(None, {"input_ids": np.array([ids], dtype="int64"),
                              "attention_mask": np.array([mask], dtype="int64")})
        logits = out[0][0]
        # softmax over 2 classes; index 1 = injection/malicious.
        m = max(logits)
        ex = [pow(2.718281828, float(v - m)) for v in logits]
        s = sum(ex) or 1.0
        return ex[-1] / s
    except Exception:  # noqa: BLE001
        return 0.0


def promote(doc, verdict, fired):
    """Return True to bump a gray (suspicious) verdict up to malicious."""
    try:
        if verdict != "suspicious":
            return False
        fired_ids = set(s.id for s in fired)
        if (fired_ids & set(_STRONG_CAP)) and _benign_intent(doc):
            return True
        if _onnx_injection_prob(doc.md) >= C.SEMANTIC_PI_THRESHOLD:
            return True
        return False
    except Exception:  # noqa: BLE001 - never break the deterministic path
        return False
