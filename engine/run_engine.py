# -*- coding: utf-8 -*-
"""Entry point: scan /data/skills, write /output/results.jsonl.

Contract (Track B 接口规范 §3): one JSON object per skill, fields exactly
{skill_id, verdict, confidence, category, evidence}. category is the uppercase
OWASP AST token (AST01..AST10) for positive verdicts, "" for benign. Guarantees:
  * one line per discovered skill_id (even empty / unreadable dirs)
  * never crashes the whole run (per-skill try/except -> conservative verdict)
  * deterministic, UTF-8, ensure_ascii=False, atomic write
The engine imports ONLY the standard library (no network, no external LLM).
"""

import argparse
import json
import os
import sys
import time

from engine import categorize, constants as C, evidence, loader, scoring, signals

DEFAULT_INPUT = "/data/skills"
DEFAULT_OUTPUT = "/output/results.jsonl"
RESULT_KEYS = ("skill_id", "verdict", "confidence", "category", "evidence")


def _to_ast_label(category):
    """Internal lowercase category -> §3 output token.

    'ast01'..'ast10' -> 'AST01'..'AST10'; benign / unknown -> '' (a clean skill
    has no OWASP AST main category). Exact-match explainability scoring needs the
    uppercase ASTxx form.
    """
    if category and category[:3].lower() == "ast":
        return category.upper()
    return ""


def analyze_doc(doc, fast=False):
    """Run the full pipeline on a loaded SkillDoc. Never raises.

    ``fast`` (set when the global time budget is exhausted) tells the scorer to
    skip the heavy gray-zone semantic model so the run still completes in time.
    """
    if doc.empty:
        return {
            "skill_id": doc.skill_id,
            "verdict": "benign",
            "confidence": 0.9,
            "category": "",
            "evidence": C.EMPTY_EVIDENCE,
        }
    fired = signals.scan(doc)
    res = scoring.score(doc, fired, fast=fast)
    category = categorize.categorize(res.verdict, res.fired)
    ev = evidence.build(doc, res, category)
    if not ev:
        ev = C.FRAME_BENIGN_CLEAN
    return {
        "skill_id": doc.skill_id,
        "verdict": res.verdict,
        "confidence": scoring.confidence(res),
        "category": _to_ast_label(category),
        "evidence": ev,
    }


def analyze_skill(input_dir, skill_id, fast=False):
    """Load + analyze one skill_id with full crash isolation."""
    try:
        doc = loader.load_skill(input_dir, skill_id)
        return analyze_doc(doc, fast=fast)
    except Exception as exc:  # noqa: BLE001 - intentional catch-all per skill
        sys.stderr.write("ERROR analyzing %s: %r\n" % (skill_id, exc))
        return {
            "skill_id": skill_id,
            "verdict": "suspicious",
            "confidence": 0.4,
            "category": _to_ast_label(C.ERROR_CATEGORY),
            "evidence": C.ERROR_EVIDENCE,
        }


def _dump_line(obj):
    # Fixed key order, UTF-8, no ASCII escaping, compact separators.
    ordered = {k: obj[k] for k in RESULT_KEYS}
    return json.dumps(ordered, ensure_ascii=False, separators=(",", ":"))


def run(input_dir, output_path):
    """Process all skills and stream results.jsonl. Returns count.

    Streaming (vs a single atomic write at the end) is deliberate: if the run is
    killed at the 30-minute wall (§4 "超时按已完成部分计分"), every completed line
    is already on disk, so the completed portion still scores. A global time
    budget switches the tail to the fast rule-only path so the run finishes and
    no skill is left without a result line.
    """
    skills = loader.discover_skills(input_dir)

    out_dir = os.path.dirname(os.path.abspath(output_path))
    try:
        os.makedirs(out_dir, exist_ok=True)
    except OSError:
        pass

    start = time.monotonic()
    n = 0
    with open(output_path, "w", encoding="utf-8", newline="\n") as fh:
        for skill_id in skills:
            fast = (time.monotonic() - start) >= C.MAX_RUNTIME_SECONDS
            obj = analyze_skill(input_dir, skill_id, fast=fast)
            fh.write(_dump_line(obj))
            fh.write("\n")
            n += 1
            if n % C.FLUSH_EVERY == 0:
                fh.flush()
        fh.flush()
    return n


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Track B agent-skill malware detection engine")
    parser.add_argument("--input", default=DEFAULT_INPUT,
                        help="input root holding skill_id subdirectories")
    parser.add_argument("--output", default=DEFAULT_OUTPUT,
                        help="path to results.jsonl")
    args = parser.parse_args(argv)

    n = run(args.input, args.output)
    sys.stderr.write("Track B engine: wrote %d result line(s) to %s\n"
                     % (n, args.output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
