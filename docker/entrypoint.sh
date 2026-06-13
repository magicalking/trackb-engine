#!/bin/sh
# Track B engine entrypoint. Offline, deterministic.
# Reads /data/skills/{skill_id}/, writes /output/results.jsonl.
# Extra args are forwarded (e.g. --input/--output overrides for local testing).
set -eu

INPUT="${SKILLS_INPUT:-/data/skills}"
OUTPUT="${RESULTS_OUTPUT:-/output/results.jsonl}"

exec python -m engine.run_engine --input "$INPUT" --output "$OUTPUT" "$@"
