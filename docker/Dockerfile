# Track B blue-team detection engine.
# Pure standard-library runtime: NO pip install, NO network at build or run.
# Deterministic, offline. Built for a fixed sha256 digest submission.
FROM python:3.11-slim

# Reproducibility / determinism.
ENV PYTHONHASHSEED=0 \
    PYTHONUTF8=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

WORKDIR /app

# Copy only the engine package (model.json is bundled inside engine/).
COPY engine/ /app/engine/
COPY docker/entrypoint.sh /app/entrypoint.sh

# Drop to a non-root user; the engine only needs to read /data and write /output.
RUN chmod +x /app/entrypoint.sh \
    && useradd --create-home --uid 10001 scanner
USER scanner

# Default ranking interface. Overridable via `docker run ... --input --output`.
ENTRYPOINT ["/app/entrypoint.sh"]
