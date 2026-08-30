# syntax=docker/dockerfile:1

###############################################################################
# VulnTracker API — production image for the FastAPI service (app/)
#
# - Minimal base image, pinned by tag AND digest
# - Multi-stage: build deps in a throwaway stage, ship only a venv + source
# - Runs as a non-root user (uid/gid 10001)
# - Container-level HEALTHCHECK against /health
# - No secrets baked in: all configuration comes from environment variables
###############################################################################

ARG PYTHON_IMAGE=python:3.11-slim-bookworm@sha256:0bee7276f83efd4a1ee05bbbf4281d95ed28e079220a9457f25a93e3f1e3c31b

# ---------------------------------------------------------------------------
# Stage 1 — builder: install dependencies into an isolated virtualenv
# ---------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

# Copy only the dependency manifest first so this layer is cached until it changes.
COPY requirements.txt .

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# ---------------------------------------------------------------------------
# Stage 2 — runtime: minimal image with just the venv and application source
# ---------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    # Default DB location: a writable volume, so the root FS can stay read-only.
    DATABASE_URL="sqlite:////data/vulntracker.db"

# tini gives us a real init: correct signal forwarding and zombie reaping.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends tini; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd --gid 10001 appuser; \
    useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin appuser; \
    mkdir -p /data; \
    chown appuser:appuser /data

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
# The app uses bare imports and must run with app/ as the working directory.
COPY --chown=appuser:appuser app/ /app/

USER appuser

EXPOSE 8000

VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"]

# -s: run as a subreaper even when not PID 1, so `docker run` without --init is fine.
ENTRYPOINT ["tini", "-s", "--"]
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
