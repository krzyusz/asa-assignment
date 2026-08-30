# syntax=docker/dockerfile:1

###############################################################################
# VulnTracker notification service — production image (notify/)
#
# - Minimal Node 20 base image, pinned by tag AND digest
# - Multi-stage: install prod-only deps in a builder, ship a lean runtime
# - Runs as the built-in unprivileged `node` user
# - Container-level HEALTHCHECK against /health
# - No secrets baked in
#
# Build context is the REPO ROOT (so compose can share one context):
#   docker build -f notify/Dockerfile -t vulntracker-notify .
###############################################################################

ARG NODE_IMAGE=node:20-bookworm-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0

# ---------------------------------------------------------------------------
# Stage 1 — builder: install production dependencies only
# ---------------------------------------------------------------------------
FROM ${NODE_IMAGE} AS builder

WORKDIR /app

COPY notify/package.json notify/package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

# ---------------------------------------------------------------------------
# Stage 2 — runtime
# ---------------------------------------------------------------------------
FROM ${NODE_IMAGE} AS runtime

ENV NODE_ENV=production \
    PORT=3001

# tini for correct PID 1 signal handling / zombie reaping.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends tini; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node notify/package.json ./package.json
COPY --chown=node:node notify/src ./src

USER node

EXPOSE 3001

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["node", "-e", "require('http').get('http://127.0.0.1:'+(process.env.PORT||3001)+'/health',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"]

# -s: run as a subreaper even when not PID 1, so `docker run` without --init is fine.
ENTRYPOINT ["tini", "-s", "--"]
CMD ["node", "src/index.js"]
