# Multi-stage build for the Next.js web app.
FROM node:22-slim AS builder

WORKDIR /app

# Copy root package files
COPY package.json package-lock.json ./

# Copy web workspace
COPY web/package.json web/
COPY web/next.config.ts web/

# DEV DEPENDENCIES ARE REQUIRED HERE. `next build` type-checks the app
# (CLAUDE.md: it is the ONLY thing that type-checks web/), which needs
# typescript and @types/*, both of which are devDependencies. `--omit=dev`
# was here and would have failed the build.
RUN npm ci --workspace=web

# Copy source code.
#
# `web/app` IS THE APPLICATION. It was missing from this list, which meant
# this image could never have built at all: Next exits with "Couldn't find
# any `pages` or `app` directory". Docker is not available in the dev
# container (CLAUDE.md), so nothing ever ran it.
COPY web/app ./web/app
COPY web/src ./web/src
COPY web/public ./web/public
COPY web/proxy.ts web/
COPY web/next-env.d.ts web/
COPY web/tsconfig.json web/
COPY tsconfig.base.json ./

# NEXT_PUBLIC_* IS INLINED AT BUILD TIME, NOT READ AT RUNTIME.
#
# Next statically replaces every `process.env.NEXT_PUBLIC_*` reference during
# `next build`, server code included. Setting it in docker-compose's
# `environment:` — which is what this file used to say it did, in a comment
# at the bottom — has no effect whatever on the built bundle: the container
# would start, and every page would fail because `apiBase()` found nothing.
#
# This was already known here and written down in playwright.config.ts, which
# rebuilds the web app for exactly this reason and says so at length. The
# Dockerfile simply never caught up.
#
# So it arrives as a build ARG. docker-compose.yml passes it under
# `build.args`, not only under `environment`.
ARG NEXT_PUBLIC_API_BASE_URL=http://api:3001
ENV NEXT_PUBLIC_API_BASE_URL=${NEXT_PUBLIC_API_BASE_URL}
# No usage reports to Vercel from the build (Next.js telemetry is on unless this is set).
ENV NEXT_TELEMETRY_DISABLED=1

WORKDIR /app/web
RUN npm run build

# Runtime stage
FROM node:22-slim

# OS security fixes newer than the base image (moon image scan)
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && rm -rf /var/lib/apt/lists/*

# The web image only runs `node web/server.js`: drop the bundled npm/npx (their own
# dependencies were the image's remaining HIGH findings).
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx

ENV NEXT_TELEMETRY_DISABLED=1

WORKDIR /app

# The node images already ship a non-root `node` user at UID 1000, so
# `useradd -m -u 1000 app` fails outright with "UID 1000 is not unique" — the
# build could never have reached this line. Use the user the base image gives
# us rather than minting a second one at the same id.
RUN chown -R node:node /app

# Copy Next.js standalone output from builder
COPY --from=builder --chown=node:node /app/web/.next/standalone /app
COPY --from=builder --chown=node:node /app/web/public ./web/public
COPY --from=builder --chown=node:node /app/web/.next/static ./web/.next/static

USER node

EXPOSE 3000

# The web service intentionally does NOT receive DATABASE_URL — CLAUDE.md
# rule 1, and the single most important boundary in this stack.
#
# `web/server.js`, not `server.js`. This is a workspace build, so Next's
# standalone output preserves the workspace layout and puts the entry point at
# `.next/standalone/web/server.js` — which is also why the two COPY lines above
# target `./web/public` and `./web/.next/static`. Verified against a real
# `next build` here; `web/public/` did not exist as a tracked directory until
# Phase 14 added the PWA icons, so this path had never actually been exercised.
#
# Next's standalone server listens on the address $HOSTNAME resolves to, and
# Docker sets HOSTNAME to the container id. With the container on two networks
# (its own + the reverse proxy's) that resolves to whichever network Docker
# attached first, so the proxy sometimes got "connection refused" (seen on moon
# 2026-11-15). Listen on every interface instead.
ENV HOSTNAME=0.0.0.0
CMD ["node", "web/server.js"]
