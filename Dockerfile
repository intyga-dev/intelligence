# Intyga Intelligence — runtime image.
#
# Multi-stage so the shipped image carries production dependencies and source only: no dev
# toolchain, no test fixtures, no build cache. Runs as a non-root user because a service whose whole
# job is reading other systems' telemetry should hold the least privilege that works.

FROM node:24-slim AS deps
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml ./
# Fetch into the store first so a lockfile-only change does not invalidate the whole layer.
RUN pnpm fetch --prod=false
COPY . .
RUN pnpm install --frozen-lockfile --offline

# Prisma's generated client is architecture-specific, so it is generated inside the image rather
# than copied from the host.
#
# `generate` reads no database, but prisma.config.ts resolves DIRECT_URL eagerly, so the build needs
# SOME value. It is deliberately one that cannot connect to anything (port 1 on loopback) rather
# than a plausible-looking default: a build-time placeholder that could accidentally resolve to a
# real host is how a build step ends up touching a live database.
RUN DIRECT_URL="postgresql://build:build@127.0.0.1:1/build" pnpm exec prisma generate

FROM node:24-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
RUN corepack enable && \
    apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/src ./src
COPY --from=deps /app/prisma ./prisma
COPY --from=deps /app/prisma.config.ts ./prisma.config.ts
COPY --from=deps /app/package.json ./package.json

# node:24-slim ships a `node` user (uid 1000). Reuse it rather than minting another.
USER node

EXPOSE 4100
# tsx runs the TypeScript sources directly, matching how the gateway in the Intyga monorepo is run.
CMD ["pnpm", "exec", "tsx", "src/server/main.ts"]
