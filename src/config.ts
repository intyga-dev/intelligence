// Configuration, resolved once at startup and fail-closed where it matters.
//
// The house rule borrowed from the system this observes: a dev default is fine, but production must
// throw rather than silently run on a placeholder. The one deliberate exception is the judgment
// provider — see `judgment` below, where UNSET is a legitimate, documented configuration rather
// than a misconfiguration.

import { publicOrigin } from "./selfhost/setup.ts"

const WEAK = new Set([
  "dev-tick-token-change-me",
  "dev-setup-token-change-me",
  "dev-secrets-enc-key-change-me-32b",
  "dev-local-only",
  "changeme",
  "secret",
])

export const isProdLike =
  (process.env.NODE_ENV ?? "development") !== "development" && process.env.NODE_ENV !== "test"

function required(name: string): string {
  const v = process.env[name]
  if (!v) throw new Error(`${name} is required`)
  return v
}

/** A secret with a dev fallback. In prod-like environments a missing or placeholder value throws. */
function secret(name: string, devDefault: string): string {
  const v = process.env[name]
  if (!isProdLike) return v || devDefault
  if (!v) throw new Error(`${name} must be set in production`)
  if (WEAK.has(v)) throw new Error(`${name} is still the development placeholder`)
  if (v.length < 16) throw new Error(`${name} is too short to be a real secret`)
  return v
}

function num(name: string, fallback: number): number {
  const raw = process.env[name]
  if (!raw) return fallback
  const n = Number(raw)
  if (!Number.isFinite(n)) throw new Error(`${name} must be a number, got ${raw}`)
  return n
}

export const config = {
  nodeEnv: process.env.NODE_ENV ?? "development",
  isProdLike,
  port: num("PORT", 4100),
  /** Canonical external origin when TLS terminates at a reverse proxy. */
  get publicUrl(): string | null {
    return process.env.PUBLIC_URL ? publicOrigin(process.env.PUBLIC_URL) : null
  },
  get intygaConsoleUrl(): string {
    return publicOrigin(process.env.INTYGA_CONSOLE_URL ?? "https://app.intyga.com")
  },

  /**
   * A getter, not a value.
   *
   * Resolved eagerly, a missing DATABASE_URL threw the moment ANY module imported config —
   * including a pure connector that only wanted an API base URL, and including every unit test of
   * it. Fail-closed is right; failing closed on import of an unrelated constant is not. The throw
   * now happens where the value is actually used.
   */
  get databaseUrl(): string {
    return required("DATABASE_URL")
  },

  /** Bearer token for POST /internal/tick. Held by the scheduler, not by a person. */
  get tickToken(): string {
    return secret("TICK_TOKEN", "dev-tick-token-change-me")
  },

  /** Encrypts per-connection secrets at rest. */
  get secretsEncKey(): string {
    return secret("SECRETS_ENC_KEY", "dev-secrets-enc-key-change-me-32b")
  },

  /**
   * Cost guards on the unauthenticated surface — see `src/server/ratelimit.ts` for what they do and
   * do not bound.
   *
   * Sized for a webhook endpoint, not an API: the global allowance absorbs a busy CI day across
   * every connector at once, and the per-connection one sits well above what a real producer sends.
   * Raise them rather than disabling them — a limiter that never fires in normal operation is still
   * what bounds the abnormal case.
   */
  ingestRate: {
    globalPerMinute: num("INGEST_RATE_GLOBAL_PER_MIN", 1_200),
    perConnectionPerMinute: num("INGEST_RATE_PER_CONNECTION_PER_MIN", 300),
  },

  /**
   * The optional semantic layer.
   *
   * `TYPESAFE_*` is the canonical spelling; the `JEV_*` names are the earlier ones and are still
   * read so an existing `.env` keeps working. Set one family, not both — the canonical name wins
   * silently, which is the wrong thing to debug at 2am.
   */
  judgment: {
    /**
     * Absent on purpose in most deployments. With no key the null provider runs: no request is
     * ever made, nothing leaves the host, and every deterministic detector still produces findings.
     * Turning this on is a data-protection decision (DPA + zero-data-retention), not a config tweak.
     */
    apiKey: process.env.TYPESAFE_API_KEY ?? process.env.JEV_API_KEY ?? null,
    model: process.env.TYPESAFE_MODEL ?? process.env.JEV_MODEL ?? "jev-latest",
    endpoint:
      process.env.TYPESAFE_ENDPOINT ?? process.env.JEV_ENDPOINT ?? "https://api.typesafe.ai/v1/systemone",
    timeoutMs: num("TYPESAFE_TIMEOUT_MS", 10_000),
  },

  /** Optional private route to the operator-configured public gateway. */
  intyga: {
    get baseUrl(): string | null {
      return process.env.INTYGA_URL ?? null
    },
    get internalUrl(): string | null {
      return process.env.INTYGA_INTERNAL_URL ?? null
    },
    timeoutMs: num("INTYGA_TIMEOUT_MS", 10_000),
  },

  github: {
    /** Read-only. The connector never writes, and the token must not be able to. */
    token: process.env.GITHUB_TOKEN ?? null,
    apiBase: process.env.GITHUB_API_BASE ?? "https://api.github.com",
  },
} as const

export type Config = typeof config
