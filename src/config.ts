// Configuration, resolved once at startup and fail-closed where it matters.
//
// The house rule borrowed from the system this observes: a dev default is fine, but production must
// throw rather than silently run on a placeholder. The one deliberate exception is the judgment
// provider — see `judgment` below, where UNSET is a legitimate, documented configuration rather
// than a misconfiguration.

const WEAK = new Set([
  "dev-tick-token-change-me",
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

  /**
   * Intyga as Intelligence's Relying Party — REQUIRED, not optional.
   *
   * Intelligence has no authentication of its own. Admins are Intyga PLATFORM_SUBJECTs who enrol a
   * passkey on Intelligence's own origin, and every privileged action is a hash-only signing
   * ceremony against that passkey. Unset means privileged actions are refused outright; it never
   * means they are allowed.
   *
   * The credential is a PLATFORM-scoped key (subjects:write, credentials:write, receipts:create,
   * receipts:read) authenticating by private_key_jwt. It acts only on Intelligence's own subjects
   * and cannot approve, bypass or read anything in Intyga's own plane.
   */
  rp: {
    baseUrl: process.env.INTYGA_RP_URL ?? null,
    clientId: process.env.INTYGA_RP_CLIENT_ID ?? null,
    /** PKCS#8 PEM. Newlines may be \n-escaped for environments that cannot carry them. */
    privateKeyPem: (process.env.INTYGA_RP_PRIVATE_KEY ?? "").replace(/\\n/g, "\n") || null,
    /** Our own WebAuthn RP ID and origin — the domain Intelligence is served from. */
    rpId: process.env.INTYGA_RP_ID ?? null,
    origin: process.env.INTYGA_RP_ORIGIN ?? null,
    timeoutMs: num("INTYGA_RP_TIMEOUT_MS", 10_000),
  },

  github: {
    /** Read-only. The connector never writes, and the token must not be able to. */
    token: process.env.GITHUB_TOKEN ?? null,
    apiBase: process.env.GITHUB_API_BASE ?? "https://api.github.com",
  },
} as const

export type Config = typeof config
