import crypto from "node:crypto"
import { config } from "../config.ts"
import { type GateIntent, intentDigest } from "./intent.ts"

// Intelligence is an Intyga RELYING PARTY (DIV §5c, the platform integration plane).
//
// This is the product model, not an add-on: you cannot use Intelligence without Intyga, because
// Intyga *is* Intelligence's identity and approval layer. Intelligence's own admins are Intyga
// PLATFORM_SUBJECTs, they enrol a passkey on Intelligence's own domain, and every privileged action
// here — activating a connector, enabling the judgment provider, purging data — is a hash-only
// signing ceremony against that passkey.
//
// Because every tenant therefore already has an Intyga relationship, the Intyga *data* connector is
// built in and merely activated, rather than configured from nothing.
//
// The boundary, restated precisely now that Intyga is a dependency rather than only a source:
//
//   Intelligence holds PLATFORM-scoped credentials — subjects:write, credentials:write,
//   receipts:create, receipts:read — which act only on Intelligence's OWN subjects. They cannot
//   approve anything in Intyga's own plane, cannot read its audit log, cannot touch policy, cannot
//   reach another tenant. And signing is HASH-ONLY: Intyga receives a SHA-256 digest and never the
//   payload, so what an Intelligence admin approved is not disclosed to Intyga at all.
//
// Authentication is `private_key_jwt` (RFC 7523) only — the platform plane refuses a static secret.

export { type GateIntent, type GatedAction, intentDigest } from "./intent.ts"

export class GateError extends Error {}
export class GateRefused extends GateError {}
export class GateUnavailable extends GateError {}
export class GateNotConfigured extends GateError {}

export interface GateConfig {
  baseUrl: string
  clientId: string
  /** PKCS#8 PEM for the P-256 key whose public half is registered with Intyga. */
  privateKeyPem: string
  rpId: string
  origin: string
}

/**
 * Resolve a tenant's RP binding.
 *
 * Per tenant, not global: the binding names the tenant's OWN Intyga workspace, so their admins are
 * their own platform subjects and their approvals meter against their own plan. Environment
 * variables are a BOOTSTRAP only — they seed the first tenant before there is a row to read, which
 * is how a deployment gets off the ground without a chicken-and-egg problem. A stored binding
 * always wins.
 */
export function resolveGateConfig(tenant: TenantRpBinding | null): GateConfig {
  const cfg = bindingFor(tenant)
  if (!cfg) {
    throw new GateNotConfigured(
      "This tenant has no Intyga Relying-Party binding. Intelligence requires Intyga for " +
        "authentication and approvals — bind the tenant's Intyga workspace before using privileged actions.",
    )
  }
  return cfg
}

export interface TenantRpBinding {
  intygaBaseUrl: string | null
  intygaClientId: string | null
  /** Already decrypted by the caller — this module never touches the key store. */
  intygaPrivateKeyPem: string | null
  intygaRpId: string | null
  intygaOrigin: string | null
}

function bindingFor(tenant: TenantRpBinding | null): GateConfig | null {
  const baseUrl = tenant?.intygaBaseUrl ?? config.rp.baseUrl
  const clientId = tenant?.intygaClientId ?? config.rp.clientId
  const privateKeyPem = tenant?.intygaPrivateKeyPem ?? config.rp.privateKeyPem
  const rpId = tenant?.intygaRpId ?? config.rp.rpId
  const origin = tenant?.intygaOrigin ?? config.rp.origin
  if (!baseUrl || !clientId || !privateKeyPem || !rpId || !origin) return null
  return { baseUrl, clientId, privateKeyPem, rpId, origin }
}

export function rpConfigured(tenant: TenantRpBinding | null = null): boolean {
  return bindingFor(tenant) !== null
}

// ─── private_key_jwt ─────────────────────────────────────────────────────────────────────────────

function b64url(buf: Buffer): string {
  return buf.toString("base64url")
}

/**
 * Build and sign an ES256 client assertion.
 *
 * `jti` is random and the window is short because the gateway keeps a replay guard on it; reusing
 * an assertion is refused rather than tolerated.
 */
function clientAssertion(cfg: GateConfig): string {
  const now = Math.floor(Date.now() / 1000)
  const header = { alg: "ES256", typ: "JWT" }
  const claims = {
    iss: cfg.clientId,
    sub: cfg.clientId,
    aud: `${cfg.baseUrl}/oauth/token`,
    jti: crypto.randomUUID(),
    iat: now,
    exp: now + 60,
  }
  const signingInput = `${b64url(Buffer.from(JSON.stringify(header)))}.${b64url(
    Buffer.from(JSON.stringify(claims)),
  )}`
  // JWS ES256 requires the raw R||S form, not the DER encoding Node produces by default.
  const signature = crypto.sign("sha256", Buffer.from(signingInput), {
    key: crypto.createPrivateKey(cfg.privateKeyPem),
    dsaEncoding: "ieee-p1363",
  })
  return `${signingInput}.${b64url(signature)}`
}

interface Cached {
  token: string
  expiresAt: number
}
// Keyed by client id: with a per-tenant binding a single global slot would hand one tenant's token
// to another tenant's request — the exact cross-tenant confusion this design exists to avoid.
const tokenCache = new Map<string, Cached>()

async function call(url: string, init: RequestInit, timeoutMs: number): Promise<Response> {
  const ac = new AbortController()
  const timer = setTimeout(() => ac.abort(), timeoutMs)
  try {
    return await fetch(url, { ...init, signal: ac.signal })
  } catch (err) {
    // An unreachable gate is never an approval. Fail closed.
    //
    // The fetch error stays on `cause`, not in the message: GateError messages are returned to the
    // browser, and undici's text embeds the URL it was handed.
    const timedOut = (err as Error).name === "AbortError"
    throw new GateUnavailable(timedOut ? "Intyga did not answer in time" : "Intyga unreachable", {
      cause: err,
    })
  } finally {
    clearTimeout(timer)
  }
}

async function accessToken(cfg: GateConfig): Promise<string> {
  const hit = tokenCache.get(cfg.clientId)
  if (hit && hit.expiresAt > Date.now() + 30_000) return hit.token

  const res = await call(
    `${cfg.baseUrl}/oauth/token`,
    {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: clientAssertion(cfg),
      }),
    },
    config.rp.timeoutMs,
  )
  if (!res.ok) throw new GateUnavailable(`token exchange failed: HTTP ${res.status}`)
  const body = (await res.json()) as { access_token?: string; expires_in?: number }
  if (!body.access_token) throw new GateUnavailable("token exchange returned no access_token")
  const fresh = { token: body.access_token, expiresAt: Date.now() + (body.expires_in ?? 900) * 1000 }
  tokenCache.set(cfg.clientId, fresh)
  return fresh.token
}

async function authed(cfg: GateConfig, path: string, init: RequestInit = {}): Promise<Response> {
  return call(
    `${cfg.baseUrl}${path}`,
    {
      ...init,
      headers: {
        ...(init.headers ?? {}),
        authorization: `Bearer ${await accessToken(cfg)}`,
        ...(init.body ? { "content-type": "application/json" } : {}),
      },
    },
    config.rp.timeoutMs,
  )
}

// ─── Subjects and credentials ────────────────────────────────────────────────────────────────────

/** Register an Intelligence admin as a platform subject. Idempotent: 409 means already present. */
export async function ensureSubject(
  cfg: GateConfig,
  externalId: string,
  claims?: Record<string, unknown>,
): Promise<void> {
  const res = await authed(cfg, "/platform/subjects", {
    method: "POST",
    body: JSON.stringify({ externalId, ...(claims ? { claims } : {}) }),
  })
  if (res.status === 409) return
  if (!res.ok) throw new GateUnavailable(`subject creation failed: HTTP ${res.status}`)
}

export async function registrationOptions(cfg: GateConfig, externalId: string): Promise<unknown> {
  const res = await authed(cfg, "/platform/credentials/register/options", {
    method: "POST",
    body: JSON.stringify({ externalId, origin: cfg.origin, rpId: cfg.rpId }),
  })
  if (!res.ok) throw new GateUnavailable(`registration options failed: HTTP ${res.status}`)
  return res.json()
}

export async function registerCredential(
  cfg: GateConfig,
  externalId: string,
  response: unknown,
): Promise<void> {
  const res = await authed(cfg, "/platform/credentials/register/verify", {
    method: "POST",
    body: JSON.stringify({ externalId, response }),
  })
  if (!res.ok) throw new GateRefused(`credential registration refused: HTTP ${res.status}`)
}

// ─── The gate itself ─────────────────────────────────────────────────────────────────────────────

export interface SignChallenge {
  nonce: string
  expiresAt: string
  /** WebAuthn assertion options, handed to the browser on Intelligence's own origin. */
  options: unknown
  payloadHash: string
}

/** Open a signing ceremony bound to this exact intent. */
export async function openChallenge(
  cfg: GateConfig,
  externalId: string,
  intent: GateIntent,
): Promise<SignChallenge> {
  const payloadHash = intentDigest(intent)
  const res = await authed(cfg, "/platform/sign/challenges", {
    method: "POST",
    body: JSON.stringify({
      externalId,
      payloadHash,
      origin: cfg.origin,
      rpId: cfg.rpId,
      expiresInSeconds: 180,
    }),
  })
  if (res.status === 403) throw new GateRefused("Intyga refused the signing request")
  if (!res.ok) throw new GateUnavailable(`sign challenge failed: HTTP ${res.status}`)
  const body = (await res.json()) as { nonce?: string; expiresAt?: string; options?: unknown }
  if (!body.nonce) throw new GateUnavailable("sign challenge returned no nonce")
  return {
    nonce: body.nonce,
    expiresAt: body.expiresAt ?? "",
    options: body.options,
    payloadHash,
  }
}

export interface CompletedReceipt {
  receipt: { canonicalPayload?: string; [k: string]: unknown }
  ledger?: { receiptSeq?: number }
}

/**
 * Complete the ceremony with the browser's assertion and check the receipt binds OUR intent.
 *
 * ── Honest limit, stated rather than implied ──────────────────────────────────────────────────
 * These are STRUCTURAL checks against the canonical payload, plus TLS trust in the gateway. They
 * are not full offline verification: `verifyPlatformReceipt` in `@intyga/verify` re-derives the
 * canonical bytes and checks the subject's ES256 signature with no Intyga secret, which is what
 * makes a receipt independently trustworthy. That package is NOT published to npm yet (verified:
 * registry 404), and a partial re-implementation of a verifier carrying DIV Invariant 3 would be
 * more dangerous than an acknowledged gap — a subtly wrong signature check reads as a real one.
 *
 * So: what is enforced here is that the receipt names our nonce and our digest. What is NOT yet
 * enforced independently is the signature. Swap in verifyPlatformReceipt the moment it ships.
 */
export async function completeChallenge(
  cfg: GateConfig,
  challenge: SignChallenge,
  assertion: unknown,
): Promise<CompletedReceipt> {
  const res = await authed(cfg, `/platform/sign/challenges/${encodeURIComponent(challenge.nonce)}/complete`, {
    method: "POST",
    body: JSON.stringify({ response: assertion }),
  })
  if (!res.ok) throw new GateRefused(`signature refused: HTTP ${res.status}`)
  const body = (await res.json()) as CompletedReceipt

  const canonical = body.receipt?.canonicalPayload
  if (typeof canonical !== "string" || canonical.length === 0) {
    throw new GateRefused("receipt carried no canonical payload")
  }
  // The digest is OURS — recomputed from the intent, never read out of the receipt. A receipt for a
  // different action cannot satisfy this, which is the property the gate actually needs.
  if (!canonical.includes(challenge.payloadHash)) {
    throw new GateRefused("receipt does not bind the intent we asked to be approved")
  }
  if (!canonical.includes(challenge.nonce)) {
    throw new GateRefused("receipt is for a different challenge")
  }
  return body
}

export async function challengeStatus(cfg: GateConfig, nonce: string): Promise<{ status: string }> {
  const res = await authed(cfg, `/platform/sign/challenges/${encodeURIComponent(nonce)}`)
  if (!res.ok) throw new GateUnavailable(`status check failed: HTTP ${res.status}`)
  return (await res.json()) as { status: string }
}

/**
 * Prove the binding actually works, before someone needs it to.
 *
 * A stored binding that has never been exercised is a configuration someone will discover is wrong
 * at the worst moment — mid-incident, trying to turn a connector off. This does the real token
 * exchange, so it fails for the real reasons: wrong key, unregistered client, unreachable host.
 * It deliberately does not cache; the point is to test now, not to report what was true earlier.
 */
export async function testConnection(cfg: GateConfig): Promise<{ ok: true } | { ok: false; error: string }> {
  tokenCache.delete(cfg.clientId)
  try {
    await accessToken(cfg)
    return { ok: true }
  } catch (err) {
    // Anything that is not a GateError was thrown before a request left — in practice, the stored
    // key failing to parse or sign. Say that rather than echo a crypto library's text.
    return {
      ok: false,
      error:
        err instanceof GateError ? err.message : "the stored private key could not sign a client assertion",
    }
  }
}
