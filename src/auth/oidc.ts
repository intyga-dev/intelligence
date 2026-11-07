import crypto from "node:crypto"
import { createRemoteJWKSet, jwtVerify } from "jose"
import { decryptSecret, encryptSecret } from "../store/crypto.ts"

// Signing in with INTYGA (core ADR 030).
//
// INTYGA is Intelligence's identity provider: a standard OpenID Connect authorization-code flow
// with PKCE against the gateway, where the person approves the sign-in with the same passkey they
// use for the console. The id_token names the person (`sub`, `email`, `name`), the workspace
// (`tenant_id`) and their role there (`role`: ADMIN or MEMBER). The gateway mints one only for an
// active member of the client's workspace, so "every Intelligence user is an INTYGA user" is
// enforced at the identity provider, not claimed here.
//
// What this module trusts: the gateway's RS256 key (fetched from its JWKS), the issuer and audience
// pinned to the bound gateway and client id, and nothing the browser says. State and the PKCE
// verifier live in an encrypted, HttpOnly cookie for the few minutes a sign-in takes.

export class AuthError extends Error {}

export const LOGIN_COOKIE = "intelligence_login"
const LOGIN_TTL_MS = 10 * 60_000

export interface OidcBinding {
  baseUrl: string
  /** Server-only route to the same gateway. The public baseUrl remains the verified issuer. */
  transportUrl?: string
  clientId: string
  /** The bound workspace. A token for any other workspace is refused, however valid. */
  workspaceId: string | null
}

export type Role = "ADMIN" | "MEMBER"

export interface SignedInPerson {
  email: string
  name: string
  tenantId: string
  role: Role
}

interface LoginState {
  state: string
  verifier: string
  startedAt: number
}

const b64url = (buf: Buffer) => buf.toString("base64url")

/** PKCE S256: the verifier never leaves this server; the challenge is what the gateway sees. */
export function pkce(): { verifier: string; challenge: string } {
  const verifier = b64url(crypto.randomBytes(48))
  const challenge = b64url(crypto.createHash("sha256").update(verifier).digest())
  return { verifier, challenge }
}

/** Where the gateway sends the person back. One fixed path on this instance's own origin. */
export function callbackUrl(origin: string): string {
  return new URL("/auth/callback", origin).toString()
}

/**
 * Begin a sign-in: the redirect to the gateway and the cookie that lets the callback finish it.
 * `loginHint` is only a convenience for the gateway's form; the gateway decides who the person is.
 */
export function beginLogin(
  binding: OidcBinding,
  origin: string,
  loginHint?: string,
): { redirectTo: string; cookie: string } {
  const { verifier, challenge } = pkce()
  const state = b64url(crypto.randomBytes(24))
  const url = new URL("/oauth/authorize", binding.baseUrl)
  url.searchParams.set("client_id", binding.clientId)
  url.searchParams.set("redirect_uri", callbackUrl(origin))
  url.searchParams.set("response_type", "code")
  url.searchParams.set("scope", "openid email profile")
  url.searchParams.set("state", state)
  url.searchParams.set("code_challenge", challenge)
  url.searchParams.set("code_challenge_method", "S256")
  if (loginHint) url.searchParams.set("login_hint", loginHint)
  const payload: LoginState = { state, verifier, startedAt: Date.now() }
  return { redirectTo: url.toString(), cookie: encryptSecret(JSON.stringify(payload)) }
}

function readLoginState(cookie: string | undefined): LoginState {
  if (!cookie) throw new AuthError("no sign-in in progress — start again")
  const json = decryptSecret(cookie)
  if (!json) throw new AuthError("the sign-in cookie is not readable — start again")
  let parsed: unknown
  try {
    parsed = JSON.parse(json)
  } catch {
    throw new AuthError("the sign-in cookie is not readable — start again")
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
    throw new AuthError("the sign-in cookie is not readable — start again")
  const s = parsed as Partial<LoginState>
  if (typeof s.state !== "string" || typeof s.verifier !== "string" || typeof s.startedAt !== "number")
    throw new AuthError("the sign-in cookie is not readable — start again")
  if (Date.now() - s.startedAt > LOGIN_TTL_MS) throw new AuthError("the sign-in took too long — start again")
  return { state: s.state, verifier: s.verifier, startedAt: s.startedAt }
}

function sameString(a: string, b: string): boolean {
  const x = crypto.createHash("sha256").update(a).digest()
  const y = crypto.createHash("sha256").update(b).digest()
  return crypto.timingSafeEqual(x, y)
}

/** jose caches the key set per URL; one set per gateway for the life of the process. */
const jwksByIssuer = new Map<string, ReturnType<typeof createRemoteJWKSet>>()
function jwks(baseUrl: string) {
  let set = jwksByIssuer.get(baseUrl)
  if (!set) {
    set = createRemoteJWKSet(new URL("/oauth/jwks", baseUrl))
    jwksByIssuer.set(baseUrl, set)
  }
  return set
}

/**
 * Finish a sign-in: redeem the code with the PKCE verifier, verify the id_token against the
 * gateway's keys, issuer and this client id, and return who signed in. The caller creates the
 * session; this module never touches the database.
 */
export async function completeLogin(
  binding: OidcBinding,
  origin: string,
  query: { code?: string; state?: string; error?: string },
  cookie: string | undefined,
  fetchImpl: typeof fetch = fetch,
): Promise<SignedInPerson> {
  if (query.error) throw new AuthError("INTYGA did not complete the sign-in")
  const login = readLoginState(cookie)
  if (!query.state || !sameString(query.state, login.state))
    throw new AuthError("the sign-in does not match this browser")
  if (!query.code || query.code.length > 2048) throw new AuthError("INTYGA returned no sign-in code")

  let res: Response
  const transportUrl = binding.transportUrl ?? binding.baseUrl
  try {
    res = await fetchImpl(new URL("/oauth/token", transportUrl), {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: query.code,
        code_verifier: login.verifier,
        client_id: binding.clientId,
        redirect_uri: callbackUrl(origin),
      }).toString(),
    })
  } catch (err) {
    throw new AuthError("INTYGA unreachable", { cause: err })
  }
  if (!res.ok) throw new AuthError("INTYGA refused the sign-in code")
  const body = (await res.json().catch(() => null)) as { id_token?: unknown } | null
  if (!body || typeof body.id_token !== "string") throw new AuthError("INTYGA returned no id_token")

  let claims: Record<string, unknown>
  try {
    const verified = await jwtVerify(body.id_token, jwks(transportUrl), {
      issuer: binding.baseUrl,
      audience: binding.clientId,
      algorithms: ["RS256"],
      requiredClaims: ["sub", "iat", "exp"],
    })
    claims = verified.payload as Record<string, unknown>
  } catch (err) {
    throw new AuthError("the id_token from INTYGA does not verify", { cause: err })
  }
  const email = typeof claims.email === "string" ? claims.email.trim().toLowerCase() : ""
  const tenantId = typeof claims.tenant_id === "string" ? claims.tenant_id : ""
  const role = claims.role === "ADMIN" ? "ADMIN" : claims.role === "MEMBER" ? "MEMBER" : null
  if (typeof claims.sub !== "string" || !claims.sub.trim() || !email || !tenantId || !role)
    throw new AuthError("the id_token from INTYGA is missing who signed in")
  if (binding.workspaceId && tenantId !== binding.workspaceId)
    throw new AuthError("that INTYGA account belongs to a different workspace than this instance is bound to")
  const name = typeof claims.name === "string" && claims.name.trim() ? claims.name.trim() : email
  return { email, name, tenantId, role }
}
