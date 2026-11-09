import assert from "node:assert/strict"
import crypto from "node:crypto"
import { after, before, beforeEach, test } from "node:test"
import { decryptSecret, encryptSecret } from "../store/crypto.ts"
import { CLIENT_ID, ORIGIN, stubGateway, WORKSPACE } from "../test/intyga.ts"
import { AuthError, beginLogin, completeLogin, pkce } from "./oidc.ts"

let gateway: Awaited<ReturnType<typeof stubGateway>>
before(async () => {
  gateway = await stubGateway()
})
beforeEach(() => gateway.reset())
after(async () => gateway.app.close())
function login() {
  const started = beginLogin(gateway.binding, ORIGIN, "admin@example.test")
  const url = new URL(started.redirectTo)
  return { ...started, url, query: { state: url.searchParams.get("state") ?? "", code: "one-time-code" } }
}

test("PKCE uses random URL-safe verifiers and the SHA-256 challenge", () => {
  const first = pkce()
  assert.match(first.verifier, /^[A-Za-z0-9_-]{43,128}$/)
  assert.equal(first.challenge, crypto.createHash("sha256").update(first.verifier).digest("base64url"))
  assert.notEqual(first.verifier, pkce().verifier)
})

test("sign-in roundtrip pins the client, callback, PKCE and verified workspace role", async () => {
  const started = login()
  assert.equal(started.url.origin, gateway.baseUrl)
  assert.equal(started.url.pathname, "/oauth/authorize")
  assert.equal(started.url.searchParams.get("client_id"), CLIENT_ID)
  assert.equal(started.url.searchParams.get("code_challenge_method"), "S256")
  assert.equal(started.url.searchParams.get("redirect_uri"), `${ORIGIN}/auth/callback`)
  assert.equal(started.url.searchParams.get("login_hint"), "admin@example.test")
  const person = await completeLogin(gateway.binding, ORIGIN, started.query, started.cookie)
  assert.deepEqual(person, {
    email: "admin@example.test",
    name: "Test Admin",
    tenantId: WORKSPACE,
    role: "ADMIN",
  })
  const exchange = gateway.state.tokenCalls[0]
  assert.equal(exchange?.get("client_id"), CLIENT_ID)
  assert.equal(exchange?.get("redirect_uri"), `${ORIGIN}/auth/callback`)
  assert.equal(exchange?.get("code"), started.query.code)
  assert.equal(
    crypto
      .createHash("sha256")
      .update(exchange?.get("code_verifier") ?? "")
      .digest("base64url"),
    started.url.searchParams.get("code_challenge"),
  )
})

test("state mismatch or missing code refuses before exchanging anything", async () => {
  const started = login()
  for (const query of [
    { ...started.query, state: "another-browser" },
    { code: "code" },
    { state: started.query.state },
    { ...started.query, error: "access_denied" },
  ]) {
    await assert.rejects(completeLogin(gateway.binding, ORIGIN, query, started.cookie), AuthError)
  }
  assert.equal(gateway.state.requests.length, 0)
})

test("missing, garbled, tampered and structurally invalid cookies refuse before exchange", async () => {
  const started = login()
  for (const cookie of [
    undefined,
    "garbled",
    `${started.cookie.slice(0, -8)}AAAAAAAA`,
    ...["null", "[]", "42", '"text"', "{", "{}", '{"state":7}'].map(encryptSecret),
  ]) {
    await assert.rejects(completeLogin(gateway.binding, ORIGIN, started.query, cookie), AuthError)
  }
  assert.equal(gateway.state.requests.length, 0)
})

test("a sign-in cookie expires after ten minutes", async () => {
  const started = login()
  const state = JSON.parse(decryptSecret(started.cookie) ?? "{}")
  const expired = encryptSecret(JSON.stringify({ ...state, startedAt: Date.now() - 600_001 }))
  await assert.rejects(completeLogin(gateway.binding, ORIGIN, started.query, expired), /took too long/)
  assert.equal(gateway.state.requests.length, 0)
})

test("a valid token for another workspace is refused", async () => {
  const started = login()
  gateway.state.claims.tenant_id = "other-workspace"
  await assert.rejects(
    completeLogin(gateway.binding, ORIGIN, started.query, started.cookie),
    /different workspace/,
  )
})

for (const claim of ["sub", "iat", "exp", "email", "tenant_id", "role"]) {
  test(`a signed token missing ${claim} is refused`, async () => {
    const started = login()
    delete gateway.state.claims[claim]
    await assert.rejects(completeLogin(gateway.binding, ORIGIN, started.query, started.cookie), AuthError)
  })
}
for (const [claim, value] of [
  ["aud", "another-client"],
  ["iss", "https://attacker.test"],
  ["exp", 1],
  ["role", "OWNER"],
  ["email", " "],
  ["sub", ""],
] as const) {
  test(`a token with invalid ${claim} is refused`, async () => {
    const started = login()
    gateway.state.claims = { ...gateway.state.claims, [claim]: value }
    await assert.rejects(completeLogin(gateway.binding, ORIGIN, started.query, started.cookie), AuthError)
  })
}

test("an internal gateway route never changes the public redirect or accepted issuer", async () => {
  const binding = {
    ...gateway.binding,
    baseUrl: "https://issuer.example.test",
    transportUrl: gateway.baseUrl,
  }
  const started = beginLogin(binding, ORIGIN)
  const url = new URL(started.redirectTo)
  assert.equal(url.origin, binding.baseUrl)
  const query = { state: url.searchParams.get("state") ?? "", code: "one-time-code" }
  gateway.state.claims.iss = binding.baseUrl
  assert.equal((await completeLogin(binding, ORIGIN, query, started.cookie)).tenantId, WORKSPACE)
  gateway.state.claims.iss = gateway.baseUrl
  await assert.rejects(completeLogin(binding, ORIGIN, query, started.cookie), /does not verify/)
})
