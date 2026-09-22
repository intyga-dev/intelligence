import assert from "node:assert/strict"
import test from "node:test"
import { intentDigest } from "../gate/intent.ts"
import { loginDigest } from "./ceremony.ts"
import { clearCookie, COOKIE, readCookie, sessionCookie } from "./session.ts"

// The property worth pinning hardest: a login and a privileged action must never produce the same
// bytes to sign. If they could, a captured login assertion would be redeemable as an approval.

test("a login digest can never collide with an action digest", () => {
  const externalId = "ada"
  const challengeId = "11111111-2222-3333-4444-555555555555"

  const login = loginDigest({ externalId, challengeId })

  // The nearest an action could get: same parameter names, same values, action-shaped.
  const nearest = intentDigest({
    action: "intelligence.connector.activate",
    params: { externalId, challengeId },
  })
  assert.notEqual(login, nearest)

  // And the reverse — a login is not the digest of any action carrying the same fields.
  for (const action of [
    "intelligence.judgment.enable",
    "intelligence.data.purge",
    "intelligence.member.add",
    "intelligence.workspace.rebind",
  ] as const) {
    assert.notEqual(login, intentDigest({ action, params: { externalId, challengeId } }))
  }
})

test("each sign-in is bound to its own challenge id", () => {
  const a = loginDigest({ externalId: "ada", challengeId: "c1" })
  const b = loginDigest({ externalId: "ada", challengeId: "c2" })
  assert.notEqual(a, b, "reusing a digest across sign-ins would make one assertion replayable")
})

test("a login digest is bound to the subject", () => {
  assert.notEqual(
    loginDigest({ externalId: "ada", challengeId: "c1" }),
    loginDigest({ externalId: "grace", challengeId: "c1" }),
  )
})

test("login digests are lowercase 64-hex, as the platform plane requires", () => {
  assert.match(loginDigest({ externalId: "ada", challengeId: "c1" }), /^[0-9a-f]{64}$/)
})

test("the session cookie is HttpOnly, SameSite=Lax and scoped to the whole site", () => {
  const c = sessionCookie("tok123")
  assert.ok(c.startsWith(`${COOKIE}=tok123`))
  assert.match(c, /HttpOnly/)
  // Lax, not Strict: the passkey ceremony returns via a top-level navigation and Strict drops it.
  assert.match(c, /SameSite=Lax/)
  assert.match(c, /Path=\//)
  assert.match(c, /Max-Age=\d+/)
})

test("clearing the cookie expires it immediately", () => {
  assert.match(clearCookie(), /Max-Age=0/)
  assert.match(clearCookie(), /HttpOnly/)
})

test("readCookie picks the right value out of a crowded header", () => {
  const header = `other=1; ${COOKIE}=abc123; trailing=2`
  assert.equal(readCookie(header, COOKIE), "abc123")
  assert.equal(readCookie(header, "other"), "1")
  assert.equal(readCookie(header, "missing"), undefined)
  assert.equal(readCookie(undefined, COOKIE), undefined)
})

test("readCookie is not fooled by a name that is a suffix of another cookie", () => {
  // `evil_intelligence_session` must not satisfy a lookup for `intelligence_session`.
  const header = `evil_${COOKIE}=attacker; ${COOKIE}=real`
  assert.equal(readCookie(header, COOKIE), "real")
})

test("readCookie tolerates whitespace and values containing '='", () => {
  assert.equal(readCookie(`  ${COOKIE}=a=b=c  `, COOKIE), "a=b=c")
})
