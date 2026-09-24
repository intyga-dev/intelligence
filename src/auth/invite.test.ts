import assert from "node:assert/strict"
import test from "node:test"
import { enrolLink, hashInvite, isInviteShaped, newInviteToken } from "./invite.ts"

test("invite tokens carry 256 bits and are never repeated", () => {
  const seen = new Set<string>()
  for (let i = 0; i < 200; i++) {
    const t = newInviteToken()
    assert.ok(isInviteShaped(t), t)
    assert.ok(!seen.has(t))
    seen.add(t)
  }
})

test("only the digest is stored, and it is not the token", () => {
  const t = newInviteToken()
  assert.match(hashInvite(t), /^[0-9a-f]{64}$/)
  assert.notEqual(hashInvite(t), t)
  assert.equal(hashInvite(t), hashInvite(t))
})

test("a subject id is not an invite", () => {
  // The bug this module exists to close: enrolment used to accept a member's externalId.
  for (const v of ["admin", "ada", "", "inv_", `inv_${"a".repeat(42)}`, `inv_${"a".repeat(44)}`, 42, null]) {
    assert.equal(isInviteShaped(v), false, String(v))
  }
  assert.equal(isInviteShaped(`inv_${"a".repeat(43)}`), true)
})

test("the enrolment link carries the token in the fragment, which browsers never send", () => {
  const t = newInviteToken()
  const link = new URL(enrolLink("https://intel.example.com/", t))
  assert.equal(link.pathname, "/members/enrol")
  assert.equal(link.search, "", "a query string would put the token in every request log")
  assert.equal(link.hash, `#invite=${t}`)
})
