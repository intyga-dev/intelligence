import assert from "node:assert/strict"
import { mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { test } from "node:test"
import { intelligenceMarker, registrationProof } from "./registration.ts"

test("only an unexpired deployment-installed proof for this origin and workspace is served", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "intelligence-registration-"))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const file = join(dir, "registration.json")
  const now = new Date("2026-11-07T12:00:00.000Z")
  const proof = {
    type: "intyga-embedded-origin-proof",
    v: 1,
    applicationId: "0cb94fd1-5ccc-4352-9b01-769c5748bf52",
    tenantId: "2db9d61c-ecdd-4b13-9be3-144b2117b4da",
    origin: "https://intelligence.example",
    challenge: "a".repeat(43),
    expiresAt: "2026-11-07T12:15:00.000Z",
  }
  const env = {
    INTYGA_EMBEDDED_REGISTRATION_FILE: file,
    PUBLIC_URL: proof.origin,
    INTYGA_WORKSPACE_ID: proof.tenantId,
  }
  assert.equal(registrationProof(env, now), null)
  writeFileSync(file, JSON.stringify(proof))
  assert.deepEqual(registrationProof(env, now), proof)
  assert.equal(registrationProof({ ...env, PUBLIC_URL: "https://other.example" }, now), null)
  assert.equal(registrationProof({ ...env, INTYGA_WORKSPACE_ID: "another-workspace" }, now), null)
  assert.equal(registrationProof(env, new Date(proof.expiresAt)), null)
  for (const raw of [
    "garbled",
    "x".repeat(8193),
    JSON.stringify({ ...proof, secret: "do-not-serve" }),
    JSON.stringify({ ...proof, expiresAt: "2027-01-01T00:00:00.000Z" }),
  ]) {
    writeFileSync(file, raw)
    assert.equal(registrationProof(env, now), null)
  }
  writeFileSync(file, JSON.stringify(intelligenceMarker))
  assert.equal(registrationProof(env, now), null, "copying the advisory marker cannot prove origin control")
})
