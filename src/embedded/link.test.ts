import assert from "node:assert/strict"
import { test } from "node:test"
import { createHash } from "node:crypto"
import { testDeployment } from "../test/deployment.ts"
import { resolveGateConfig } from "../gate/deployment.ts"
import { decryptSecret, encryptSecret } from "../store/crypto.ts"
import { beginEmbeddedLink, readEmbeddedLink } from "./link.ts"

test("linking fixes the application and callback, and binds PKCE to the initiating browser", () => {
  const deployment = testDeployment()
  try {
    const cfg = { ...resolveGateConfig(), embeddedApplicationId: "123e4567-e89b-42d3-a456-426614174000" }
    const started = beginEmbeddedLink(cfg)
    const url = new URL(started.url)
    assert.equal(url.origin, cfg.consoleUrl)
    assert.equal(url.pathname, "/embedded/link")
    assert.equal(url.searchParams.get("applicationId"), cfg.embeddedApplicationId)
    const state = url.searchParams.get("state") ?? ""
    const data = readEmbeddedLink(cfg, started.cookie, state)
    assert.equal(
      url.searchParams.get("pkceChallenge"),
      createHash("sha256").update(data.verifier).digest("base64url"),
    )
    assert.equal(url.searchParams.has("verifier"), false)
    for (const cookie of [
      undefined,
      "garbled",
      encryptSecret("null"),
      encryptSecret(JSON.stringify({ ...data, expiresAt: Date.now() - 1 })),
    ])
      assert.throws(() => readEmbeddedLink(cfg, cookie, state), /expired|another browser/)
    assert.throws(() => readEmbeddedLink(cfg, started.cookie, "x".repeat(43)), /another browser/)
    assert.throws(
      () => readEmbeddedLink({ ...cfg, bindingId: "another" }, started.cookie, state),
      /another browser/,
    )
    assert.ok(decryptSecret(started.cookie))
  } finally {
    deployment.dispose()
  }
})
