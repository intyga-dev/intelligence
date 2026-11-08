import assert from "node:assert/strict"
import { test } from "node:test"
import { allConnectors } from "../connectors/index.ts"
import { CONFIGURE_CONNECTOR } from "./connectorSettings.ts"

const base = { connectionId: "00000000-0000-4000-8000-000000000001", label: "Updated source" }

test("connector configuration accepts only declared non-secret settings for every registered kind", () => {
  for (const def of allConnectors()) {
    const config = Object.fromEntries(
      def.fields
        .filter((f) => !f.secret)
        .map((f) => [
          f.name,
          f.name === "repos" ? "acme/core" : f.name === "pathMap" ? "generic" : "test-value",
        ]),
    )
    const params = { ...base, kind: def.kind, config }
    assert.equal(CONFIGURE_CONNECTOR.safeParse(params).success, true, def.kind)
    for (const key of [
      "serviceSecret",
      "trustAnchor",
      "secretCiphertext",
      ...def.fields.filter((f) => f.secret).map((f) => f.name),
    ]) {
      assert.equal(
        CONFIGURE_CONNECTOR.safeParse({ ...params, config: { ...config, [key]: "secret" } }).success,
        false,
        `${def.kind}: ${key}`,
      )
    }
    for (const field of def.fields.filter((f) => !f.secret && f.required))
      assert.equal(
        CONFIGURE_CONNECTOR.safeParse({ ...params, config: { ...config, [field.name]: " " } }).success,
        false,
      )
  }
  assert.equal(CONFIGURE_CONNECTOR.safeParse({ ...base, kind: "unknown", config: {} }).success, false)
  assert.equal(
    CONFIGURE_CONNECTOR.safeParse({ ...base, kind: "github", config: { repos: "../.." } }).success,
    false,
  )
  assert.equal(
    CONFIGURE_CONNECTOR.safeParse({
      ...base,
      kind: "gitlab",
      config: { projects: "acme/core", pathMap: "unknown" },
    }).success,
    false,
  )
})
