import { mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { anchor, CLIENT_ID, ORIGIN, WORKSPACE } from "./intyga.ts"

/** Each test process gets a deployment file; no live environment or credentials are used. */
export function testDeployment(
  baseUrl = "http://127.0.0.1:9",
  serviceClientId = "test-service",
  serviceSecret = "test-service-secret",
) {
  const directory = mkdtempSync(join(tmpdir(), "intelligence-deployment-"))
  const anchorPath = join(directory, "anchor.json")
  const env = {
    INTYGA_URL: baseUrl,
    INTYGA_EMBEDDED_APPLICATION_ID: "",
    INTYGA_INTERNAL_URL: "",
    INTYGA_CONSOLE_URL: "https://console.example.test",
    INTYGA_WORKSPACE_ID: WORKSPACE,
    INTYGA_OIDC_CLIENT_ID: CLIENT_ID,
    INTYGA_SERVICE_CLIENT_ID: serviceClientId,
    INTYGA_SERVICE_CLIENT_SECRET: serviceSecret,
    INTYGA_TRUST_ANCHOR_FILE: anchorPath,
    PUBLIC_URL: ORIGIN,
  }
  const previous = Object.fromEntries(Object.keys(env).map((key) => [key, process.env[key]]))
  function apply() {
    Object.assign(process.env, env)
    writeFileSync(anchorPath, JSON.stringify(anchor))
  }
  apply()
  return {
    env,
    anchorPath,
    apply,
    dispose() {
      for (const [key, value] of Object.entries(previous)) {
        if (value === undefined) delete process.env[key]
        else process.env[key] = value
      }
      rmSync(directory, { recursive: true, force: true })
    },
  }
}
