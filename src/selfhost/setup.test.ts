import assert from "node:assert/strict"
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs"
import { tmpdir } from "node:os"
import path from "node:path"
import test from "node:test"
import { initialiseSelfHost, publicOrigin } from "./setup.ts"

test("installer writes private secrets once and never overwrites a prior install", (t) => {
  const dir = mkdtempSync(path.join(tmpdir(), "intelligence-setup-"))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  initialiseSelfHost(dir, "https://intelligence.example.com/", 4200)
  const env = readFileSync(path.join(dir, ".env.selfhost"), "utf8")
  assert.match(env, /PUBLIC_URL=https:\/\/intelligence.example.com\n/)
  assert.match(env, /POSTGRES_PASSWORD=[a-f0-9]{64}\n/)
  assert.match(env, /SELFHOST_HTTP_PORT=4200\n/)
  assert.match(env, /SECRETS_ENC_KEY=[A-Za-z0-9+/]{43}=\n/)
  assert.match(env, /SETUP_TOKEN=[a-f0-9]{64}\n/)
  assert.doesNotMatch(
    env,
    /INTYGA_(URL|SERVICE|OIDC|TRUST)/,
    "the INTYGA binding is entered in the setup form, never generated",
  )
  assert.equal(statSync(path.join(dir, ".env.selfhost")).mode & 0o777, 0o600)
  assert.throws(() => initialiseSelfHost(dir, "https://other.example.com"), /Refusing to rotate/)
  assert.equal(readFileSync(path.join(dir, ".env.selfhost"), "utf8"), env)
})

test("public origin requires HTTPS or loopback and refuses embedded credentials or paths", () => {
  for (const origin of [
    "http://public.example.com",
    "https://example.com/path",
    "https://user:pass@example.com",
    "https://example.com?q=x",
    "https://example.com/#frag",
    "file:///tmp/a",
  ]) {
    assert.throws(() => publicOrigin(origin))
  }
  assert.equal(publicOrigin("http://localhost:4100/"), "http://localhost:4100")
  assert.equal(publicOrigin("http://[::1]:4100"), "http://[::1]:4100")
})
