import assert from "node:assert/strict"
import { createPrivateKey, createPublicKey } from "node:crypto"
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs"
import { tmpdir } from "node:os"
import path from "node:path"
import test from "node:test"
import { initialiseSelfHost, publicOrigin } from "./setup.ts"

test("installer creates matching keys and private secrets without overwriting a prior install", (t) => {
  const dir = mkdtempSync(path.join(tmpdir(), "intelligence-setup-"))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  initialiseSelfHost(dir, "https://intelligence.example.com/", 4200)
  const env = readFileSync(path.join(dir, ".env.selfhost"), "utf8")
  assert.match(env, /PUBLIC_URL=https:\/\/intelligence.example.com\n/)
  assert.match(env, /POSTGRES_PASSWORD=[a-f0-9]{64}\n/)
  assert.match(env, /SELFHOST_HTTP_PORT=4200\n/)
  const privateKey = createPrivateKey(readFileSync(path.join(dir, ".selfhost/rp.pk8")))
  assert.equal(
    createPublicKey(privateKey).export({ type: "spki", format: "der" }).toString("base64"),
    readFileSync(path.join(dir, ".selfhost/rp-public.txt"), "utf8").trim(),
  )
  for (const f of [".env.selfhost", ".selfhost/rp.pk8"])
    assert.equal(statSync(path.join(dir, f)).mode & 0o777, 0o600)
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
