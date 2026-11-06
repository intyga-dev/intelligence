import assert from "node:assert/strict"
import test from "node:test"
import { scheduledTick } from "./scheduler.ts"

test("scheduler authenticates, refuses redirects and checks application success", async () => {
  const fetcher = (async (url, init) => {
    assert.equal(url, "http://app:4100/internal/tick")
    assert.equal(init?.method, "POST")
    assert.equal(new Headers(init?.headers).get("authorization"), "Bearer local-tick-secret")
    assert.equal(init?.redirect, "error", "never forward the bearer credential through a redirect")
    assert.ok(init?.signal)
    return Response.json({ ok: true })
  }) as typeof fetch
  assert.equal(await scheduledTick("http://app:4100/internal/tick", "local-tick-secret", fetcher), true)
  for (const response of [Response.json({ ok: false }), Response.json({ ok: true }, { status: 503 })]) {
    assert.equal(await scheduledTick("http://app", "token", (async () => response) as typeof fetch), false)
  }
})
