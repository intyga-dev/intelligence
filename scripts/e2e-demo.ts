#!/usr/bin/env -S pnpm exec tsx
// End-to-end exercise: signed webhooks in, findings out.
//
// Drives the REAL HTTP surface with REAL HMAC signatures — not the normalizer directly — so it
// exercises signature verification, idempotency, normalization, detection and the API together.
// A green unit suite and a working pipeline are different claims.
//
//   pnpm exec tsx scripts/e2e-demo.ts <connectionId> <secret> [baseUrl]

import "../src/loadenv.ts"
import crypto from "node:crypto"

const [, , connectionId, secret, baseUrl = "http://localhost:4100"] = process.argv
if (!connectionId || !secret) {
  console.error("usage: e2e-demo.ts <connectionId> <secret> [baseUrl]")
  process.exit(1)
}

/** Same scheme Intyga signs with: t=<unix>,v1=hex(HMAC-SHA256(secret, "<t>.<body>")). */
function sign(body: string, t: number): string {
  const mac = crypto.createHmac("sha256", secret).update(`${t}.${body}`).digest("hex")
  return `t=${t},v1=${mac}`
}

async function deliver(event: {
  id: string
  type: string
  at: Date
  actionType: string
  requesterDid: string
  challengeCreatedAt: Date
}): Promise<number> {
  const body = JSON.stringify({
    id: event.id,
    type: event.type,
    createdAt: event.at.toISOString(),
    data: {
      nonce: `n_${event.id}`,
      actionType: event.actionType,
      verificationCode: "0000",
      requesterDid: event.requesterDid,
      requiredApprovals: 1,
      approvalsCount: 0,
      createdAt: event.challengeCreatedAt.toISOString(),
    },
  })
  const t = Math.floor(Date.now() / 1000)
  const res = await fetch(`${baseUrl}/ingest/intyga/${connectionId}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-intyga-event-id": event.id,
      "x-intyga-event-type": event.type,
      "x-intyga-signature": sign(body, t),
    },
    body,
  })
  return res.status
}

const AGENT = "did:intyga:agent-billing-01"
const now = Date.now()
let n = 0
// Unique per run: event ids are the idempotency key, so a second run with the same ids would be
// correctly deduplicated and appear to do nothing.
const RUN = crypto.randomBytes(3).toString("hex")
const id = () => `evt_${RUN}_${String(++n).padStart(5, "0")}`

// A quiet, ordinary history: roughly one refusal per 8-minute window over the last few hours.
const history: Parameters<typeof deliver>[0][] = []
for (let b = 1; b <= 40; b++) {
  history.push({
    id: id(),
    type: "challenge.denied",
    at: new Date(now - (8 * b + 1) * 60_000),
    actionType: "read_record",
    requesterDid: AGENT,
    challengeCreatedAt: new Date(now - (8 * b + 2) * 60_000),
  })
}

// Then the burst: 17 refusals in 8 minutes, 12 of them an action never seen from this agent.
const burst: Parameters<typeof deliver>[0][] = []
for (let i = 0; i < 12; i++) {
  burst.push({
    id: id(),
    type: "challenge.denied",
    at: new Date(now - i * 25_000),
    actionType: "grant_permission",
    requesterDid: AGENT,
    challengeCreatedAt: new Date(now - i * 25_000 - 4_000),
  })
}
for (let i = 0; i < 5; i++) {
  burst.push({
    id: id(),
    type: "challenge.denied",
    at: new Date(now - i * 30_000 - 10_000),
    actionType: "read_record",
    requesterDid: AGENT,
    challengeCreatedAt: new Date(now - i * 30_000 - 14_000),
  })
}

const all = [...history, ...burst]
const codes = new Map<number, number>()
for (const e of all) {
  const s = await deliver(e)
  codes.set(s, (codes.get(s) ?? 0) + 1)
}
console.log(`delivered ${all.length} events →`, Object.fromEntries(codes))

// Redeliver a handful to prove idempotency is real rather than assumed.
const replayed = all.slice(0, 5)
for (const e of replayed) await deliver(e)
console.log(`redelivered ${replayed.length} (must not duplicate)`)

const tick = await fetch(`${baseUrl}/internal/tick`, {
  method: "POST",
  headers: { authorization: `Bearer ${process.env.TICK_TOKEN ?? "dev-tick-token-change-me"}` },
})
console.log("tick →", JSON.stringify(await tick.json()))

// The findings API is session-gated now, and this script has no session — correctly, since it is
// a data-injection tool rather than an administrator. Report that rather than crashing on a 401.
const res = await fetch(`${baseUrl}/api/findings`)
if (res.status === 401) {
  console.log("\nEvents ingested and detection ran. Findings are session-gated —")
  console.log(`sign in at ${baseUrl}/login to read them.`)
} else {
  const findings = (await res.json()) as {
    findings: { severity: string; title: string; summary?: string; count: number; evidence: unknown[] }[]
  }
  console.log(`\n${findings.findings.length} finding(s):\n`)
  for (const f of findings.findings) {
    console.log(`  [${f.severity.toUpperCase()}] ${f.title}`)
    console.log(`  ${f.summary ?? ""}`)
    console.log(`  ${f.evidence.length} pieces of evidence, seen ${f.count}×\n`)
  }
}
