# Writing a detector

A detector is the rule that turns stored events into a finding. This guide walks through writing
one, from the events it reads to the tests that pin it, using a complete example you can copy.

Read it together with [CONNECTORS.md](CONNECTORS.md), which covers getting events in. A connector
only stores events; a detector decides what they mean.

## Do you need one?

Often you do not. Check these first:

| You want to                                             | Use                                                                                                                     |
| :------------------------------------------------------ | :---------------------------------------------------------------------------------------------------------------------- |
| Monitor CI, a scheduled job or a service objective      | The operational detectors, configured on **Detectors → Configure operational detectors**. No code.                      |
| Report deploys, errors or crashes from your own systems | The custom webhook kinds `deployment`, `error`, `crash`, `ci_run`, `job.completed` and `slo.sample`. No code.           |
| Bring in alerts a provider already raises               | A native provider connector feeding `provider-alerts`. See [CONNECTORS.md](CONNECTORS.md#native-provider-integrations). |
| Change thresholds of a built-in detector                | Its defaults, in its own file under `src/domain/detectors/`. A code change, but not a new detector.                     |
| Flag a condition no built-in detector understands       | A new detector: this guide.                                                                                             |

## What a detector is

A detector is a **pure function**: events in, findings out. No database, no network, no clock of
its own. Everything it needs is passed in, so every rule can be unit-tested without a database and
cannot quietly start depending on a live system. The tick (`src/jobs/tick.ts`) loads the events,
calls the detector and stores what it returns.

Each finding it returns is built with `createFinding` from `src/domain/finding.ts`. The fields that
need a decision:

| Field              | What to decide                                                                                                                                                                                                                                                   |
| :----------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `evidence`         | A non-empty list whose **first item is something measured or observed**: a `metric`, `eventRef`, `deployment`, `codeChange` or `correlation`. The type `EvidenceList` makes anything else a compile error. Model output is never evidence a finding can rest on. |
| `dedupeKey`        | The identity of the **condition**, not of one occurrence. Two runs over the same ongoing condition must produce the same key, or the list grows by one finding per tick.                                                                                         |
| `severity`         | `info`, `low`, `medium`, `high` or `critical`, computed from what you measured. Once stored, severity only ratchets up, never down.                                                                                                                              |
| `category`         | `security`, `engineering`, `product`, `customer` or `business`. Alert rules can filter on it.                                                                                                                                                                    |
| `detectedAt`       | When the evidence happened, not when the tick ran.                                                                                                                                                                                                               |
| `title`, `summary` | What was measured, and what it does **not** establish. A reader should not have to guess the limits of the claim.                                                                                                                                                |
| `serviceId`        | Copy it from the events (`event.serviceId`), so the finding appears under the right Service.                                                                                                                                                                     |

Two behaviours of the store shape every design:

- **A finding that is reported again reopens** if someone had resolved or dismissed it. That is
  deliberate when the condition genuinely recurs. It is noise when your detector simply re-reports
  an unchanged condition every tick, so design for that (the example below shows how).
- **The prefix `sensitive:` is reserved.** A `dedupeKey` starting with it marks an informational
  observation, which never alerts and is never sent for AI review. Do not use it for findings.

## Worked example: certificate expiry

The example flags a TLS certificate that is close to expiry, as reported by a checker you already
run. It is small, but it makes every decision a real detector has to make: which events, what
counts as the same condition, when to report, and what the finding does not prove.

### 1. The events

The checker posts one event per certificate check to the custom webhook, signed as described in
[CONNECTORS.md](CONNECTORS.md#signing). The kind is stored as `custom.cert.checked`:

```json
{
  "id": "cert-check-api-2026-11-20",
  "kind": "cert.checked",
  "at": "2026-11-20T06:00:00Z",
  "subject": "api.example.com",
  "attrs": { "host": "api.example.com", "notAfter": "2026-12-01T00:00:00Z" }
}
```

The detector computes the days remaining itself from `notAfter` and the check time, rather than
trusting a number the sender worked out.

### 2. The detector

`src/domain/detectors/certificateExpiry.ts`:

```ts
import type { NormalizedEvent } from "../../connectors/types.ts"
import { createFinding, type Finding } from "../finding.ts"

// Example detector: a TLS certificate close to expiry, as reported by your own checker.
//
// It reads `custom.cert.checked` events from the custom webhook. It fires when a certificate
// moves into a worse band than its previous check, not on every check: re-reporting an unchanged
// condition would reopen a finding someone has already dismissed, once per tick.

export const CERT_KINDS = ["custom.cert.checked"]

const DAY_MS = 86_400_000

type Band = "ok" | "medium" | "high" | "critical"
const RANK: Record<Band, number> = { ok: 0, medium: 1, high: 2, critical: 3 }

export function bandFor(daysLeft: number): Band {
  if (daysLeft <= 3) return "critical"
  if (daysLeft <= 7) return "high"
  if (daysLeft <= 14) return "medium"
  return "ok"
}

interface Check {
  event: NormalizedEvent
  host: string
  notAfter: Date
  daysLeft: number
}

/** Malformed events are skipped, not guessed at: a finding needs facts it can show. */
function asCheck(e: NormalizedEvent): Check | null {
  const host = e.attrs.host
  const notAfter = typeof e.attrs.notAfter === "string" ? new Date(e.attrs.notAfter) : null
  if (typeof host !== "string" || host === "" || !notAfter || Number.isNaN(notAfter.getTime())) return null
  const daysLeft = Math.floor((notAfter.getTime() - e.at.getTime()) / DAY_MS)
  return { event: e, host, notAfter, daysLeft }
}

export interface CertificateExpiryInput {
  tenantId: string
  /** Checks ingested since this detector last ran. Each one is evaluated exactly once. */
  events: readonly NormalizedEvent[]
  /** Earlier checks, so each new check can be compared with the one before it. */
  history: readonly NormalizedEvent[]
}

export function detectCertificateExpiry(input: CertificateExpiryInput): Finding[] {
  // One certificate is one connection, host and expiry. A renewed certificate is a new condition.
  const certKey = (c: Check) => `${c.event.connectionId}\u0000${c.host}\u0000${c.notAfter.toISOString()}`
  const checksByCert = new Map<string, Check[]>()
  for (const c of [...input.history, ...input.events].map(asCheck)) {
    if (!c) continue
    checksByCert.set(certKey(c), [...(checksByCert.get(certKey(c)) ?? []), c])
  }

  const findings: Finding[] = []
  for (const e of input.events) {
    const check = asCheck(e)
    if (!check) continue
    const band = bandFor(check.daysLeft)
    if (band === "ok") continue

    const previous = (checksByCert.get(certKey(check)) ?? [])
      .filter((c) => c.event.at < e.at)
      .sort((a, b) => b.event.at.getTime() - a.event.at.getTime())[0]
    if (previous && RANK[bandFor(previous.daysLeft)] >= RANK[band]) continue

    const dedupeKey = `cert-expiry:${e.connectionId}:${check.host}:${check.notAfter.toISOString()}`
    findings.push(
      createFinding({
        id: dedupeKey,
        tenantId: input.tenantId,
        serviceId: e.serviceId ?? null,
        category: "engineering",
        severity: band,
        title:
          check.daysLeft < 0
            ? `Certificate for ${check.host} has expired`
            : `Certificate for ${check.host} expires in ${check.daysLeft} days`,
        summary:
          `Your checker reported a certificate for ${check.host} valid until ` +
          `${check.notAfter.toISOString()}. Intelligence did not connect to the host itself, and a ` +
          "renewal your checker has not reported yet is not visible here.",
        evidence: [
          {
            kind: "metric",
            label: "days until certificate expiry",
            value: check.daysLeft,
            window: { from: e.at, to: check.notAfter },
          },
          {
            kind: "eventRef",
            connectionId: e.connectionId,
            sourceId: e.sourceId,
            at: e.at,
            eventKind: e.kind,
          },
        ],
        detectedAt: e.at,
        dedupeKey,
      }),
    )
  }
  return findings
}
```

The decisions worth noticing:

- **One condition per certificate.** The `dedupeKey` is the connection, host and expiry. A renewed
  certificate has a new expiry, so it is a new condition rather than a continuation of the old one.
- **Report on a transition, not on every check.** It fires when a check moves into a worse band
  than the previous check of the same certificate. A daily check that still says ten days does not
  reopen a finding someone dismissed yesterday. A move from 14 days to 7 does, at higher severity,
  which is new information.
- **Skip what cannot be read.** A missing host or an unparseable date produces nothing. A finding
  has to show facts it can back.
- **Say what it does not prove.** The summary states that Intelligence never connected to the host,
  and that a renewal the checker has not reported is invisible.

### 3. The tests

`src/domain/detectors/certificateExpiry.test.ts`, next to the detector:

```ts
import assert from "node:assert/strict"
import test from "node:test"
import type { NormalizedEvent } from "../../connectors/types.ts"
import { isDeterministic } from "../finding.ts"
import { bandFor, detectCertificateExpiry } from "./certificateExpiry.ts"

const EXPIRY = "2026-12-01T00:00:00.000Z"
let seq = 0

/** One check, `daysBefore` days before the certificate expires. */
function check(daysBefore: number, attrs: NormalizedEvent["attrs"] = {}): NormalizedEvent {
  seq += 1
  return {
    connectionId: "conn-1",
    source: "webhook",
    sourceId: `check-${seq}`,
    kind: "custom.cert.checked",
    at: new Date(new Date(EXPIRY).getTime() - daysBefore * 86_400_000),
    subjectRef: "api.example.com",
    correlationRef: null,
    attrs: { host: "api.example.com", notAfter: EXPIRY, ...attrs },
  }
}

const run = (history: NormalizedEvent[], events: NormalizedEvent[]) =>
  detectCertificateExpiry({ tenantId: "t1", history, events })

test("bands have exact boundaries", () => {
  assert.equal(bandFor(15), "ok")
  assert.equal(bandFor(14), "medium")
  assert.equal(bandFor(7), "high")
  assert.equal(bandFor(3), "critical")
  assert.equal(bandFor(-1), "critical")
})

test("entering a band fires once, led by measured evidence", () => {
  const found = run([check(20)], [check(10)])
  assert.equal(found.length, 1)
  assert.equal(found[0]?.severity, "medium")
  assert.equal(found[0]?.title, "Certificate for api.example.com expires in 10 days")
  assert.ok(found[0] && isDeterministic(found[0].evidence[0]))
})

test("a later check in the same band does not fire again", () => {
  assert.equal(run([check(20), check(10)], [check(9)]).length, 0)
})

test("a worse band fires again under the same identity", () => {
  const medium = run([check(20)], [check(10)])
  const high = run([check(20), check(10)], [check(6)])
  assert.equal(high[0]?.severity, "high")
  assert.equal(high[0]?.dedupeKey, medium[0]?.dedupeKey)
})

test("a renewed certificate is a new condition", () => {
  const renewed = check(5, { notAfter: "2027-03-01T00:00:00.000Z" })
  assert.equal(run([check(10)], [renewed]).length, 0, "90 days left is ok")
  const old = run([], [check(10)])
  const next = run([], [check(10, { notAfter: "2026-12-02T00:00:00.000Z" })])
  assert.notEqual(old[0]?.dedupeKey, next[0]?.dedupeKey)
})

test("malformed checks are skipped, not guessed at", () => {
  assert.equal(run([], [check(2, { notAfter: "not a date" })]).length, 0)
  assert.equal(run([], [check(2, { host: null })]).length, 0)
})
```

These run without a database. Construct events directly, inject time through the events rather than
the clock, and test the boundaries and the cases that must **not** fire, not only the happy path.

### 4. Register it

A detector is wired in four places. The compiler catches a missing `DETECTOR_INFO` or
`DETECTOR_SETTINGS` entry. It cannot catch a detector that is registered but never called from the
tick, so check the tick report after your first run.

**`src/domain/detectors/index.ts`** — the one list of detectors that exist. Add the id to
`DETECTORS` and describe it in `DETECTOR_INFO`. This is also what makes it appear on the Detectors
page and lets an administrator switch it off with a signed approval.

```ts
export const DETECTORS = [
  // …the built-in detectors…
  "provider-alerts",
  "certificate-expiry",
] as const

export const DETECTOR_INFO: Readonly<Record<DetectorId, { description: string; needs: string }>> = {
  "certificate-expiry": {
    description:
      "A certificate your checker reports moves into a worse expiry band: 14, 7 or 3 days. Intelligence does not connect to the host.",
    needs: "custom webhook with cert.checked events",
  },
  // …
}
```

**`src/server/app.ts`** — the thresholds shown on the Detectors page, in `DETECTOR_SETTINGS`:

```ts
const DETECTOR_SETTINGS: Readonly<Record<DetectorId, string>> = {
  "certificate-expiry": "bands at 14, 7 and 3 days; fires when a check moves into a worse band",
  // …
}
```

**`src/jobs/tick.ts`** — load the events, run the detector, store the findings. Import
`CERT_KINDS` and `detectCertificateExpiry`, then add a block beside the other event-driven
detectors:

```ts
if (!off.has("certificate-expiry")) {
  await run("certificate-expiry", async () => {
    const after =
      (await getDetectorCursor(tenantId, "certificate-expiry")) ?? new Date(now.getTime() - LOOKBACK_MS)
    const [events, history] = await Promise.all([
      loadIngestedEvents(tenantId, { kinds: CERT_KINDS, after, until: now }),
      loadEvents(tenantId, {
        kinds: CERT_KINDS,
        since: new Date(now.getTime() - LOOKBACK_MS),
        until: now,
      }),
    ])
    const found = detectCertificateExpiry({ tenantId, events, history })
    const created = await persist(tenantId, found)
    // Moved only after the findings are stored, so a crash re-reads the batch instead of losing it.
    await setDetectorCursor(tenantId, "certificate-expiry", now)
    return { found: found.length, created }
  })
}
```

`loadIngestedEvents` returns events stored since the cursor, so each check is evaluated once.
`loadEvents` supplies the earlier checks the detector compares against. `run` isolates failures:
if this detector throws, the others still run and the tick reports it as an error.

**The cursor list in the same file.** A switched-off detector stops watching rather than deferring.
Add the id to the list whose cursors keep moving while a detector is off, so switching it back on
does not replay everything that happened meanwhile:

```ts
for (const id of [
  "sensitive-code-change",
  "deploy-regression",
  "metrics-health",
  "certificate-expiry",
] as const) {
  if (off.has(id)) await setDetectorCursor(tenantId, id, now)
}
```

### 5. Try it

Run `pnpm verify` (typecheck, lint, boundary check and tests). Then, against a local instance with
an active custom webhook connector, post a signed check using the signing examples in
[CONNECTORS.md](CONNECTORS.md#signing), and trigger a tick:

```bash
curl -X POST http://localhost:4100/internal/tick -H "Authorization: Bearer $TICK_TOKEN"
```

The tick report lists `certificate-expiry` under `detectors` with how many findings it found and
created. The event appears under **Activity** and the finding under **Findings**.

## What happens to its findings

Nothing else needs wiring. Once a detector returns findings:

- **It runs by default.** A new detector is switched on from the first tick after deployment. It
  stops only when an administrator switches it off on the Detectors page, which takes a signed
  approval.
- **Alert rules apply.** Active rules deliver findings at or above their minimum severity, in their
  selected categories, to Slack or a signed webhook.
- **AI review may apply.** Findings stored through the tick's `persist` are eligible for automatic
  review when an administrator has turned reviews on. The provider receives only the restricted
  projection in `src/redaction/project.ts`: your metric label is sent as the generic "detector
  measurement" and your event kind as "other". A review never changes the finding.

If your detector already states a concrete failure, like the operational detectors, and should not
be sent for review or reopened by an identical re-run, follow `persistFresh` in
`src/jobs/operational.ts` instead of `persist`.

## Sensitive code paths

The paths that make a pull request a review observation are code, not configuration. Every GitHub
and GitLab connector uses the built-in `generic` map in `src/domain/sensitivity.ts`.

To add your own paths, add a component to `GENERIC_COMPONENTS` there: an id, a one-line rationale
shown in the observation, a severity floor and glob patterns. It applies to every repository. A
different map per repository or connector is not supported today; it needs changes to
`pathMapFor`, the GitHub configuration action in `src/actions/registry.ts` and the path-map lookup
in `src/jobs/tick.ts`.

## Keeping a fork mergeable

There is no plugin interface yet, so a detector of your own means touching `index.ts`, `app.ts`
and `tick.ts`. To keep merges from upstream cheap:

- Put the detector and its tests in their own files. Keep each edit to a shared file to one entry or
  one block.
- Prefer new event kinds through the custom webhook over changes to an existing connector.
- Give your detector ids and `dedupeKey` prefixes a name that upstream is unlikely to use.

A detector that is useful beyond your own systems is welcome upstream. Open an issue first, as
[CONTRIBUTING.md](../CONTRIBUTING.md) asks.

## Checklist

- [ ] The first evidence item is measured or observed, and the summary says what it does not prove.
- [ ] `dedupeKey` identifies the condition, and an unchanged condition does not reopen every tick.
- [ ] `detectedAt` is the time of the evidence, and `serviceId` comes from the events.
- [ ] Tests cover boundaries and the cases that must not fire.
- [ ] Registered in `DETECTORS`, `DETECTOR_INFO`, `DETECTOR_SETTINGS`, the tick and the cursor list.
- [ ] `pnpm verify` passes.
- [ ] You know it runs by default after deployment, and which alert rules will pick it up.
