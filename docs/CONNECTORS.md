# Connecting your own sources

There are two ways to get events from a system Intelligence does not ship a connector for:

1. **Send them to the custom webhook.** No code in this repository. Anything that can make a
   signed HTTP POST (a CI job, a deploy script, an in-house service) can do it. Start here.
2. **Write a connector.** One TypeScript file plus one registration line. Do this when you want to
   poll an API, or verify a vendor's own webhook signature without a relay in between.

Either way, everything becomes the same `NormalizedEvent`, and detectors never learn which source
an event came from.

---

## 1. The custom webhook

On **Connectors → Add a connector**, choose **Custom webhook**. You get an endpoint and a signing
secret, and the secret is shown once. Turn the connector on when the sender is ready: deliveries to
a connector that is off are verified and then ignored.

### The request

```http
POST /ingest/webhook/<connection id>
Content-Type: application/json
x-intelligence-signature: t=1790000000,v1=5f2c…(64 hex characters)

{
  "id": "deploy-981",
  "kind": "deployment",
  "at": "2026-09-23T12:00:00Z",
  "subject": "billing-api",
  "correlation": "abc1234",
  "attrs": { "production": true, "succeeded": true, "sha": "abc1234", "name": "billing-api" }
}
```

| Field | Required | Meaning |
| :--- | :--- | :--- |
| `id` | yes | Your id for this event. **Resending the same id is a no-op**, so retries are safe. |
| `kind` | yes | Lowercase `a-z 0-9 . _ -`. Stored as `custom.<kind>`. |
| `at` | no | ISO 8601 with an offset. Defaults to when the request arrived. |
| `subject` | no | Who or what the event is about: a service, a user, a job. |
| `correlation` | no | Ties related events together, such as a commit SHA or a trace id. |
| `attrs` | no | A **flat** object of strings, numbers, booleans or null. Nested objects are refused. |

The endpoint answers `200` for a verified delivery, even when the body is not a valid event. That
way your queue does not retry a malformed event forever. Such an event is stored raw and not used.
A bad signature gets `401`.

### Kinds the detectors read today

| `kind` | Read by | `attrs` that matter |
| :--- | :--- | :--- |
| `deployment` | `deploy-regression`, as the anchor | `production: true` (**required**, since absence does not mean production), `succeeded` (default true), `sha`, `name` |
| `error` | `deploy-regression`, as an error signal | none |
| `crash` | `deploy-regression`, as a crash signal | none |

Any other kind is stored, and waits for a detector that reads it. If a deployment's `sha` matches a
pull or merge request the GitHub or GitLab connector has seen (head or merge commit), the finding names
that PR and says whether it touched sensitive code.

Why the `custom.` prefix is forced: without it, anyone holding this connector's secret could send
`challenge.denied` and make up an authorization-refusal finding against any subject. A custom event
can only ever be a custom event.

### Signing

`v1` is the lowercase hex HMAC-SHA256 of `"<t>.<raw body>"`, keyed with the connector's secret,
where `t` is the current Unix time in seconds. Deliveries more than **five minutes** away from the
server's clock are refused, which bounds replay. This is the same scheme Intelligence uses to sign
its outbound alerts.

```bash
# bash + openssl
body='{"id":"deploy-981","kind":"deployment","attrs":{"production":true,"sha":"abc1234"}}'
t=$(date +%s)
sig=$(printf '%s' "$t.$body" | openssl dgst -sha256 -hmac "$SECRET" -hex | sed 's/^.* //')
curl -sS -X POST "$URL" -H 'content-type: application/json' \
  -H "x-intelligence-signature: t=$t,v1=$sig" --data "$body"
```

```ts
// Node
import { createHmac } from "node:crypto"
const body = JSON.stringify(event)
const t = Math.floor(Date.now() / 1000)
const v1 = createHmac("sha256", secret).update(`${t}.${body}`).digest("hex")
await fetch(url, {
  method: "POST",
  headers: { "content-type": "application/json", "x-intelligence-signature": `t=${t},v1=${v1}` },
  body, // exactly the bytes that were signed
})
```

```python
# Python
import hmac, hashlib, json, time, urllib.request
body = json.dumps(event, separators=(",", ":")).encode()
t = str(int(time.time()))
v1 = hmac.new(secret.encode(), f"{t}.".encode() + body, hashlib.sha256).hexdigest()
req = urllib.request.Request(url, data=body, method="POST", headers={
    "content-type": "application/json", "x-intelligence-signature": f"t={t},v1={v1}"})
urllib.request.urlopen(req)
```

Sign the exact bytes you send. Re-serialising the JSON after signing it is the usual reason a
correct secret still gets `401`.

### Example: report deploys from GitHub Actions

```yaml
- name: Tell Intelligence about this deploy
  if: success()
  env:
    URL: ${{ secrets.INTELLIGENCE_WEBHOOK_URL }}
    SECRET: ${{ secrets.INTELLIGENCE_WEBHOOK_SECRET }}
  run: |
    body=$(printf '{"id":"deploy-%s-%s","kind":"deployment","subject":"%s","correlation":"%s","attrs":{"production":true,"succeeded":true,"sha":"%s","name":"%s"}}' \
      "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" "$GITHUB_REPOSITORY" "$GITHUB_SHA" "$GITHUB_SHA" "$GITHUB_WORKFLOW")
    t=$(date +%s)
    sig=$(printf '%s' "$t.$body" | openssl dgst -sha256 -hmac "$SECRET" -hex | sed 's/^.* //')
    curl -fsS -X POST "$URL" -H 'content-type: application/json' \
      -H "x-intelligence-signature: t=$t,v1=$sig" --data "$body"
```

(If you already connect GitHub, naming the workflow in its *Deploy workflow names* setting does
the same thing without this step.)

---

## 2. Writing a connector

A connector is one object implementing `PushConnector` or `PollConnector`
([`src/connectors/registry.ts`](../src/connectors/registry.ts)), registered with one line in
[`src/connectors/index.ts`](../src/connectors/index.ts). You don't need a migration, a schema
change, or edits to the ingest route, the tick or the UI. The **Add a connector** form is generated
from your `fields`, and the setup page from your `setup` steps.

The existing connectors are the best reference:

| Shape | Look at |
| :--- | :--- |
| Push, vendor-supplied secret, HMAC without timestamp | `src/connectors/sentry/` |
| Push, secret we mint, timestamped HMAC | `src/connectors/intyga/`, `src/connectors/webhook/` |
| Push, SHA-1 HMAC | `src/connectors/vercel/` |
| Push, HMAC with rotation (several signatures) | `src/connectors/pagerduty/` |
| Push, signed JWS (HS256) | `src/connectors/netlify/` |
| Push, vendor cannot sign, shared-secret header | `src/connectors/opsgenie/`, `src/connectors/datadog/` |
| Poll, paginated diffs + self-managed base URL | `src/connectors/gitlab/` |
| Poll, unordered list, own cursor | `src/connectors/cloudflare/` |
| Poll, paginated API with cursors | `src/connectors/github/` |
| Poll, query API | `src/connectors/metrics/`, `src/connectors/fly/` |

### The shape everything becomes

```ts
interface NormalizedEvent {
  connectionId: string   // passed to you
  source: string         // your connector's kind
  sourceId: string       // unique per connection: the idempotency key
  kind: string           // "<source>.<event>", e.g. "pagerduty.incident.triggered"
  at: Date               // when it happened at the source
  subjectRef: string | null      // who or what a finding would be about
  correlationRef: string | null  // what ties it to other events (a commit SHA, a trace id)
  attrs: Record<string, string | number | boolean | null>  // flat
}
```

Prefix `kind` with your source name. Detectors select on `kind`, and a bare `deployment` or
`challenge.denied` would feed detectors that were never meant to see your events.

### A push connector

```ts
import crypto from "node:crypto"
import type { PushConnector } from "../registry.ts"

export const exampleConnector: PushConnector = {
  kind: "example",
  mode: "push",
  label: "Example",
  blurb: "One line for the connector catalogue.",
  generatesSecret: false,   // true: we mint the secret and show it once; false: the user pastes theirs
  fields: [
    { name: "secret", label: "Signing secret", required: true, secret: true },
  ],
  setup: ["Where to find the secret.", "Where to paste the endpoint shown below."],

  verify: ({ headers, rawBody, secret }) => {
    // Over the RAW bytes, in constant time. Never over a re-serialised parse.
    const given = String(headers["x-example-signature"] ?? "")
    if (!/^[0-9a-f]{64}$/.test(given)) return { ok: false, reason: "malformed-header" }
    const want = crypto.createHmac("sha256", secret).update(rawBody, "utf8").digest()
    return crypto.timingSafeEqual(want, Buffer.from(given, "hex"))
      ? { ok: true }
      : { ok: false, reason: "mismatch" }
  },

  // The vendor's delivery id. Null means "cannot deduplicate", so prefer something stable.
  eventId: (headers, body) => String((body as { id?: string })?.id ?? "") || null,

  normalize: ({ connectionId, body, receivedAt }) => {
    const b = body as { id?: string; type?: string; service?: string; created_at?: string }
    if (!b?.id || !b.type) return null   // not something we model: stored raw, not used
    return {
      connectionId,
      source: "example",
      sourceId: b.id,
      kind: `example.${b.type}`,
      at: b.created_at ? new Date(b.created_at) : receivedAt,
      subjectRef: b.service ?? null,
      correlationRef: null,
      attrs: { type: b.type },
    }
  },
}
```

### A poll connector

```ts
export const examplePoller: PollConnector = {
  kind: "example-poll",
  mode: "poll",
  label: "Example (poll)",
  blurb: "…",
  fields: [{ name: "token", label: "Read-only token", required: true, secret: true }],
  setup: ["…"],

  async poll(ctx) {
    const since = (await ctx.getCursor("items")) ?? new Date(Date.now() - 86_400_000).toISOString()
    const res = await fetch(`https://api.example.com/items?since=${encodeURIComponent(since)}&limit=100`, {
      headers: { authorization: `Bearer ${ctx.secret}` },
      signal: AbortSignal.timeout(15_000),
    })
    if (!res.ok) { ctx.log("example poll failed", { status: res.status }); return [] }
    const items = (await res.json()) as { id: string; at: string }[]
    let newest = since
    const out = items.map((i) => {
      if (i.at > newest) newest = i.at
      return { connectionId: ctx.connectionId, source: "example-poll", sourceId: i.id,
               kind: "example-poll.item", at: new Date(i.at), subjectRef: null,
               correlationRef: null, attrs: {} }
    })
    await ctx.setCursor("items", newest)
    return out
  },
}
```

### Rules a connector must follow

These are the review criteria. Each one exists because breaking it caused a real problem.

* **Verify over the raw bytes, in constant time.** `verify` gets the exact request body. Use
  `timingSafeEqual`, and handle unequal lengths before calling it.
* **Say what the vendor's scheme cannot do.** If it has no timestamp (Sentry), a captured delivery
  replays forever and only `eventId` idempotency contains that. Write it in a comment.
* **`sourceId` must be stable per event.** It is the idempotency key, and a random one turns every
  retry into a duplicate.
* **Bound every poll.** Cap pages, items and requests per tick. A busy day must not turn one tick
  into an outage.
* **Advance a cursor only past what you return.** The caller stores the events you return. Moving
  the cursor past anything else loses data after a crash.
* **Return `[]` or `null` on a vendor error, don't throw.** One failing source must not stop the
  others, and a push endpoint that answers 5xx gets retried and then disabled by the vendor.
* **Read-only credentials only.** Ask for the smallest read scopes, and say which in `fields.help`.
  Nothing here writes to your systems.
* **Keep `attrs` flat and deliberate.** Everything in it is stored and shown. Leave out secrets,
  tokens and personal data the detectors do not need.
* **Test `verify` and `normalize` with no network**, next to the code as `*.test.ts`. The
  `sentry.test.ts` and `webhook.test.ts` files show the pattern: accept a correct signature, reject
  tampering, a wrong secret and malformed headers, and pin the normalized output.

### Registering it

```ts
// src/connectors/index.ts
import { exampleConnector } from "./example/index.ts"
registerConnector(exampleConnector)
```

Run `pnpm verify`. The connector now appears in **Connectors → Add a connector**. It is created
switched off, and turning it on is a passkey-signed action, like every other source.

### Making a detector use it

A connector only produces events. To have them raise findings, either:
* emit a kind a detector already reads, prefixed with your own source name. That usually means
  asking for the detector to accept it, as `deploy-regression` does for `custom.error`; or
* add a detector: a pure function in `src/domain/detectors/`, an entry in
  `src/domain/detectors/index.ts`, and a call in `src/jobs/tick.ts`. The existing three are small
  and each is commented with what it does and does not claim.

A pull request adding a connector for a common service is welcome. Open an issue first if it needs
anything beyond the one file, its tests and its registration line.
