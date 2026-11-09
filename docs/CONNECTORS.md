# INTYGA Intelligence 1.0 connectors

Version 1.0.0 includes 21 connectors. This guide covers custom events, connector development and
[native provider setup](#native-provider-integrations). The [README catalogue](../README.md#supported-connectors)
lists all sources; each integration has a defined collection scope and needs live-account validation.

Administrators can use **Edit configuration** on every registered connector to change its label,
provider settings and credential. Forms follow each provider's field definitions, including multiline
Google service-account JSON and Prometheus queries. Leave the replacement credential empty to keep
the saved one. Webhook sources with generated secrets offer **Generate replacement secret**; copy
the new secret and update the sender after approval. Saved credentials are never displayed.

Changes take effect only after passkey approval; collected history and polling cursors are retained.
Replacement credentials stay encrypted on the Intelligence host. Non-secret settings and a digest
of the encrypted replacement enter the signed approval parameters. The built-in INTYGA connector
supports label and webhook-secret edits; this does not change the deployment's sign-in credentials,
workspace binding or trust anchor.

**Remove connector** also requires approval. It stops future collection, clears the saved credential
and removes the source from the connector list and configuration selectors. Historical events and
findings remain available. A collection already in progress may finish. Removal does not revoke a
provider token or unregister a provider webhook; do that in the provider if it is no longer needed.
Built-in connectors can be edited or switched off but cannot be removed. To connect a removed source again,
add a new connector and approve its activation.

There are two ways to get events from a system Intelligence does not ship a connector for:

1. **Send them to the custom webhook.** No code in this repository. Anything that can make a
   signed HTTP POST (a CI job, a deploy script, an in-house service) can do it. Start here.
2. **Write a connector.** One TypeScript file plus one registration line. Do this when you want to
   poll an API, or verify a vendor's own webhook signature without a relay in between.

Either way, everything becomes a `NormalizedEvent`. Detectors consume normalized event kinds and
attributes rather than vendor API responses.

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

| Field         | Required | Meaning                                                                              |
| :------------ | :------- | :----------------------------------------------------------------------------------- |
| `id`          | yes      | Your id for this event. **Resending the same id is a no-op**, so retries are safe.   |
| `kind`        | yes      | Lowercase `a-z 0-9 . _ -`. Stored as `custom.<kind>`.                                |
| `at`          | no       | ISO 8601 with an offset. Defaults to when the request arrived.                       |
| `subject`     | no       | Who or what the event is about: a service, a user, a job.                            |
| `correlation` | no       | Ties related events together, such as a commit SHA or a trace id.                    |
| `attrs`       | no       | A **flat** object of strings, numbers, booleans or null. Nested objects are refused. |

The endpoint answers `200` for a verified delivery, even when the body is not a valid event. That
way your queue does not retry a malformed event forever. Such an event is stored raw and not used.
A bad signature gets `401`.

### Kinds the detectors read today

| `kind`          | Read by                                 | `attrs` that matter                                                                                                  |
| :-------------- | :-------------------------------------- | :------------------------------------------------------------------------------------------------------------------- |
| `deployment`    | `deploy-regression`, as the anchor      | `production: true` (**required**, since absence does not mean production), `succeeded` (default true), `sha`, `name` |
| `error`         | `deploy-regression`, as an error signal | none                                                                                                                 |
| `crash`         | `deploy-regression`, as a crash signal  | none                                                                                                                 |
| `ci_run`        | `ci-health`                             | `repo`, `branch`, `workflow`, `runId`, `conclusion`, `event`; send completed attempts only                           |
| `job.completed` | `job-overdue`                           | `job`, `succeeded: true`; set `at` to successful completion time                                                     |
| `slo.sample`    | `service-degradation`                   | `objective`, `windowSeconds: 60`, integer `total`, integer `bad`; `at` is the UTC minute start                       |

Any other kind is stored, and waits for a detector that reads it. If a deployment's `sha` matches a
pull or merge request the GitHub or GitLab connector has seen (head or merge commit), the finding names
that PR and says whether it touched sensitive code.

Why the `custom.` prefix is forced: without it, anyone holding this connector's secret could send
`challenge.denied` and make up an authorization-refusal finding against any subject. A custom event
can only ever be a custom event.

### Operational detector events

Create and enable a **Custom webhook** connector, then add a target on **Detectors → Configure
operational detectors**. Use the same connector and exact job/objective/workflow names in both
configuration and events. Approve the configuration with INTYGA. Collection and findings require
the scheduler to keep running. Each event below uses the signed request format described below.

For a backup, sync, scheduled report or integrity check, emit after successful completion:

```json
{
  "id": "backup-run-123",
  "kind": "job.completed",
  "at": "2026-11-07T02:03:00Z",
  "attrs": { "job": "production-backup", "succeeded": true }
}
```

Configure the expected interval (for example 1440 minutes) and grace (for example 30 minutes).
The initial deadline is monitoring start + interval + grace. A success moves that deadline;
failed completions do not. A missing event means **completion not observed**, so check both the
job and event delivery. The detector cannot prove that a backup is restorable; a scheduled restore
check can send its own completion event. This is an elapsed-interval contract, not a wall-clock cron
schedule. Maintenance pauses monitoring and starts a fresh interval when it ends.

For errors or latency, aggregate a whole service/objective into **one complete sample per UTC minute**:

```json
{
  "id": "checkout-availability-2026-11-07T12:00Z",
  "kind": "slo.sample",
  "at": "2026-11-07T12:00:00Z",
  "attrs": { "objective": "checkout-availability", "windowSeconds": 60, "total": 1000, "bad": 20 }
}
```

Send after the minute has ended. `at` must be exactly minute-aligned; `0 <= bad <= total` and
both counts must be integers. Send zero-count minutes too. For a latency objective, count requests
above your chosen latency threshold as `bad`. Aggregate across instances before sending; do not
send per-instance counts under the same objective. Retries must reuse the event ID and payload.
Conflicting samples, missing minutes and insufficient traffic suppress detection. Windows end at
the latest received complete minute, with at most two minutes of delivery lag. Late samples are
usable while they remain in the current monitoring window. No metrics exporter is automatically
connected by this configuration: your producer must send these aggregates.

For non-GitHub CI, emit each completed attempt with a unique event ID, retaining `runId` across retries:

```json
{
  "id": "build-42-attempt-2",
  "kind": "ci_run",
  "at": "2026-11-07T12:05:00Z",
  "attrs": {
    "repo": "acme/api",
    "branch": "main",
    "workflow": "Build",
    "runId": "42",
    "conclusion": "success",
    "event": "push"
  }
}
```

Failed conclusions are `failure`, `timed_out`, and `action_required`. Successful retries supersede
earlier attempts; `cancelled`, `skipped`, and `neutral` do not count as failures. PR events are
excluded. The producer must send successful outcomes too: the detector can only reason about
collected history. Findings older than 24 hours without fresh CI outcomes are suppressed.

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

(If you already connect GitHub, naming the workflow in its _Deploy workflow names_ setting does
the same thing without this step.)

---

## 2. Writing a connector

A connector is one object implementing `PushConnector` or `PollConnector`
([`src/connectors/registry.ts`](../src/connectors/registry.ts)), registered with one line in
[`src/connectors/index.ts`](../src/connectors/index.ts). You don't need a migration, a schema
change, or edits to the ingest route, the tick or the UI. The **Add a connector** form is generated
from your `fields`, and the setup page from your `setup` steps.

The existing connectors are the best reference:

| Shape                                                | Look at                                               |
| :--------------------------------------------------- | :---------------------------------------------------- |
| Push, vendor-supplied secret, HMAC without timestamp | `src/connectors/sentry/`                              |
| Push, secret we mint, timestamped HMAC               | `src/connectors/intyga/`, `src/connectors/webhook/`   |
| Push, SHA-1 HMAC                                     | `src/connectors/vercel/`                              |
| Push, HMAC with rotation (several signatures)        | `src/connectors/pagerduty/`                           |
| Push, signed JWS (HS256)                             | `src/connectors/netlify/`                             |
| Push, vendor cannot sign, shared-secret header       | `src/connectors/opsgenie/`, `src/connectors/datadog/` |
| Poll, paginated diffs + self-managed base URL        | `src/connectors/gitlab/`                              |
| Poll, unordered list, own cursor                     | `src/connectors/cloudflare/`                          |
| Poll, paginated API with cursors                     | `src/connectors/github/`                              |
| Poll, query API                                      | `src/connectors/metrics/`, `src/connectors/fly/`      |

### The shape everything becomes

```ts
interface NormalizedEvent {
  connectionId: string // passed to you
  source: string // your connector's kind
  sourceId: string // unique per connection: the idempotency key
  kind: string // "<source>.<event>", e.g. "pagerduty.incident.triggered"
  at: Date // when it happened at the source
  subjectRef: string | null // who or what a finding would be about
  correlationRef: string | null // what ties it to other events (a commit SHA, a trace id)
  attrs: Record<string, string | number | boolean | null> // flat
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
  generatesSecret: false, // true: we mint the secret and show it once; false: the user pastes theirs
  fields: [{ name: "secret", label: "Signing secret", required: true, secret: true }],
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
    if (!b?.id || !b.type) return null // not something we model: stored raw, not used
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
    if (!res.ok) {
      ctx.log("example poll failed", { status: res.status })
      return []
    }
    const items = (await res.json()) as { id: string; at: string }[]
    let newest = since
    const out = items.map((i) => {
      if (i.at > newest) newest = i.at
      return {
        connectionId: ctx.connectionId,
        source: "example-poll",
        sourceId: i.id,
        kind: "example-poll.item",
        at: new Date(i.at),
        subjectRef: null,
        correlationRef: null,
        attrs: {},
      }
    })
    await ctx.setCursor("items", newest)
    return out
  },
}
```

### Rules a connector must follow

These are the review criteria. Each one exists because breaking it caused a real problem.

- **Verify over the raw bytes, in constant time.** `verify` gets the exact request body. Use
  `timingSafeEqual`, and handle unequal lengths before calling it.
- **Say what the vendor's scheme cannot do.** If it has no timestamp (Sentry), a captured delivery
  replays forever and only `eventId` idempotency contains that. Write it in a comment.
- **`sourceId` must be stable per event.** It is the idempotency key, and a random one turns every
  retry into a duplicate.
- **Bound every poll.** Cap pages, items and requests per tick. A busy day must not turn one tick
  into an outage.
- **Advance a cursor only past what you return.** The caller stores the events you return. Moving
  the cursor past anything else loses data after a crash.
- **Report polling failures through `ctx.log`.** It marks the poll unhealthy; it is not a debug
  logger. Return the events safely collected so far, or `[]` if there are none. An empty successful
  poll is healthy, so silently returning `[]` on a vendor error hides the failure. Push signature
  failures return `{ ok: false, reason }`; unsupported event shapes normalize to `null`.
- **Read-only credentials only.** Ask for the smallest read scopes, and say which in `fields.help`.
  Nothing here writes to your systems.
- **Keep `attrs` flat and deliberate.** Everything in it is stored and shown. Leave out secrets,
  tokens and personal data the detectors do not need.
- **Test `verify` and `normalize` with no network**, next to the code as `*.test.ts`. The
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

- emit a kind a detector already reads, prefixed with your own source name. That usually means
  asking for the detector to accept it, as `deploy-regression` does for `custom.error`; or
- add a detector: a pure function in `src/domain/detectors/`, an entry in
  `src/domain/detectors/index.ts`, and a call in `src/jobs/tick.ts`. The existing detectors are small
  and each is commented with what it does and does not claim.

A pull request adding a connector for a common service is welcome. Open an issue first if it needs
anything beyond the one file, its tests and its registration line.

## Native provider integrations

The catalogue now contains 21 connectors. The eight below accept documented provider formats or
query native APIs; they are not aliases for the generic custom webhook. Creating one saves it
**inactive**. Turning it on still requires INTYGA approval. Configure an HTTPS public endpoint for
push sources; polling sources need no inbound provider access. Development on localhost requires
an appropriate tunnel for real webhook deliveries.

| Connector                     | Implemented signals                                                                                                | Authentication                                                              | First verification                                           |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------- | ------------------------------------------------------------ |
| AWS EventBridge               | CloudWatch ALARM/OK; failed/completed Backup, Copy and Restore jobs; AWS Health issues; GuardDuty findings/archive | EventBridge API Destination API-key header                                  | Forward a representative event using a narrowly scoped rule  |
| Google Cloud Monitoring       | Native open/closed Monitoring incidents                                                                            | HTTP Basic, username `intelligence`, generated connector secret as password | Test notification channel, then send a real alert            |
| Google Workspace Alert Center | Provider security alert metadata, medium/high severity, explicit closure/deletion                                  | Dedicated service-account JSON key and delegated admin identity             | Run scheduler; inspect poll status and first collected alert |
| Azure Monitor                 | Fired/Resolved monitor conditions across one subscription                                                          | Dedicated Entra client credentials; Monitoring Reader                       | Run scheduler with a known alert                             |
| Grafana Alerting              | Individual firing/resolved alerts inside native grouped notifications                                              | HTTP Basic                                                                  | Test contact point, then real firing and resolved group      |
| Prometheus Alertmanager       | Individual firing/resolved alerts inside native grouped notifications                                              | HTTP Basic                                                                  | Send a native alert group, then its resolved notification    |
| Stripe                        | Failed payouts, payment disputes, payout recovery and dispute closure                                              | Stripe raw-body signature with timestamp tolerance                          | Stripe CLI or endpoint test delivery using snapshot events   |
| Better Stack                  | Confirmed uptime/heartbeat incidents and explicit recovery                                                         | Team-scoped API token                                                       | Run scheduler against a confirmed incident                   |

Provider alerts become findings only at **medium, high or critical** severity. Unknown/low Workspace
or Azure severity is not promoted. CloudWatch alarms and unlabelled Grafana/Alertmanager/Google
Monitoring incidents default to medium because a provider alert rule already fired. Configure alert
thresholds and notification routing at the source. Findings state that they reflect a provider's
condition; no model request is needed. They do not currently feed the separate deploy-regression
detector automatically.

A connector still maps to one Intelligence service. For now, create separate connections and
resource-scoped provider rules for separate products/environments. Native account/resource IDs are
retained in event attributes, but account-wide automatic service discovery is a later milestone.

### AWS: no stored AWS access key

1. Add **AWS EventBridge** in Intelligence; copy the generated secret and endpoint.
2. In EventBridge, create a Connection with API Key authorization. Use header
   `x-intelligence-token` and the secret as its value.
3. Create an API Destination using that Connection, method `POST`, and the Intelligence endpoint.
4. Create rules in the accounts/regions that contain the selected resources. Forward original
   events; do not use a custom input transformer. Set retries and a dead-letter queue.
5. Turn the connector on and inspect a real or representative provider event.

Example CloudWatch event pattern (add account/resource restrictions appropriate to your deployment):

```json
{
  "source": ["aws.cloudwatch"],
  "detail-type": ["CloudWatch Alarm State Change"],
  "detail": { "state": { "value": ["ALARM", "OK", "INSUFFICIENT_DATA"] } }
}
```

`INSUFFICIENT_DATA` is ignored by the finding rule, never interpreted as recovery. Supported Backup
states are FAILED, ABORTED, EXPIRED and COMPLETED. AWS Health `scheduledChange` events are ignored;
only `issue` events with open/closed states are interpreted. GuardDuty scores below 4 are retained
without a finding; 4–6.9 map to medium, 7–8.9 to high and 9+ to critical.

This adapter does not yet import arbitrary CloudTrail events, Security Hub, billing alerts or all
EventBridge service events. AWS Backup's event stream is best effort, so it cannot establish that
an expected backup never ran. Use the scheduled-job contract or an upstream heartbeat monitor for
that. [API Destination setup](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-api-destinations.html),
[Backup delivery semantics](https://docs.aws.amazon.com/aws-backup/latest/devguide/eventbridge.html).

### Google: Cloud Monitoring and Workspace are separate connectors

**Cloud Monitoring** uses the provider's native webhook channel with Basic authentication. Use
username `intelligence`, the generated connector secret as password, and the endpoint shown in the
console. Attach the channel to selected alert policies, including incident-closure notifications.
No service-account key is required for this push integration. Pub/Sub envelopes are not accepted by
this adapter. [Notification channel setup](https://docs.cloud.google.com/monitoring/support/notification-options#webhooks).

**Workspace Alert Center** requires a dedicated service account and super-admin-authorized
domain-wide delegation for `https://www.googleapis.com/auth/apps.alerts`. Configure the delegated
administrator's email and the service-account JSON key. The scope is broader than read-only even
though this implementation only lists alerts. The key is encrypted at rest; only short-lived access
tokens are cached in memory. No Gmail or Drive data-access scopes are requested, and detailed alert
user/message payloads are not copied into normalized events. This initial setup is manual, not a
one-click Google OAuth installation. [Official authorization/setup](https://developers.google.com/workspace/admin/alertcenter/guides).

Workspace reads up to five pages of 100 alerts sorted by update time. Larger result sets report
incomplete coverage. Native alert ID/state/change time make repeated snapshots idempotent.

### Azure and Better Stack polling

Azure requires the public Azure cloud, an Entra tenant/application/client secret, subscription ID,
and Monitoring Reader access. Alerts are read from the documented Alerts Management API, using a
30-day window and up to five pages of 100 results. Acknowledging an alert does not resolve it;
`monitorCondition=Resolved` does. Sovereign clouds, resource inventory and automatic rule creation
are not implemented. [API contract](https://learn.microsoft.com/en-us/rest/api/alerts-management/alerts/alerts/get-all?view=rest-alerts-management-alerts-2019-03-01).

Better Stack uses a team API token and the current Incidents API. It reads at most five pages of
50 incidents, including confirmed active and resolved incidents. Unconfirmed states are ignored;
Validating and Acknowledged remain active. No response bodies or screenshots are copied.
The token may permit more than reads; this connector only makes GET requests.
[API contract](https://betterstack.com/docs/uptime/api/list-all-incidents/).

Both report incomplete coverage when the page budget is exhausted. Both reject pagination links
outside their fixed provider origin/scope, and authenticated requests refuse redirects. Polling
snapshots record when current state was observed and preserve the provider's change time separately.
An incident missing from a response is never treated as resolved.

### Grafana and Alertmanager

Grafana: create a Webhook contact point, retain the default JSON body, choose Basic authentication
(username `intelligence`, password the generated connector secret), and enable resolved messages.
This connector uses Basic authentication, not Grafana's optional HMAC scheme.
[Grafana webhook reference](https://grafana.com/docs/grafana/latest/alerting/configure-notifications/manage-contact-points/integrations/webhook-notifier/).

Alertmanager receiver example:

```yaml
receivers:
  - name: intelligence
    webhook_configs:
      - url: https://intelligence.example/ingest/alertmanager/CONNECTION_ID
        send_resolved: true
        max_alerts: 0
        http_config:
          basic_auth:
            username: intelligence
            password_file: /run/secrets/intelligence-webhook-password
```

Route at most 200 alerts into a single group. `max_alerts: 0` avoids silent truncation; split groups
using routing labels when necessary. Requests declaring truncation or containing more than 200
alerts are retained as failed normalization and shown as Delivery errors. Each alert has an
independent identity; a group recovery cannot close unrelated incidents.
[Alertmanager webhook reference](https://prometheus.io/docs/alerting/latest/configuration/#webhook_config).

### Stripe

Use **snapshot events**, with `payout.failed`, `payout.paid`, `charge.dispute.created`, and
`charge.dispute.closed`. Use the endpoint's signing secret, not an API key. Separate test and live
connections. Signatures cover the raw bytes; timestamps beyond five minutes are rejected; multiple
v1 signatures are accepted for rotation. Individual payment declines and failed invoices are not
anomalies and do not create findings. Closing a dispute does not mean it was won.
[Stripe webhook reference](https://docs.stripe.com/webhooks).

### Verification and operational limits

Automated coverage includes authentic/forged/expired signatures, native payload normalization,
malformed and truncated batches, token exchange with signed delegated claims, pagination boundaries,
provider errors, duplicate and out-of-order events, inactive sources, tenant/service isolation,
finding creation, and explicit recovery. Provider API tests use mocks and representative documented
fixtures. These checks establish implementation behavior; they do not establish that a particular
customer's IAM roles, billing plan, alert rules or delivery configuration work. Complete the final
live check after configuring an account: provider event → authenticated delivery/poll → stored event
→ finding → provider recovery → resolved finding.

Basic/API-key connectors rely on HTTPS and a shared secret; they are not body-signing protocols.
Webhook raw payloads are retained by the existing ingestion store, so treat them as provider data
under the deployment's retention/access policy. The no-content-copy guarantee above applies to the
poll adapters' normalized metadata, not arbitrary raw webhook payloads.

The scheduler is still responsible for polling and detection. Polling is bounded and sequential;
these integrations do not introduce a background queue or promise unlimited account coverage.

## Integration expansion plan

The goal is to let a team install Intelligence using tools it already has. Prioritize a searchable,
honest catalogue and working setup paths; keep planned options out of the installable catalogue
until they have authentication, useful detector coverage and verification.

| Stage                         | Services or capabilities                                                                                                                      | Useful outcomes                                                                              | Completion gate                                                                               |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| Delivered foundation          | Native alerts from the eight integrations above; searchable categories and coverage descriptions                                              | First useful finding from existing provider rules; explicit recovery                         | Fixture/auth tests and local browser/API/database flow                                        |
| Easier cloud installation     | AWS provisioning templates; Google delegated setup validation; Azure credential validation; private-network pull option                       | Fewer manual steps, actionable permission errors, reliable uninstall/revocation              | A fresh account can install, test and remove the integration using its guide                  |
| Resource-aware coverage       | AWS accounts/regions, GCP projects, Azure subscriptions, Kubernetes namespaces mapped to products and environments                            | One cloud connection safely supports multiple Intelligence services                          | Cross-tenant/account/environment isolation and editable mapping preview                       |
| Deeper cloud monitoring       | AWS CloudTrail/Security Hub/cost signals; GCP Audit Logs, Security Command Center, Billing, Cloud Build; Azure Activity Logs and cost signals | Confirmed control violations, infrastructure failures, budget changes and deployment context | Each signal has documented API coverage, freshness and a concrete rule                        |
| Workspace and identity        | Workspace Admin SDK reports, Microsoft 365 service health, Entra, Okta, Auth0                                                                 | Provider security alerts, risky changes under explicit policies, SSO outages                 | Minimum scopes, content minimization and verified admin-consent paths                         |
| Portable infrastructure       | OpenTelemetry collector bridge, Alertmanager extensions, Kubernetes, PostgreSQL, Redis, Kafka, RabbitMQ                                       | Service error budgets, queue age, replication lag, restore-check failures                    | Complete windows, meaningful thresholds and lightweight deployment recipe                     |
| Business and customer systems | Broader Stripe aggregates, Shopify, Paddle, email providers, Zendesk/Intercom, HubSpot/Salesforce                                             | Payment failure-rate increases, delivery problems, urgent support/SLA issues                 | Volume baselines and privacy-safe aggregate collection                                        |
| Google business products      | GA4, Search Console, Google Ads                                                                                                               | Tracking failures, sustained traffic/conversion changes, spend without expected results      | OAuth/access verification, quota budgeting, finalized reporting windows and seasonality tests |
| Delivery and workflow tools   | Buildkite, CircleCI, Bitbucket, Argo CD, Terraform Cloud, Linear and Jira                                                                     | Failed production delivery, drift backed by actual plans, incident follow-through            | Distinguish ordinary work from failures; correlate resource and deployment identities         |

The Google business products are separate from Google Cloud and Workspace. Reuse the same service
identity and incident view, but keep reporting-delay logic separate from operational alerting.
Search Console does not guarantee all result rows, and missing rows must not be interpreted as zero
traffic. Analytics/Ads access and quotas need validation during their implementation milestone.
[Search Console query limitations](https://developers.google.com/webmaster-tools/v1/searchanalytics/query),
[GA4 quotas](https://developers.google.com/analytics/devguides/reporting/data/v1/quotas).

Before expanding high-volume account coverage, add durable asynchronous ingestion, retries,
dead-letter handling, resumable backfill, per-account rate budgets, credential rotation and explicit
freshness/coverage status. Prefer short-lived federated cloud credentials when the hosting identity
supports them. Preserve source identity when translating signals; custom webhooks must never be able
to impersonate native security-provider events.

For every new integration, define: supported resources; exact authentication and scopes; events or
metrics and their freshness; the detector it unlocks; normal events that must stay quiet; setup and
removal steps; cost/edition prerequisites; fixtures and negative tests; and one real-account smoke
test. Treat a permission failure, truncated export or missing baseline as unknown coverage rather
than healthy service state. A deployment, PR merge, scaling action or role assignment becomes a
finding only with an explicit failure/policy condition or corroborating evidence.
