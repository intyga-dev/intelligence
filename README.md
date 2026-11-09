# INTYGA Intelligence

**Operational attention compression for modern engineering systems.**

Observe → Classify → Correlate → Surface. INTYGA Intelligence turns high-volume telemetry, Git
commits, CI/CD deployments and authorization events into a **short, prioritised list of
evidence-backed findings** that genuinely need human attention.

> **MFA verifies who you are. INTYGA verifies what you are doing. Intelligence shows what matters.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

---

## Read this first

**Free to self-host. INTYGA approvals are required.** Configure an INTYGA workspace, a SERVICE API
key and an exported trust-anchor file in the deployment environment. Start with the
[self-hosting walkthrough](docs/SELF_HOST.md).

Intelligence is a self-hosted application with member-bound embedded approvals. Link your real INTYGA workspace membership
once, then create an application passkey. Sign-in and protected changes use that passkey inside
Intelligence. ADMINs administer; MEMBERs read. Quorum, eligibility and one-use redemption remain
INTYGA’s responsibility. Intelligence verifies every receipt against a mounted application trust
anchor before redemption and execution. OIDC is optional; there is no local password or gate bypass.
Before configuration, explore the static example incident at `/demo`.

Group deployment, error and incident sources into **Services** to investigate their findings and
recent observations together. Deploy regressions use only signals from the same service.

**Version: `1.0.0`.** Ten deterministic detectors and 21 connectors are included.
See the [release notes](CHANGELOG.md), [detector coverage](#deterministic-detectors), and
[connector setup and limits](docs/CONNECTORS.md). Validate each connector against your provider
account before relying on it. There is no support SLA.

---

## Why Intelligence?

Modern engineering teams suffer from **alert fatigue**:

- A deploy goes out on Vercel without passing standard CI.
- An authorization denial spike occurs across an API gateway.
- An error rate in Sentry creeps up ten minutes later.
- Prometheus fires disconnected alerts across three different channels.

Instead of expecting engineers to cross-reference dashboards by hand, **Intelligence correlates
these disparate signals into a unified timeline**.

```mermaid
flowchart LR
    subgraph Sources [Operational Sources]
        direction TB
        G[GitHub PRs & CI]
        V[Vercel Deploys]
        I[INTYGA Access Events]
        S[Sentry Errors]
        P[Prometheus Metrics]
        F[Fly.io Runtime]
    end

    subgraph Intelligence [INTYGA Intelligence]
        direction TB
        Ingest[Normalized Ingestion] --> Detect[Deterministic Detection Engine]
        Detect --> Correlate[Cross-System Correlation]
        Correlate --> Findings[Evidence-Backed Findings]
    end

    subgraph Governance [Governance]
        Changes[Protected configuration changes] --> Approval[WebAuthn Passkey Signing]
    end

    Sources --> Ingest
```

---

## Core guarantees

- **Attention compression, not summarisation.** Not _"summarise everything that happened in
  Slack"_, but _"here are the two things that deviated from baseline today, and why"_.
- **Deterministic evidence first.** A model cannot invent a finding. The type system enforces that
  hard evidence — a baseline refusal ratio, a commit SHA, a changed file path — leads:

  ```typescript
  type EvidenceList = readonly [DeterministicEvidence, ...Evidence[]]
  ```

  AI review is optional, off by default and advisory: it never creates a finding or changes its
  severity, status or alerts.
- **Sign in with an application passkey.** Active INTYGA workspace membership supplies the person
  and role. Application passkeys sign inside Intelligence; private keys stay in the authenticator.
  Optional OIDC uses PKCE. Sessions are opaque, server-side and revocable, with HttpOnly cookies.
- **Every privileged action needs approval.** Intelligence sends the action description, target and
  parameters to INTYGA. It verifies the receipt against the frozen request and the locally pinned
  approver keys, then redeems the approval before executing. This is an ordinary workspace approval,
  not a hash-only platform ceremony.

---

## The security invariant

> **Intelligence may ask INTYGA for permission. It may never hold the power to grant it, bypass it,
> or read across it.**

- **Observation degrades open.** If Intelligence is offline, INTYGA authorization is completely
  unaffected. Nothing in the approval path depends on this service.
- **Privileged actions fail closed.** If INTYGA is unreachable, no privileged administrative action
  in Intelligence can execute. Missing workspace credentials or trust configuration means _refused_, never _allowed_.
- Intelligence holds an ordinary **SERVICE API key** (client ID and secret). It can request approvals
  under the workspace's rules, but it cannot sign them. OIDC sign-in optionally uses a separate public
  client with no secret. The exported trust anchor contains public keys and WebAuthn pinning.
- [`scripts/check-no-intyga-client.mjs`](scripts/check-no-intyga-client.mjs) enforces the shape of
  that boundary in CI: no INTYGA operator credentials in this process's environment, no direct
  database access to INTYGA, no admin, policy, sweep or internal endpoints. It is a text scan and
  says so in its own comments — the design is the control, the script is the ratchet that makes
  breaking it deliberate.

### First-time setup and sign-in

The deployment environment is the only source of connection settings. Set the gateway and console
URLs, workspace ID, service client ID and secret, and `PUBLIC_URL`; mount the exported online trust
anchor and set `INTYGA_TRUST_ANCHOR_FILE`. Its `tenantId` must match `INTYGA_WORKSPACE_ID`. The UI
shows connection status and cannot replace credentials, trust keys or the workspace. None of those
settings are stored in the database.

Register the origin and SERVICE key in **INTYGA → Integrations → Member applications**, serve the
short-lived ownership proof, and verify it. Set `INTYGA_EMBEDDED_APPLICATION_ID`. Members authorize
linking with their console passkey, then create a separate passkey on Intelligence’s origin.
The service cannot choose an email and enroll as that person. Export the application’s trust anchor
after enrollment and mount it before sign-in. See [the full sequence](docs/SELF_HOST.md#connect-intyga).

Sign-in binds a random browser identifier, instance origin and duration into an approval. The
initiating browser receives the signing member’s current workspace role. Application credentials
cannot sign in to the INTYGA console. Revoking an application, its passkey, or membership invalidates
embedded approvals, including approvals awaiting redemption. Shared approval links let other
eligible members contribute to quorum using their own application passkeys.

Embedded requests use INTYGA's application-specific authorization endpoint. Approve inside
Intelligence, or share its application approval link with another eligible member. INTYGA does not
send console approval notifications for these requests; quorum, audit records and receipt checks
still apply. The gateway must support application approval routing; Intelligence refuses to fall
back to a console ceremony when that endpoint is unavailable.

Without embedded configuration, normal approval sign-in opens INTYGA and explicitly grants its
initiating browser ADMIN access for 12 hours. Optional OIDC uses a registered `/auth/callback` URI
and `INTYGA_OIDC_CLIENT_ID`; its verified identity claims determine the role. Use the console-origin
anchor for that mode. Existing sessions expire within 12 hours unless revoked locally; upstream role
changes refresh at sign-in. Changing deployment identity invalidates old sessions and pending actions.

A deployment operator can put arbitrary public keys into a trust anchor. A bad anchor can make actions
fail, but it cannot bypass approval: INTYGA independently checks eligibility and one-use redemption.

---

## Supported connectors

Every data source maps into a single canonical [`NormalizedEvent`](src/connectors/types.ts).
Detectors never observe raw vendor APIs.

| Connector            | Ingest mode                               | Signals contributed                                                                                         |
| :------------------- | :---------------------------------------- | :---------------------------------------------------------------------------------------------------------- |
| **INTYGA**           | `push` (webhook)                          | Authorization approvals, refusals, expiries and approval latency.                                           |
| **GitHub**           | `poll` (API)                              | Pull requests with changed file paths, CI workflow outcomes, deploy runs.                                   |
| **Metrics**          | `poll` (Prometheus)                       | Samples of PromQL queries. Known INTYGA failure counters and ledger-integrity gauges feed `metrics-health`. |
| **Custom webhook**   | `push` (signed JSON)                      | Anything you send it. `deployment`, `error` and `crash` events feed deploy-regression.                      |
| **Sentry**           | `push` (webhook)                          | Post-release exception spikes and regression indicators.                                                    |
| **Vercel**           | `push` (webhook)                          | Production and preview deployment lifecycles mapped to commit SHAs.                                         |
| **Fly.io**           | `poll` (API)                              | Machine state changes, restarts and OOM kills.                                                              |
| **GitLab**           | `poll` (API, gitlab.com or self-managed)  | Merge requests with changed paths, and deployments per environment.                                         |
| **PagerDuty**        | `push` (webhook v3, signed)               | Incidents triggered, acknowledged and resolved.                                                             |
| **Opsgenie**         | `push` (webhook, shared-secret header)    | Alerts created and closed. For existing Opsgenie deployments; confirm provider availability.                |
| **Datadog**          | `push` (webhook, shared-secret header)    | Monitor alerts triggering and recovering.                                                                   |
| **Cloudflare Pages** | `poll` (API)                              | Finished Pages deployments mapped to commit SHAs.                                                           |
| **Netlify**          | `push` (deploy notifications, signed JWS) | Deploys that went live or failed, mapped to commit SHAs.                                                    |

The following native alert integrations complete the 21-connector catalogue:

| Connector                     | Ingest mode | Implemented signals                                                                  |
| ----------------------------- | ----------- | ------------------------------------------------------------------------------------ |
| AWS EventBridge               | Push        | CloudWatch alarms, Backup jobs, Health issues and GuardDuty findings.                |
| Google Cloud Monitoring       | Push        | Open and closed Monitoring incidents.                                                |
| Google Workspace Alert Center | Poll        | Alert metadata and provider status; no Gmail or Drive content.                       |
| Azure Monitor                 | Poll        | Alerts Management alerts for a configured public-Azure subscription.                 |
| Grafana Alerting              | Push        | Individual firing and resolved alerts in grouped deliveries.                         |
| Prometheus Alertmanager       | Push        | Individual firing and resolved alerts; does not scrape metrics.                      |
| Stripe                        | Push        | Failed/paid payouts and created/closed disputes; excludes ordinary payment declines. |
| Better Stack                  | Poll        | Monitor and heartbeat incidents with explicit recovery.                              |

These feed `provider-alerts`; provider reports do not independently establish a root cause.
See [authentication and first-event checks](docs/CONNECTORS.md#native-provider-integrations).

**Your own sources:** send signed JSON to the custom webhook with no code, or write a connector in one
file. [docs/CONNECTORS.md](docs/CONNECTORS.md) covers both, with signing examples for bash, Node and
Python, a GitHub Actions snippet, and the rules a connector has to follow.

---

## Deterministic detectors

Ten detectors ship. Each is a pure function over stored events, runs on every detection tick, and
can be switched off on `/detectors`. Switching one off is a passkey-signed action. The severity and
the reason a finding exists are always computed; an optional AI review is shown beside them and changes neither.

- **`denial-burst`** — a subject refused far more than it usually is, judged against its own
  history, plus any action type it has never attempted before. _Needs:_ the INTYGA connector.
  ([source](src/domain/detectors/denialBurst.ts))
- **`sensitive-code-change`** — informational review observations for pull requests touching sensitive paths.
  They appear under **Findings → Observations**, do not trigger alerts, and are not sent for model anomaly scoring.
  A merge or path match alone does not establish unusual behavior. Conventional names such as
  auth, sessions, permissions, crypto, secrets, migrations, infrastructure and CI provide review
  context for any repository. Path names cannot establish cross-package compatibility.

  Drafts and noise (lockfiles, docs, blog articles, styles, tests) are skipped. Each PR has one observation, updated on each
  push. Works the same on GitLab merge requests. _Needs:_ the GitHub or GitLab connector. ([source](src/domain/detectors/sensitiveChange.ts))
- **`deploy-regression`** — errors (Sentry), machine crashes (Fly), incidents (PagerDuty,
  Opsgenie, Datadog; one is enough) or the approval refusal rate (INTYGA) rising in the 30 minutes
  after a successful production deploy (GitHub, GitLab, Vercel, Netlify, Cloudflare Pages, or a
  custom event), compared with the 24 hours before. When the deployed commit matches a PR it has seen (head or merge commit), the
  finding names the PR, and severity rises one step if that PR touched sensitive code.
  This is timing, not proof of cause, and each finding says so.
  _Needs:_ a deploy source, plus at least one signal source.
  ([source](src/domain/detectors/deployRegression.ts))

Noise guards are part of each detector, not tuning left to you:

- **Floors.** A minimum count before anything fires.
- **Own baselines.** Each subject or service is judged against its own normal level.
- **History.** A newly connected source does not make the next deploy look like a regression.
- **Volume.** A refusal _rate_ needs enough approvals to mean something.

- **`metrics-health`** — detects increases in the default INTYGA audit-write, replay-guard,
  approval-requirement, notification and billing-refusal counters, plus positive broken-block or
  broken-checkpoint gauges. Counter samples must belong to the same source and label set and be no
  more than 15 minutes apart. Initial lifetime values, counter resets and longer collection gaps
  do not trigger findings. Only newly ingested samples from the last 15 minutes are evaluated;
  rerunning a completed tick does not count them again. **Needs:** the Metrics connector with bare
  metric queries (the defaults work). Transformed PromQL expressions, age/backlog gauges and other
  metrics are stored without automatic interpretation.
  ([source](src/domain/detectors/metricsHealth.ts))

Enter custom PromQL expressions one per line. Comma-separated bare metric names remain supported;
commas inside selectors or functions are preserved.

The operational detectors have editable settings on **Detectors → Configure operational detectors**.
Settings changes use the same signed INTYGA action flow as switching a detector on/off.

**`provider-alerts`** imports medium-or-higher native alerts from AWS EventBridge, Google Cloud
Monitoring, Google Workspace Alert Center, Azure Monitor, Grafana, Prometheus Alertmanager, Stripe
and Better Stack. These eight additions bring the catalogue to 21 connectors. Search the catalogue
by provider or use its categories; every card explains its implemented detector coverage.
Native alerts are labelled as provider-reported conditions, not independent anomaly assessments.
Explicit provider recovery closes only the matching incident; silence and acknowledgement do not.
See [setup recipes, coverage limits and the expansion plan](docs/CONNECTORS.md#native-provider-integrations).

| Detector              | Condition                                                                                                     | Setup                                                                                                                                        |
| --------------------- | ------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `collection-health`   | Three failed polls in a row, or a recorded gap over 15 minutes when polling resumes (defaults).               | Automatic for active polling connectors. Successful empty polls are healthy; push silence is not a failed poll.                              |
| `ci-health`           | Three failed workflow runs or a failure at least 30 minutes old without a later collected success (defaults). | Select connector, repository, branch and exact workflow name. GitHub Actions or signed `ci_run` events.                                      |
| `merge-policy`        | GitHub recorded an accepted bypass with a failed active review or required-check rule.                        | Select GitHub repositories/branches with rulesets; token needs **Administration: read** in addition to normal connector permissions.         |
| `job-overdue`         | No successful completion within the configured interval plus grace.                                           | Select a custom webhook, job name, start time, interval and grace; emit `job.completed` after successful backups, syncs or scheduled checks. |
| `service-degradation` | Both short and long windows exceed the configured error-budget burn threshold.                                | Select a custom webhook and objective; emit complete one-minute `slo.sample` aggregates for errors or slow requests.                         |

All but collection health start with no targets. [Webhook examples and setup details](docs/CONNECTORS.md#operational-detector-events)
cover non-Git systems. SLO defaults: 99.9% success, 5m/60m windows, 14.4× burn and at least 100 requests
per window. Missing or conflicting minute aggregates mean unknown health and produce no degradation
finding. Job and SLO targets support a maintenance end time. Job intervals restart after maintenance;
SLO monitoring waits for a complete post-maintenance window.

Changing operational settings or re-enabling a detector starts a fresh monitoring period; old events
are not replayed. Job monitoring starts no earlier than its configured start, connector activation,
or latest settings change. Repeated ticks over identical evidence do not reopen dismissed findings.
Healthy data stops new detections; existing findings remain available for human resolution.
These five detectors use deterministic evidence and do not request model anomaly scores.

Collection health runs inside the scheduler: it cannot report a stopped scheduler until polling
resumes. Use an external uptime/dead-man monitor for that. CI failures older than 24 hours or GitHub
collection errors are treated as unknown. GitHub polling is bounded to 50 recent runs per repository;
high-volume repositories that exceed a day's coverage report a collection error. Ruleset collection
looks back one day, at most 500 evaluations per target and 40 bypass details per connector per tick;
incomplete coverage reports a collection error and retains cursors for retry. Classic branch
protection without ruleset evaluations is not covered. A recorded bypass can be an authorized
exception: it is a review finding, not proof of misconduct.

The merge detector uses [GitHub's historical rule-suite API](https://docs.github.com/en/rest/repos/rule-suites).
The service detector follows the [multiwindow burn-rate approach](https://sre.google/workbook/alerting-on-slos/).

Adding a detector: a pure function in `src/domain/detectors/`, an entry in
`src/domain/detectors/index.ts`, and a call in `src/jobs/tick.ts`. Failures are isolated per
detector, so a new one cannot take the working ones down with it.

---

## Quickstart

_Local evaluation. For the bundled Docker stack, follow [docs/SELF_HOST.md](docs/SELF_HOST.md).
For independently managed infrastructure, use [docs/PRODUCTION.md](docs/PRODUCTION.md)
and [`.env.production.example`](.env.production.example)._

### Prerequisites

- **Node.js** `v26+` and **pnpm** `v10+`
- **Docker & Docker Compose** (for PostgreSQL)
- **An INTYGA workspace** with a SERVICE key and trust anchor (OIDC is optional) — see
  [Read this first](#read-this-first). On INTYGA Cloud the gateway is `https://api.intyga.com` and
  the console is `https://app.intyga.com`.

### 1. Clone and configure

```bash
git clone https://github.com/intyga-dev/intelligence.git
cd intelligence
cp .env.example .env
pnpm install
```

Generate a 32-byte key for encrypting connector credentials at rest, and set `SECRETS_ENC_KEY`:

```bash
openssl rand -base64 32
```

### 2. Start PostgreSQL and run migrations

```bash
docker compose up -d postgres
pnpm db:generate
pnpm db:deploy
```

### 3. Create approval credentials in INTYGA

In **API Keys → Create a service and its key**, save the SERVICE client ID and secret. Configure
its approvers under **Approval Rules**. Register Intelligence’s origin and service client ID under
**Integrations → Member applications**. Save the application UUID and download its ownership proof.
The workspace ID is shown at the top of API Keys. For local origin verification, the INTYGA console
must run with `EMBEDDED_ALLOW_LOCALHOST=true` in development.

### 4. Configure the connection

Set these in your private `.env`. The URLs below suit a local INTYGA development stack; for INTYGA
Cloud use the values in [`.env.production.example`](.env.production.example):

```dotenv
PUBLIC_URL=http://localhost:4100
INTYGA_URL=http://localhost:8787
INTYGA_CONSOLE_URL=http://localhost:3999
INTYGA_WORKSPACE_ID=<workspace-id>
INTYGA_SERVICE_CLIENT_ID=<service-client-id>
INTYGA_SERVICE_CLIENT_SECRET=<service-secret>
INTYGA_TRUST_ANCHOR_FILE=./config/intyga-trust-anchor.json
INTYGA_EMBEDDED_APPLICATION_ID=<application-id>
INTYGA_EMBEDDED_REGISTRATION_FILE=./config/intyga-embedded-registration.json
# Optional:
INTYGA_OIDC_CLIENT_ID=
```

Create `config/` and save the ownership proof there. After members link their passkeys, export and
save the application trust anchor there too. Keep `.env` owner-readable only; both
local configuration paths are ignored by Git. The anchor must name the configured workspace.
No browser form or database command is needed to configure the connection.

### 5. Start the application

```bash
pnpm dev
```

Open **`http://localhost:4100`**. Source edits hot reload. For a local INTYGA gateway, run the app
on the host so `localhost:8787` is reachable. Docker's `host.docker.internal` is not loopback;
the SDK refuses plain HTTP to it. Container deployments should use an HTTPS gateway.

### 6. Sign in and approve a change

Choose **Verify ownership** in INTYGA before the proof expires. In Intelligence, choose **Link my
INTYGA membership**, authorize with the console passkey, and create an application passkey on return.
Export the application trust anchor from Member applications and mount it in `config/`.

Sign in with the application passkey. In **Settings**, click **Test connection**, then create a
Service or activate a connector and approve directly in Intelligence. If the rule needs more than
one approver, share the application approval link with other enrolled workspace members.
Intelligence verifies and redeems the completed approval before making the change.

The approval dialog separates review, passkey entry, workspace approval and applied states. A
successful signature alone never shows the change as applied. Action toasts report progress,
failures and success; saved feedback and approved changes keep their success message across reloads.
Styles live in `src/ui/*.module.css`, served through a fixed asset allowlist. This server-rendered
app uses component selectors for scoping and does not require a frontend bundler.

---

## Your display name

Choose **Edit your name** beside your signed-in identity, or open `/profile`. Save a name of
1–80 characters for activity attribution. It persists across sign-ins. This is a display
preference: it does not change your INTYGA identity, workspace role, passkeys or recorded actor IDs.

## Adding connectors

1. Navigate to **Connectors** (`http://localhost:4100/connectors`).
2. Under **Add a connector**, select an integration.
3. Enter a label (e.g. `INTYGA Staging`, `GitHub Production`).
4. Follow the integration's setup instructions: push connectors supply an ingestion URL and
   authentication details; polling connectors use the credentials you entered.
5. Click **Turn on** — this requires an administrator passkey tap, because it starts a data flow.

The connector page distinguishes setup pending, awaiting a first poll or delivery, successful
polling, overdue polling (no poll for 15 minutes), and ingestion errors. Poll failures retain a safe
summary and the time of the last successful poll. A successful empty poll is normal; webhook
silence is not treated as an outage. Setup instructions remain available after activation.

## Investigating findings

The default view shows findings backed by detector evidence beyond path sensitivity. **Observations**
holds routine sensitive-code changes for review; **Everything** includes both. API clients can use
`kind=finding`, `kind=observation`, or `kind=all` (the API default). Model confidence labels name the
answer they describe: severity confidence is not confidence in an anomaly score.

To update existing path-only findings after upgrading, preview and then apply the reclassification:

```bash
pnpm exec tsx scripts/reclassify-observations.ts <tenant-id>
pnpm exec tsx scripts/reclassify-observations.ts <tenant-id> --apply
```

This preserves IDs, timestamps, counts, feedback and historical model request records. It updates
the review context from stored events, sets informational severity, and removes unsupported model
scores from observation cards. It does not poll providers, call a model, or deliver alerts.

On **Findings**, combine status, severity and category filters with a search over titles, summaries
or a finding ID. Choose highest priority or most recently seen. Priority is applied before
pagination so an older critical finding cannot be hidden behind newer low-severity results.
Filters and page numbers live in the URL for bookmarking and sharing.

Expand changed paths directly in code evidence. Add an optional investigation note, then choose
**investigating**, **fixed**, **expected**, or another feedback action. The most recent five actions
show who recorded them and their notes. Notes are attributed to the signed-in member. Finding-title
links include closed findings, so they keep working after resolution or dismissal.

`GET /api/findings` supports `status` (`open`, `all`, or comma-separated statuses), `severity`,
`category`, `q`, `sort` (`priority` or `recent`), `page`, and `limit` (1–500). The response includes
`findings`, `total`, `page`, `limit`, and `hasMore`. The API defaults to all statuses and 100 results;
the console defaults to open findings and 25 per page. Invalid filters return HTTP 400.

---

## Operational architecture

### Ingestion

`POST /ingest/:kind/:connectionId` is the only inbound data path. Each connector authenticates
deliveries using its documented signature, shared secret or HTTP Basic credentials. Signed payloads
are checked against the raw bytes. Accepted deliveries are stored idempotently by source event ID
and normalized; browser sessions do not authenticate webhook deliveries.

The endpoint is internet-facing by definition, so it spends two token buckets before doing any work
— one global, one per connection — bounding the CPU and the rows an unauthenticated caller can cost.
They are a **cost guard, not an authentication control**; each connector's authentication check
decides whether a delivery is accepted. See [`src/server/ratelimit.ts`](src/server/ratelimit.ts) for what they do and do not bound,
including why they are deliberately not keyed on the client address.

### Detection tick

`POST /internal/tick` polls active polling connectors, runs detection and delivers alerts. An
external scheduler calls it once a minute. The overlap guard is in-process: run one application
instance and one scheduler, and monitor scheduler failures independently. A restart or outage can
leave collection gaps. The endpoint requires a bearer token (`TICK_TOKEN`), compared in constant time:

```bash
curl -X POST http://localhost:4100/internal/tick \
  -H "Authorization: Bearer dev-tick-token-change-me"
```

### Tenancy

Intelligence is **single-tenant per deployment**. The schema carries a `tenantId` column, but there
is no row-level security behind it — scoping is the `where` clause and nothing underneath it. The
single-tenant deployment is the isolation. Read the header comment in
[`prisma/schema.prisma`](prisma/schema.prisma) before considering hosting two unrelated
organisations on one instance; it says exactly what would have to be built first.

---

## Alerts

Alert rules decide which findings are worth interrupting someone for. Findings are recorded
either way.

- **Channels:** a signed JSON **webhook**, or a **Slack incoming webhook**. Email is not available:
  Intelligence has no mail sender.
- **Created switched off.** Turning a rule on is a passkey-signed action that shows the approver
  the destination host, and the host is part of what is signed. That is the moment finding data
  starts leaving the host.
- **What is sent:** each finding's id, title, severity, category, status, occurrence count and
  timestamps, plus a link to the console. Never evidence, summaries or raw events. Titles can name
  the subject involved.
- **When:** on each detection tick, at most once per rule per cooldown, as one batch of up to 20
  findings seen since the last successful delivery. Delivery is **at-least-once** — a failure is
  retried on the next tick — so de-duplicate on finding `id` + `lastSeenAt`. Redirects are not
  followed; HTTPS is required.
- **Verifying a webhook.** Each delivery carries
  `x-intelligence-signature: t=<unix seconds>,v1=<hex>`, where `v1` is HMAC-SHA256 of
  `"<t>.<raw body>"` under the rule's signing secret (shown once when the rule is created). Verify
  against the raw bytes before parsing, compare in constant time, and reject old timestamps:

  ```ts
  const [, t, v1] = /^t=(\d+),v1=([0-9a-f]{64})$/.exec(header) ?? []
  const want = createHmac("sha256", secret).update(`${t}.${rawBody}`).digest("hex")
  const ok = v1 !== undefined && timingSafeEqual(Buffer.from(v1), Buffer.from(want))
    && Math.abs(Date.now() / 1000 - Number(t)) < 300
  ```

## The optional judgment layer

Intelligence supports **TypeSafe AI (JEV), OpenAI and Anthropic**. AI reviews are optional,
advisory opinions: they do not create findings, change severity or status, suppress alerts, or
authorize actions. Existing automatic review paths use one primary provider; other providers run
only when explicitly requested. Operational and native-provider detectors remain deterministic.

1. Open **Judgment** (`/judgment`) and configure a provider, model ID and API key. OpenAI and
   Anthropic models must support structured JSON output. Settings and credential replacements
   require administrator passkey approval; keys are encrypted and never displayed again.
2. Select the primary reviewer and approve **Turn on**. Configuring a key alone does not enable
   reviews. Existing `TYPESAFE_*` / `JEV_*` deployment settings remain a fallback until that
   workspace configures or removes JEV in the UI.
3. On a finding, choose **Request an AI review or second opinion**, select a configured provider,
   inspect the exact outbound request, and approve. If the model or projected evidence changes
   during approval, open a fresh request. Path-only observations cannot be sent for anomaly review.
4. Compare the provider/model-labelled opinions on the finding. OpenAI and Anthropic reviews
   include supporting evidence, missing context and suggested human checks. JEV retains its score
   contract; no explanation is invented when it returns none. Estimates are not calibrated or
   averaged. Updated detector evidence clears outdated cards; historical requests remain in the audit.

Only the allowlisted projection in [`src/redaction/project.ts`](src/redaction/project.ts) leaves
for review: controlled descriptions, measurements, observation windows and known event kinds.
Free-text titles, summaries, arbitrary labels, repository paths, source IDs and previous opinions
are excluded. Subject identifiers may be represented by a salted digest. Requests go to each
provider's fixed API destination; the existing operator-owned JEV endpoint override is preserved.
Review the provider's data-handling settings before enabling it. OpenAI requests use `store: false`;
this does not by itself promise zero retention by the provider.

Each provider has a default **20 requests per UTC day**, a bounded timeout and an output-token
limit (OpenAI/Anthropic only). Failed attempts consume the daily allowance too. These are usage
limits, not dollar budgets; configure account spending controls with the provider. Identical
completed reviews are reused, recent failures have a five-minute retry cooldown, concurrent
requests are bounded, and there is no automatic cross-provider fallback. A process interrupted
during a request can leave an audit row marked SENDING; its concurrency reservation expires after
two minutes, without automatically repeating the request.

The audit records provider, requested and returned model, exact minimized payload, digest, outcome
and available token usage. Late responses remain audit-only if the finding changed while the call
was in flight. Provider failures do not remove deterministic findings or other providers' opinions.

The adapters follow [OpenAI structured outputs](https://developers.openai.com/api/docs/guides/structured-outputs?api-mode=responses)
and [Anthropic structured outputs](https://platform.claude.com/docs/en/build-with-claude/structured-outputs).
Local tests use synthetic responses; they do not establish live model access or review quality.

## Environment configuration

Set connection variables explicitly; an unconfigured instance refuses sign-in and protected changes.
Leave unused optional variables unset rather than assigning a placeholder string.

| Variable                             | Purpose                                                                                      | Requirement or default                             |
| ------------------------------------ | -------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| `NODE_ENV`                           | Runtime mode; use `production` for a deployed instance.                                      | `development`                                      |
| `PORT`                               | HTTP listener port.                                                                          | `4100`                                             |
| `PUBLIC_URL`                         | Exact browser origin, approval target and webhook-link base.                                 | Required                                           |
| `DATABASE_URL`                       | Intelligence PostgreSQL connection.                                                          | Required                                           |
| `DIRECT_URL`                         | Direct database connection for Prisma migrations.                                            | Required for migrations                            |
| `TICK_TOKEN`                         | Bearer token for `POST /internal/tick`.                                                      | Required in production                             |
| `SECRETS_ENC_KEY`                    | Encryption key for stored credentials and browser state; generate 32 random bytes as base64. | Required in production                             |
| `INTYGA_URL`                         | Gateway origin for sign-in and approval requests.                                            | Required                                           |
| `INTYGA_CONSOLE_URL`                 | INTYGA console origin for member linking and hosted approval mode.                           | Required                                           |
| `INTYGA_WORKSPACE_ID`                | Workspace named by tokens, receipts and the trust anchor.                                    | Required                                           |
| `INTYGA_SERVICE_CLIENT_ID`           | SERVICE API key client ID.                                                                   | Required                                           |
| `INTYGA_SERVICE_CLIENT_SECRET`       | SERVICE API key secret.                                                                      | Required                                           |
| `INTYGA_TRUST_ANCHOR_FILE`           | Read-only online application anchor; use a console anchor for hosted mode.                   | Required for sign-in/actions                       |
| `INTYGA_EMBEDDED_APPLICATION_ID`     | Member application UUID for in-page passkey ceremonies.                                      | Required for embedded mode                         |
| `INTYGA_EMBEDDED_REGISTRATION_FILE`  | Short-lived ownership proof JSON.                                                            | Required during application ownership verification |
| `INTYGA_OIDC_CLIENT_ID`              | Public App sign-in client; callback is `<origin>/auth/callback`.                             | Optional                                           |
| `INTYGA_INTERNAL_URL`                | Private HTTPS route to the same gateway; public issuer checks stay unchanged.                | Optional                                           |
| `INGEST_RATE_GLOBAL_PER_MIN`         | Aggregate ingest allowance.                                                                  | `1200`                                             |
| `INGEST_RATE_PER_CONNECTION_PER_MIN` | Per-connection ingest allowance.                                                             | `300`                                              |
| `TYPESAFE_API_KEY`                   | Optional judgment provider key; configure judgment explicitly before use.                    | Optional                                           |
| `TYPESAFE_MODEL`                     | Judgment model.                                                                              | `jev-latest`                                       |
| `TYPESAFE_ENDPOINT`                  | Judgment endpoint.                                                                           | `https://api.typesafe.ai/v1/systemone`             |
| `TYPESAFE_TIMEOUT_MS`                | Judgment request timeout.                                                                    | `10000`                                            |
| `GITHUB_TOKEN`                       | Read-only GitHub token for operator helpers; normally configure credentials per connector.   | Optional                                           |
| `GITHUB_API_BASE`                    | GitHub API base URL, including an Enterprise API path when applicable.                       | `https://api.github.com`                           |
| `INTYGA_TIMEOUT_MS`                  | INTYGA request timeout in milliseconds.                                                      | `10000`                                            |
| `LOG_LEVEL`                          | Pino log level.                                                                              | `info`                                             |

The `JEV_API_KEY`, `JEV_MODEL` and `JEV_ENDPOINT` names are the earlier spelling and are still read
for compatibility. Set one family, not both — the `TYPESAFE_*` name wins silently.

In production (`NODE_ENV` anything but `development` or `test`) a missing or still-placeholder
`TICK_TOKEN` or `SECRETS_ENC_KEY` **throws at startup** rather than running on a dev default. Missing
INTYGA configuration exposes only a status page and refuses sign-in and privileged actions.

---

## Verification

```bash
pnpm verify   # typecheck, lint, boundary check, unit tests (DB-backed tests need TEST_DATABASE_URL — see CONTRIBUTING)
```

To simulate an end-to-end event burst and watch findings appear:

```bash
pnpm exec tsx scripts/e2e-demo.ts <connectionId> <webhookSecret> http://localhost:4100
```

---

## Contributing and security

- [Release guide](docs/RELEASING.md) — versioning, CI, upgrade checks and publication for 1.0.0.
- [Changelog](CHANGELOG.md) — shipped behavior and upgrade notes.

- [CONTRIBUTING.md](CONTRIBUTING.md) — how to propose a change, and the two rules a pull request
  here has to clear.
- [SECURITY.md](SECURITY.md) — how to report a vulnerability. **Do not open a public issue.**

---

## License

[Apache License 2.0](LICENSE). Copyright 2026 Janbjer Technologies AB.

INTYGA is a trademark of Janbjer Technologies AB. The license covers the code; it does not grant
rights to the name or the logo.
