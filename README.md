# INTYGA Intelligence

**Operational attention compression for modern engineering systems.**

Observe → Classify → Correlate → Surface. INTYGA Intelligence turns high-volume telemetry, Git
commits, CI/CD deployments and authorization events into a **short, prioritised list of
evidence-backed findings** that genuinely need human attention.

> **MFA verifies who you are. INTYGA verifies what you are doing. Intelligence shows what matters.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

---

## Read this first

**Free to self-host. INTYGA sign-in is required.** Intelligence is a first-party integration, outside
the Embedded plan gate, including on your own public domain. Start with the
[self-hosting walkthrough](docs/SELF_HOST.md) for Docker, local secret generation and guided setup.

It has no authentication of its own. Administrators are INTYGA platform subjects who enrol a passkey
on Intelligence's origin, and every privileged change — turning on a connector, enabling the
judgment provider, purging data — is a hash-only signing ceremony against that passkey, executed
through INTYGA. There is no local admin account, no password fallback and no environment variable
that turns the gate off. Before connecting a workspace you can explore the static example incident
at `/demo`. Your own observations stay behind INTYGA authentication.

Group deployment, error and incident sources into **Services** to investigate their findings and
recent observations together. Deploy regressions use only signals from the same service.

**Status: `0.1.0`, early.** Four deterministic detectors ship today (see
[Detectors](#deterministic-detectors)); the connectors are working integrations but should be read
as reference implementations rather than a supported product surface. There is no support SLA.
Issues and pull requests are welcome and will be read; nothing here is promised on a timeline.

---

## Why Intelligence?

Modern engineering teams suffer from **alert fatigue**:

* A deploy goes out on Vercel without passing standard CI.
* An authorization denial spike occurs across an API gateway.
* An error rate in Sentry creeps up ten minutes later.
* Prometheus fires disconnected alerts across three different channels.

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
        Findings --> Approval[WebAuthn Passkey Signing]
    end

    Sources --> Ingest
```

---

## Core guarantees

* **Attention compression, not summarisation.** Not *"summarise everything that happened in
  Slack"*, but *"here are the two things that deviated from baseline today, and why"*.
* **Deterministic evidence first.** A model cannot invent a finding. The type system enforces that
  hard evidence — a baseline refusal ratio, a commit SHA, a changed file path — leads:
  ```typescript
  type EvidenceList = readonly [DeterministicEvidence, ...Evidence[]]
  ```
  Model judgment is optional, off by default, and can only calibrate severity or filter expected
  behaviour. It can never be the reason a finding exists.
* **Passkey native (WebAuthn).** No passwords, no session tokens in `localStorage`, no external
  OAuth. Administrators sign in and authorise changes with Touch ID, Windows Hello or a hardware
  key.
* **Approvals are hash-only.** INTYGA receives the SHA-256 digest of an intent and never the intent
  itself. Your findings, code references and raw payloads do not leave your infrastructure in order
  to get a change approved.

---

## The security invariant

> **Intelligence may ask INTYGA for permission. It may never hold the power to grant it, bypass it,
> or read across it.**

* **Observation degrades open.** If Intelligence is offline, INTYGA authorization is completely
  unaffected. Nothing in the approval path depends on this service.
* **Privileged actions fail closed.** If INTYGA is unreachable, no privileged administrative action
  in Intelligence can execute. Unset RP configuration means *refused*, never *allowed*.
* The credential Intelligence holds is a **platform-scoped** key (`subjects:write`,
  `credentials:write`, `receipts:create`, `receipts:read`) authenticating by `private_key_jwt`. It
  acts only on Intelligence's own subjects. It cannot approve, bypass or read anything in INTYGA's
  own plane.
* [`scripts/check-no-intyga-client.mjs`](scripts/check-no-intyga-client.mjs) enforces the shape of
  that boundary in CI: no operator or service credentials in this process's environment, no direct
  database access to INTYGA, no admin, policy, sweep or internal endpoints. It is a text scan and
  says so in its own comments — the design is the control, the script is the ratchet that makes
  breaking it deliberate.

### First-time setup and enrolment

These are the two moments when nobody can be asked for a passkey yet, so they are gated by
something else:

* **Binding a workspace** from the browser requires `SETUP_TOKEN` from the server's environment.
  Until an instance is bound, the setup form is the only route it serves. With `SETUP_TOKEN` unset in
  production, browser setup is off and `scripts/bind-workspace.ts` is the only way in.
* **Enrolling a passkey** requires a **one-time invite link** — never just a subject id, which is
  not a secret. Invites come from first-time setup, from an administrator's signed *Enrolment link*
  action on `/members`, or from `scripts/invite-member.ts` for whoever holds the database
  credential. They are 256-bit, single use, expire after 72 hours, are stored only as a SHA-256, and
  travel in the URL fragment (`/members/enrol#invite=…`), so they never reach a server or proxy log.
  Treat one like a password: whoever opens it first can add a passkey to that administrator.

---

## Supported connectors

Every data source maps into a single canonical [`NormalizedEvent`](src/connectors/types.ts).
Detectors never observe raw vendor APIs.

| Connector | Ingest mode | Signals contributed |
| :--- | :--- | :--- |
| **INTYGA** | `push` (webhook) | Authorization approvals, refusals, expiries and approval latency. |
| **GitHub** | `poll` (API) | Pull requests with changed file paths, CI workflow outcomes, deploy runs. |
| **Metrics** | `poll` (Prometheus) | Samples of PromQL queries. Known INTYGA failure counters and ledger-integrity gauges feed `metrics-health`. |
| **Custom webhook** | `push` (signed JSON) | Anything you send it. `deployment`, `error` and `crash` events feed deploy-regression. |
| **Sentry** | `push` (webhook) | Post-release exception spikes and regression indicators. |
| **Vercel** | `push` (webhook) | Production and preview deployment lifecycles mapped to commit SHAs. |
| **Fly.io** | `poll` (API) | Machine state changes, restarts and OOM kills. |
| **GitLab** | `poll` (API, gitlab.com or self-managed) | Merge requests with changed paths, and deployments per environment. |
| **PagerDuty** | `push` (webhook v3, signed) | Incidents triggered, acknowledged and resolved. |
| **Opsgenie** | `push` (webhook, shared-secret header) | Alerts created and closed. Opsgenie itself shuts down on 5 April 2027. |
| **Datadog** | `push` (webhook, shared-secret header) | Monitor alerts triggering and recovering. |
| **Cloudflare Pages** | `poll` (API) | Finished Pages deployments mapped to commit SHAs. |
| **Netlify** | `push` (deploy notifications, signed JWS) | Deploys that went live or failed, mapped to commit SHAs. |

**Your own sources:** send signed JSON to the custom webhook with no code, or write a connector in one
file. [docs/CONNECTORS.md](docs/CONNECTORS.md) covers both, with signing examples for bash, Node and
Python, a GitHub Actions snippet, and the rules a connector has to follow.

---

## Deterministic detectors

Four detectors ship. Each is a pure function over stored events, runs on every detection tick, and
can be switched off on `/detectors`. Switching one off is a passkey-signed action. The severity and
the reason a finding exists are always computed; the optional model can only adjust them afterwards.

* **`denial-burst`** — a subject refused far more than it usually is, judged against its own
  history, plus any action type it has never attempted before. *Needs:* the INTYGA connector.
  ([source](src/domain/detectors/denialBurst.ts))
* **`sensitive-code-change`** — a pull request touching security-sensitive code. Each GitHub
  connector picks a **path map**:
  * `generic` (the default) matches conventional names in any repository: auth, sessions,
    permissions, crypto, secrets, migrations, infrastructure, CI. It is a heuristic and says so.
  * `intyga-core` is a measured map for the INTYGA monorepo. It adds a **mirror rule**: code that
    must change together across six language ports is flagged when a PR updates only some of them.
    That rule is never applied to a truncated file list.

  Drafts and noise (lockfiles, docs, tests) are skipped. Each PR has one finding, updated on each
  push. Works the same on GitLab merge requests. *Needs:* the GitHub or GitLab connector. ([source](src/domain/detectors/sensitiveChange.ts))
* **`deploy-regression`** — errors (Sentry), machine crashes (Fly), incidents (PagerDuty,
  Opsgenie, Datadog; one is enough) or the approval refusal rate (INTYGA) rising in the 30 minutes
  after a successful production deploy (GitHub, GitLab, Vercel, Netlify, Cloudflare Pages, or a
  custom event), compared with the 24 hours before. When the deployed commit matches a PR it has seen (head or merge commit), the
  finding names the PR, and severity rises one step if that PR touched sensitive code.
  This is timing, not proof of cause, and each finding says so.
  *Needs:* a deploy source, plus at least one signal source.
  ([source](src/domain/detectors/deployRegression.ts))

Noise guards are part of each detector, not tuning left to you:
* **Floors.** A minimum count before anything fires.
* **Own baselines.** Each subject or service is judged against its own normal level.
* **History.** A newly connected source does not make the next deploy look like a regression.
* **Volume.** A refusal *rate* needs enough approvals to mean something.

* **`metrics-health`** — detects increases in the default INTYGA audit-write, replay-guard,
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

Adding a detector: a pure function in `src/domain/detectors/`, an entry in
`src/domain/detectors/index.ts`, and a call in `src/jobs/tick.ts`. Failures are isolated per
detector, so a new one cannot take the working ones down with it.

---

## Quickstart

*Local evaluation. For the bundled Docker stack, follow [docs/SELF_HOST.md](docs/SELF_HOST.md).
For independently managed infrastructure, use [docs/PRODUCTION.md](docs/PRODUCTION.md)
and [`.env.production.example`](.env.production.example).*

### Prerequisites

* **Node.js** `v24+` and **pnpm** `v10+`
* **Docker & Docker Compose** (for PostgreSQL)
* **An INTYGA workspace** with a platform-scoped client ID and private key — see
  [Read this first](#read-this-first). INTYGA Cloud (`app.intyga.com`) is not generally available
  yet; during preview, bind against a staging or self-hosted gateway.

### 1. Clone and configure

```bash
git clone https://github.com/intyga-dev/intyga-intelligence.git
cd intyga-intelligence
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

### 3. Provision tenant and administrator

```bash
pnpm exec tsx scripts/provision-tenant.ts default admin
```

*(Alternatively skip steps 3–4 and complete setup in the browser at step 5: it asks for
`SETUP_TOKEN` from your `.env`, then takes you straight to enrolling your passkey.)*

### 4. Bind your INTYGA workspace

Intelligence uses INTYGA as its Relying Party identity and signing plane. Bind your tenant with your
client ID and private key (`rp.pk8`):

```bash
pnpm exec tsx scripts/bind-workspace.ts \
  --base-url https://api.staging.intyga.com \
  --client-id <YOUR_CLIENT_ID> \
  --rp-id localhost \
  --origin http://localhost:4100 \
  --key ./rp.pk8
```

*(For a local gateway, use `--base-url http://localhost:8787`.)*

It prints a **one-time enrolment link** for each administrator who has not enrolled yet. Keep it for
step 6, and treat it like a password.

### 5. Start the application

```bash
pnpm dev
```

Open **`http://localhost:4100`**.

### 6. Enrol your passkey and sign in

1. Open the enrolment link from step 4 and register your passkey. Lost it, or it expired?
   `pnpm exec tsx scripts/invite-member.ts admin` issues a new one.
2. Sign in at `http://localhost:4100/login`.
3. Go to **Settings** and click **Test connection**.

Further administrators are added on **Members**, which is a signed action and hands you their
enrolment link once.

---

## Adding connectors

1. Navigate to **Connectors** (`http://localhost:4100/connectors`).
2. Under **Add a connector**, select an integration.
3. Enter a label (e.g. `INTYGA Staging`, `GitHub Production`).
4. Copy the unique **webhook ingestion URL** and one-time **signing secret** into your provider.
5. Click **Turn on** — this requires an administrator passkey tap, because it starts a data flow.

The connector page distinguishes setup pending, awaiting a first poll or delivery, successful
polling, overdue polling (no poll for 15 minutes), and ingestion errors. Poll failures retain a safe
summary and the time of the last successful poll. A successful empty poll is normal; webhook
silence is not treated as an outage. Setup instructions remain available after activation.

## Investigating findings

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

`POST /ingest/:kind/:connectionId` is the only inbound data path. Deliveries are verified by HMAC
over the raw bytes, stored idempotently under the provider's own event id, then normalized. It
authenticates per request by signature and never by a session.

The endpoint is internet-facing by definition, so it spends two token buckets before doing any work
— one global, one per connection — bounding the CPU and the rows an unauthenticated caller can cost.
They are a **cost guard, not an authentication control**; the HMAC is what decides whether a delivery
is real. See [`src/server/ratelimit.ts`](src/server/ratelimit.ts) for what they do and do not bound,
including why they are deliberately not keyed on the client address.

### Detection tick

`POST /internal/tick` polls the poll-mode connectors and runs the detectors. Driven externally
rather than by an in-process timer, so a restart does not skip a window and a second replica does
not double-run. Protected by a bearer token (`TICK_TOKEN`), compared in constant time:

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

* **Channels:** a signed JSON **webhook**, or a **Slack incoming webhook**. Email is not available:
  Intelligence has no mail sender.
* **Created switched off.** Turning a rule on is a passkey-signed action that shows the approver
  the destination host, and the host is part of what is signed. That is the moment finding data
  starts leaving the host.
* **What is sent:** each finding's id, title, severity, category, status, occurrence count and
  timestamps, plus a link to the console. Never evidence, summaries or raw events. Titles can name
  the subject involved.
* **When:** on each detection tick, at most once per rule per cooldown, as one batch of up to 20
  findings seen since the last successful delivery. Delivery is **at-least-once** — a failure is
  retried on the next tick — so de-duplicate on finding `id` + `lastSeenAt`. Redirects are not
  followed; HTTPS is required.
* **Verifying a webhook.** Each delivery carries
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

Intelligence can send a **projected, identifier-free view** of a finding to a third-party model to
calibrate severity or mark a finding as expected behaviour. This is **off unless you configure it**,
and turning it on requires an administrator passkey signature.

* With no API key set, the **null provider** runs: no request is ever made and nothing leaves the
  host. Every deterministic detector still produces findings.
* The provider is **TypeSafe AI (JEV)**, a third-party processor outside INTYGA's infrastructure.
  Enabling it is a data-protection decision — sign the DPA and request zero data retention first.
* What crosses is an **allowlist, not a redaction pass**: only the fields
  [`src/redaction/project.ts`](src/redaction/project.ts) names are sent. Subject identifiers and
  source event ids become salted digests, so the model can reason about "the same subject,
  repeatedly" without being told who that is. Adding a field there is a data-protection decision,
  not a refactor.
* `/judgment` in the console shows the exact request body that would be sent, before you enable
  anything.

---

## Environment configuration

| Variable | Description | Default |
| :--- | :--- | :--- |
| `PORT` | HTTP port the console and ingest API bind to. | `4100` |
| `PUBLIC_URL` | External HTTPS origin used for setup defaults and webhook links behind a reverse proxy. | Request origin |
| `INTYGA_CONSOLE_URL` | INTYGA console for signup and free Intelligence registration. | `https://app.intyga.com` |
| `DATABASE_URL` | PostgreSQL connection string. | Required |
| `DIRECT_URL` | Direct connection string for Prisma migrations (bypasses any pooler). | Required |
| `TICK_TOKEN` | Bearer token protecting `POST /internal/tick`. | Required in production |
| `SETUP_TOKEN` | Required to complete first-time setup in the browser. Unset in production ⇒ browser setup disabled; use `scripts/bind-workspace.ts`. | Dev placeholder |
| `SECRETS_ENC_KEY` | 32-byte base64 key encrypting connection credentials at rest. | Required in production |
| `INTYGA_RP_URL` | INTYGA gateway base URL. Unset means privileged actions are refused. | None |
| `INTYGA_RP_CLIENT_ID` | Platform-scoped client ID. | None |
| `INTYGA_RP_PRIVATE_KEY` | PKCS#8 PEM for `private_key_jwt`. `\n`-escaped newlines accepted. | None |
| `INTYGA_RP_ID` | WebAuthn RP ID — the domain Intelligence is served from. | None |
| `INTYGA_RP_ORIGIN` | Exact origin Intelligence is served from. | None |
| `INGEST_RATE_GLOBAL_PER_MIN` | Aggregate ingest allowance across all connectors. | `1200` |
| `INGEST_RATE_PER_CONNECTION_PER_MIN` | Per-connection ingest allowance. | `300` |
| `TYPESAFE_API_KEY` | *(Optional)* Judgment provider key. Unset ⇒ null provider. | None |
| `TYPESAFE_MODEL` | Judgment model. | `jev-latest` |
| `TYPESAFE_ENDPOINT` | Judgment endpoint. | `https://api.typesafe.ai/v1/systemone` |
| `TYPESAFE_TIMEOUT_MS` | Judgment request timeout. | `10000` |
| `GITHUB_TOKEN` | *(Optional)* Read-only fine-grained PAT for repository polling. | None |
| `LOG_LEVEL` | Pino log level. | `info` |

The `JEV_API_KEY`, `JEV_MODEL` and `JEV_ENDPOINT` names are the earlier spelling and are still read
for compatibility. Set one family, not both — the `TYPESAFE_*` name wins silently.

In production (`NODE_ENV` anything but `development` or `test`) a missing or still-placeholder
`TICK_TOKEN` or `SECRETS_ENC_KEY` **throws at startup** rather than running on a dev default. A
placeholder `SETUP_TOKEN` is refused when setup is attempted.

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

* [CONTRIBUTING.md](CONTRIBUTING.md) — how to propose a change, and the two rules a pull request
  here has to clear.
* [SECURITY.md](SECURITY.md) — how to report a vulnerability. **Do not open a public issue.**

---

## License

[Apache License 2.0](LICENSE). Copyright 2026 Janbjer Technologies AB.

INTYGA is a trademark of Janbjer Technologies AB. The license covers the code; it does not grant
rights to the name or the logo.
