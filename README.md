# INTYGA Intelligence

**Operational attention compression for modern engineering systems.**

Observe → Classify → Correlate → Surface. INTYGA Intelligence turns high-volume telemetry, Git
commits, CI/CD deployments and authorization events into a **short, prioritised list of
evidence-backed findings** that genuinely need human attention.

> **MFA verifies who you are. INTYGA verifies what you are doing. Intelligence shows what matters.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

---

## Read this first

**Intelligence is not standalone. It requires an INTYGA workspace and will not run without one.**

It has no authentication of its own. Administrators are INTYGA platform subjects who enrol a passkey
on Intelligence's origin, and every privileged change — turning on a connector, enabling the
judgment provider, purging data — is a hash-only signing ceremony against that passkey, executed
through INTYGA. There is no local admin account, no password fallback and no environment variable
that turns the gate off. Without an INTYGA workspace this repository will let you read the code and
run the tests, and nothing else.

**Status: `0.1.0`, early.** One deterministic detector ships today (see
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

---

## Supported connectors

Every data source maps into a single canonical [`NormalizedEvent`](src/connectors/types.ts).
Detectors never observe raw vendor APIs.

| Connector | Ingest mode | Signals contributed |
| :--- | :--- | :--- |
| **INTYGA** | `push` (webhook) | Authorization approvals, refusals, expiries and approval latency. |
| **GitHub** | `poll` (API) | Pull requests with changed file paths, CI workflow outcomes, deploy runs. |
| **Metrics** | `poll` (Prometheus) | Auth failures, rate limits, signature rejections, ledger health. |
| **Sentry** | `push` (webhook) | Post-release exception spikes and regression indicators. |
| **Vercel** | `push` (webhook) | Production and preview deployment lifecycles mapped to commit SHAs. |
| **Fly.io** | `poll` (API) | Machine state changes, restarts and OOM kills. |

---

## Deterministic detectors

One detector ships in `0.1.0`:

* **`denialBurst`** — detects statistically significant spikes in authorization refusals against an
  actor's historical baseline, and flags action types never before seen from that subject.
  ([source](src/domain/detectors/denialBurst.ts) ·
  [tests](src/domain/detectors/denialBurst.test.ts))

Severity is assigned deterministically by [`src/domain/sensitivity.ts`](src/domain/sensitivity.ts)
before any model is consulted.

**Not yet implemented.** Two further detectors are designed, and the ingestion they need is already
in place, but there is no code for them. They are listed here as intent, not as features:

* `mirrorIncomplete` — partial updates to canonical multi-port interfaces across pull requests.
* `postDeployRegression` — correlating deploy timestamps with a rise in exceptions or refusals.

Adding a detector touches `src/domain/detectors/` and one line of `src/jobs/tick.ts`. Failures are
isolated per detector, so a new one cannot take the working ones down with it.

---

## Quickstart

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

### 5. Start the application

```bash
pnpm dev
```

Open **`http://localhost:4100`**.

### 6. Enrol your passkey and sign in

1. Go to `http://localhost:4100/settings` and click **Test connection**.
2. Visit `http://localhost:4100/members/enrol?id=admin` to register your hardware passkey.
3. Sign in at `http://localhost:4100/login`.

---

## Adding connectors

1. Navigate to **Connectors** (`http://localhost:4100/connectors`).
2. Under **Add a connector**, select an integration.
3. Enter a label (e.g. `INTYGA Staging`, `GitHub Production`).
4. Copy the unique **webhook ingestion URL** and one-time **signing secret** into your provider.
5. Click **Turn on** — this requires an administrator passkey tap, because it starts a data flow.

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
| `DATABASE_URL` | PostgreSQL connection string. | Required |
| `DIRECT_URL` | Direct connection string for Prisma migrations (bypasses any pooler). | Required |
| `TICK_TOKEN` | Bearer token protecting `POST /internal/tick`. | Required in production |
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
`TICK_TOKEN` or `SECRETS_ENC_KEY` **throws at startup** rather than running on a dev default.

---

## Verification

```bash
pnpm verify   # typecheck, lint, boundary check, unit tests
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
