# Running Intelligence in production

A step-by-step guide for self-hosting. Each step ends with **Done when**, a check you can run. Do
them in order: later steps assume earlier ones.

For the bundled Docker stack with automatic secret generation, migrations and scheduling, start with
[SELF_HOST.md](SELF_HOST.md). This guide covers independently managed infrastructure.

What you will run:

```
            your scheduler ──POST /internal/tick (1/min)──┐
                                                          ▼
 browser ──TLS──▶ reverse proxy ──▶ Intelligence (1 container) ──▶ your Postgres
 GitHub/Sentry/… webhooks ─────────────────────▲                 └──▶ INTYGA (sign-in and approvals)
```

One container, one Postgres database and one scheduler. Intelligence holds no INTYGA
credential beyond a SERVICE key that requests approvals, and INTYGA's availability does not
depend on it.

---

## 0. Decisions to make first — these are hard to change later

| Decision | Why it is sticky |
| :--- | :--- |
| **The hostname** Intelligence is served from, e.g. `intelligence.example.com` | It fixes the embedded application origin/RP ID and approval target. Moving hosts requires a new registration and app-scoped passkeys. Optional OIDC also requires its callback registration to change. |
| **`SECRETS_ENC_KEY`** | Encrypts every stored credential: connector tokens, webhook secrets, alert destinations and temporary browser state. The INTYGA service key stays in deployment secrets. Losing it means entering all of them again. Keep it in your secret manager with a backup. |
| **Single instance** | Rate limits and the tick guard are in-process. Run exactly one container. Two replicas would double the allowances; correctness holds, but the guards weaken. |

## 1. Prerequisites

- An **INTYGA workspace**, with an administrator who can use **Integrations → App sign-in** and create API keys.
  Your INTYGA deployment must support member applications, SERVICE keys and application trust-anchor exports. OIDC App sign-in is optional.
- A **Postgres** database for Intelligence alone, never INTYGA's database. The project is developed and
  tested against Postgres 16.
- A place to run one container (Fly.io, Cloud Run with `--max-instances=1`, a VM, Kubernetes with
  `replicas: 1`) behind **TLS**.
- A **scheduler** that can POST to a URL once a minute (Upstash QStash, a cron job, GitHub Actions
  as a last resort; its 5-minute floor is fine for the detectors, just slower).

**Done when:** you can reach an empty Postgres from where the container will run.

## 2. INTYGA side — register the embedded application

Create a SERVICE identity and API key, and configure its ordinary workspace approval rules.
Register Intelligence under **Integrations → Member applications** with its exact HTTPS origin
and that service client ID. The RP ID is the origin hostname; it cannot overlap the console’s
passkey scope. Save the returned application ID and short-lived ownership proof.

Only active human workspace members can link application credentials. External platform subjects
cannot use this path. Template recognition is advisory and grants no authority.

**Done when:** the service and member application exist in the intended workspace.

## 3. Configure the environment

Copy [`.env.production.example`](../.env.production.example) into your secret store and fill it in.
Generate each secret with `openssl rand -base64 32`. The server **refuses to start** when
`DATABASE_URL`, `TICK_TOKEN` or `SECRETS_ENC_KEY` is missing or a placeholder, so a bad config fails at
deploy instead of later.

Set `PUBLIC_URL`, `INTYGA_URL`, `INTYGA_CONSOLE_URL`, `INTYGA_WORKSPACE_ID`, the SERVICE client ID
and secret, and `INTYGA_EMBEDDED_APPLICATION_ID`. Mount `config/` read-only and set
`INTYGA_TRUST_ANCHOR_FILE` and `INTYGA_EMBEDDED_REGISTRATION_FILE` to the files inside it.
There is no browser setup token or database credential binding. `INTYGA_OIDC_CLIENT_ID` is optional.

**Done when:** every uncommented variable in the template has a value in your secret store.

## 4. Build and migrate

```bash
docker build -t intyga-intelligence .
docker run --rm -e DIRECT_URL="<direct connection string>" \
  --entrypoint node_modules/.bin/prisma intyga-intelligence migrate deploy
```

Migrations read `DIRECT_URL` and need a **direct** connection, not a transaction pooler. The migration
engine is baked into the image, so this needs no network beyond the database. Re-run it on every
upgrade before starting the new version.

**Done when:** `migrate deploy` reports all migrations applied.

## 5. Deploy

Run the image with your environment. It listens on `PORT` (4100) on both IPv4 and IPv6.

- Put it behind your TLS terminator. `trustProxy` is deliberately **off**, so request logs show the
  proxy's address, not the client's. That is the safe trade: a trusted hop count is spoofable by
  anyone who reaches the container directly.
- **Liveness:** `GET /health`. **Readiness:** `GET /ready`, which checks the database.
- The image needs **no outbound network to start**: no package download at boot.

**Done when:** `https://<hostname>/ready` returns `{"ok":true,…}`.

## 6. Prove ownership, link members and sign in

Serve the registration proof at `/.well-known/intyga-embedded` by mounting its file and setting
`INTYGA_EMBEDDED_REGISTRATION_FILE`. Choose **Verify ownership** in INTYGA before the proof
expires. A copied Intelligence template marker does not satisfy this proof.

Each member chooses **Link my INTYGA membership** from Intelligence, approves with their console
passkey, and creates a new passkey after returning to Intelligence. The one-use grant is bound to
the member, application, origin, version and initiating browser through PKCE.

Export the application's trust anchor from INTYGA Member applications and mount it as
`INTYGA_TRUST_ANCHOR_FILE`. Its workspace must match `INTYGA_WORKSPACE_ID`. Refresh it after
passkey additions or revocations. Neither the service credential nor this anchor is stored in the
Intelligence database.

**Done when:** an ADMIN signs in with an application passkey, **Settings → Test connection**
succeeds, and a protected change is approved in place and applied. MEMBERs can read Intelligence.

## 7. Schedule the tick

Detection, polling and alert delivery run on `POST /internal/tick`, driven from outside so a restart
never skips a window:

```bash
curl -X POST https://<hostname>/internal/tick -H "Authorization: Bearer $TICK_TOKEN"
```

Schedule that **once a minute**. The endpoint allows 6 calls a minute, so a duplicate delivery is
harmless and a stampede is refused.

**Done when:** the tick returns 200 with a `detectors` and `alerts` report, and it keeps doing so.

## 8. Connect sources and alerts

Everything here happens in the console, and every activation is a passkey-signed action:

- **Connectors:** add each source, copy its endpoint and secret into the source, then **Turn on**.
  For sources Intelligence has no connector for, see [CONNECTORS.md](CONNECTORS.md).
- **Detectors:** all three are on by default. The code-change detector's path map is set per GitHub or
  GitLab connector (`generic` unless you choose otherwise).
- **Alerts:** create a rule, point it at a webhook or a Slack incoming webhook, then **Turn on**. It
  starts from now and never replays history. Verify webhook signatures as described in the README.

**Done when:** a test event from one source appears under **Activity**, and an alert rule shows a
recent **Last delivered**.

## 9. Operate

| Task | How |
| :--- | :--- |
| **Upgrade** | Build the new image, run step 4's migration, then replace the container. |
| **Backups** | Postgres backups with point-in-time recovery. Intelligence holds derived observations, not a system of record, but it does hold connector configuration and history. Test a restore once. |
| **Lost passkey** | Recover the INTYGA account, link a replacement application passkey, and refresh the mounted application trust anchor. Revocation/recovery invalidates embedded signing eligibility. |
| **Rotate the SERVICE secret or trust anchor** | Update the deployment secret or mounted application anchor and restart. The anchor must name the connected workspace. INTYGA rechecks eligibility at redemption. |
| **Change workspace** | Replace deployment configuration and the mounted anchor, register the application in the new workspace, and restart. The binding fingerprint invalidates old sessions and pending actions. |
| **Watch** | Alert on `/ready` failing, and on the tick scheduler's failures. Nothing else pages you if ticks stop: findings simply stop appearing. |

## Security properties to know

- Intelligence **may ask INTYGA for approval and may never grant or bypass it** (`pnpm check:boundary`).
- **Embedded identity comes from the active workspace membership bound to the passkey that signed the browser’s login approval.** Optional OIDC verifies signed identity tokens with PKCE.
  Intelligence uses server-side sessions; role changes are refreshed at sign-in. Sessions expire after
  12 hours unless revoked locally, so upstream membership changes do not instantly revoke them.
- **Single-tenant per deployment, no row-level security.** Do not host two unrelated organisations on
  one instance (see the header of `prisma/schema.prisma`).
- **What leaves the host:** sign-in exchanges and approval descriptions, targets and parameters to
  INTYGA; alert payloads to destinations you activated;
  judgment requests only if you enabled that provider.

- Application credentials are separate from console credentials. A service cannot enroll an email
  address as somebody else, rewrite a human DID, or use an application credential for console login.
- Embedded approvals use the ordinary policy engine: quorum, requester exclusions, hardware rules,
  expiry and one-use redemption still apply. Unsupported hardware evidence fails closed.
- An administrator can pin arbitrary public keys in an anchor. A bad anchor can make actions fail;
  it cannot skip INTYGA's approval and redemption checks.
