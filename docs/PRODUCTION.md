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
| **The hostname** Intelligence is served from, e.g. `intelligence.example.com` | It sets the OIDC callback URI and approval execution target. Moving hosts requires updating the registered callback and instance origin; passkeys stay at INTYGA. |
| **`SECRETS_ENC_KEY`** | Encrypts every stored credential: connector tokens, webhook secrets, alert destinations and the INTYGA key. Losing it means entering all of them again. Keep it in your secret manager with a backup. |
| **Single instance** | Rate limits and the tick guard are in-process. Run exactly one container. Two replicas would double the allowances; correctness holds, but the guards weaken. |

## 1. Prerequisites

- An **INTYGA workspace**, with an administrator who can use **Integrations → App sign-in** and create API keys.
  Your INTYGA deployment must support App sign-in, SERVICE keys and online trust-anchor exports.
- A **Postgres** database for Intelligence alone, never INTYGA's database. The project is developed and
  tested against Postgres 16.
- A place to run one container (Fly.io, Cloud Run with `--max-instances=1`, a VM, Kubernetes with
  `replicas: 1`) behind **TLS**.
- A **scheduler** that can POST to a URL once a minute (Upstash QStash, a cron job, GitHub Actions
  as a last resort; its 5-minute floor is fine for the detectors, just slower).

**Done when:** you can reach an empty Postgres from where the container will run.

## 2. INTYGA side — register sign-in and approval credentials

1. In **Integrations → App sign-in**, register the exact redirect URI
   `https://<hostname>/auth/callback`. Save the public OIDC client ID; there is no OIDC client secret.
2. In **API Keys → Create a service and its key**, create a SERVICE identity and save its client ID
   and secret in your secret manager. This key requests approvals under the workspace's rules.
3. Configure the service's approval rules and approvers, then export the online trust anchor from
   **Approval Rules**. It pins the approvers' public keys and INTYGA console's WebAuthn origin/RP ID.
4. Copy the workspace ID from **Settings**, plus the gateway and console URLs.

**Done when:** you have the OIDC client ID, SERVICE client ID and secret, and an online trust anchor
whose `tenantId` matches the workspace. No signing key or passkey is created on Intelligence's domain.

## 3. Configure the environment

Copy [`.env.production.example`](../.env.production.example) into your secret store and fill it in.
Generate each secret with `openssl rand -base64 32`. The server **refuses to start** when
`DATABASE_URL`, `TICK_TOKEN` or `SECRETS_ENC_KEY` is missing or a placeholder, so a bad config fails at
deploy instead of later.

Set `SETUP_TOKEN` only if you will finish setup in the browser (step 6a). Remove it afterwards.
Set `PUBLIC_URL` to the external HTTPS origin so webhook links use the right address behind TLS.
For a private INTYGA console, also set `INTYGA_CONSOLE_URL`.

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

## 6. Connect the workspace and sign in

**6a. In the browser.** With `SETUP_TOKEN` set, open `https://<hostname>/` and enter the setup token,
the credentials from step 2, and this instance's origin. Sign in through INTYGA with an existing
workspace administrator's passkey. Then remove `SETUP_TOKEN` and redeploy.

**6b. From the CLI**, with no browser setup:

```bash
docker exec <container> node_modules/.bin/tsx scripts/provision-tenant.ts default
docker exec <container> node_modules/.bin/tsx scripts/bind-workspace.ts \
  --base-url https://api.intyga.com --console-url https://app.intyga.com \
  --workspace-id <workspace-id> --oidc-client-id <oidc-id> \
  --service-client-id <service-id> --service-secret-file /run/secrets/service.secret \
  --trust-anchor /run/secrets/trust-anchor.json --origin https://<hostname>
```

Mount those files in the container. The script stores the service secret encrypted and the public
trust anchor in the database. Sign in at `https://<hostname>/login` through INTYGA.

**Done when:** an INTYGA workspace ADMIN can sign in, **Settings → Test connection** succeeds, and
one approved change completes. Manage additional administrators and passkeys in INTYGA; keep a
second administrator or recovery credential available there. MEMBERs can read Intelligence.

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
| **Lost passkey** | Use INTYGA's account/passkey recovery and workspace administration. Intelligence has no separate passkey enrolment or invite mechanism. |
| **Rotate the SERVICE secret or trust anchor** | Settings → Credentials, as a signed-in ADMIN. The replacement anchor must name the connected workspace. INTYGA still checks every approval at redemption. |
| **Change workspace** | Use the approved workspace-rebind action, or the operator CLI with database access. Sign in to the new workspace and install its matching credentials and anchor. |
| **Watch** | Alert on `/ready` failing, and on the tick scheduler's failures. Nothing else pages you if ticks stop: findings simply stop appearing. |

## Security properties to know

- Intelligence **may ask INTYGA for approval and may never grant or bypass it** (`pnpm check:boundary`).
- **Identity comes from INTYGA OIDC with PKCE.** Signed tokens bind the person, workspace and role.
  Intelligence uses server-side sessions; role changes are refreshed at sign-in. Sessions expire after
  12 hours unless revoked locally, so upstream membership changes do not instantly revoke them.
- **Single-tenant per deployment, no row-level security.** Do not host two unrelated organisations on
  one instance (see the header of `prisma/schema.prisma`).
- **What leaves the host:** sign-in exchanges and approval descriptions, targets and parameters to
  INTYGA; alert payloads to destinations you activated;
  judgment requests only if you enabled that provider.
