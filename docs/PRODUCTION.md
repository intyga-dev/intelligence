# Running INTYGA Intelligence 1.0 in production

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

| Decision                                                                      | Why it is sticky                                                                                                                                                                                                                                                   |
| :---------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **The hostname** Intelligence is served from, e.g. `intelligence.example.com` | It fixes the embedded application origin/RP ID and approval target. Moving hosts requires a new registration and app-scoped passkeys. Optional OIDC also requires its callback registration to change.                                                             |
| **`SECRETS_ENC_KEY`**                                                         | Encrypts every stored credential: connector tokens, webhook secrets, alert destinations and temporary browser state. The INTYGA service key stays in deployment secrets. Losing it means entering all of them again. Keep it in your secret manager with a backup. |
| **Single instance**                                                           | Run one app container and one scheduler. Rate limits and the tick overlap guard are in-process; replicas do not share them and can run concurrent ticks.                                                                                                           |

## 1. Prerequisites

- An **INTYGA workspace**, with an administrator who can use **Integrations → Member applications** and create API keys.
  Your INTYGA deployment must support member applications, SERVICE keys and application trust-anchor exports and application-specific approval routing (`POST /embedded/applications/:applicationId/authorize`). OIDC App sign-in is optional.
- A **Postgres** database for Intelligence alone, never INTYGA's database. The project is developed and
  tested against Postgres 16.
- A place to run one container (Fly.io, Cloud Run with `--max-instances=1`, a VM, Kubernetes with
  `replicas: 1`) behind **TLS**.
- A **scheduler** that can POST to a URL once a minute (Upstash QStash, a cron job, GitHub Actions
  as a last resort; its 5-minute floor is fine for the detectors, just slower).

**Done when:** you can reach an empty Postgres from where the container will run.

## 2. INTYGA side — register or reuse a Member application

Use an existing SERVICE identity and API key, or create them, and configure the workspace approval
rules for that service. Open **Integrations → Member applications** (`/embedded`) in the INTYGA
console. Reuse an active, verified registration if its origin and SERVICE client ID already match
this Intelligence deployment; otherwise register one with those exact values.

This guide uses Member applications for in-page passkeys. Customer applications (`/platform`) and
OIDC App sign-in (`/oidc-clients`) are separate features and do not provide this application ID. The RP ID is the origin hostname; it cannot overlap the console’s
passkey scope. Save the returned application ID and short-lived ownership proof.

Only active human workspace members can link application credentials. External platform subjects
cannot use this path. Template recognition is advisory and grants no authority.

**Done when:** the service and member application exist in the intended workspace.

## 3. Configure the environment

Copy [`.env.production.example`](../.env.production.example) into your secret store and fill it in.
Generate `TICK_TOKEN` and `SECRETS_ENC_KEY` separately with `openssl rand -base64 32`; obtain the
SERVICE credentials from INTYGA. The server **refuses to start** when `DATABASE_URL` is missing or
either local secret is missing, too short or a known placeholder in production.

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

### Avoid repeated image deployments during setup

Prepare DNS, TLS, the SERVICE credentials and the Member application ID before starting the app.
Generate the short-lived proof when the hostname is ready to serve it. Deploy the image with those
settings and the proof, verify ownership, then link the first application passkey and install the
exported application anchor. The anchor comes last because it includes that new passkey.

The app reads both files when needed. If your runtime mounts an operator-managed directory, updating
its proof or anchor file requires no app restart. If files are materialized only at container startup,
update the deployment configuration and restart using the **same image**. Environment changes also
require recreating or updating the container. Neither step requires rebuilding the application or
rerunning migrations. Keep trust-anchor installation under operator control; a browser setup flow
must not be able to replace the keys trusted to approve actions.

## 7. Schedule the tick

Detection, polling and alert delivery run on `POST /internal/tick`. An external scheduler keeps
requesting ticks after app restarts; outages can still delay collection or exceed detector windows:

```bash
curl -X POST https://<hostname>/internal/tick -H "Authorization: Bearer $TICK_TOKEN"
```

Schedule that **once a minute**. The endpoint allows 6 calls a minute and prevents overlapping
ticks within one app process. Monitor failed scheduler deliveries and avoid multiple schedulers.

**Done when:** the tick returns 200 with a `detectors` and `alerts` report, and it keeps doing so.

## 8. Connect sources and alerts

Everything here happens in the console, and every activation is a passkey-signed action:

- **Connectors:** add each source, copy its endpoint and secret into the source, then **Turn on**.
  For sources Intelligence has no connector for, see [CONNECTORS.md](CONNECTORS.md).
- **Detectors:** ten are available. CI, merge-policy, overdue-job and service-objective monitoring
  need explicit targets in **Operational settings** before they can find anything. Collection
  health applies to active polling sources. The code-change path map is per GitHub/GitLab connector;
  path-only matches appear as **Observations** and do not trigger alerts. See the [detector guide](../README.md#deterministic-detectors).
- **Alerts:** create a rule, point it at a webhook or a Slack incoming webhook, then **Turn on**. It
  starts from now and never replays history. Verify webhook signatures as described in the README.

**Done when:** a test event from one source appears under **Activity**, and an alert rule shows a
recent **Last delivered**.

After activation, inspect connector health and an expected event. An empty successful poll is healthy.
GitHub sources can be edited in place with a signed approval; existing tokens and collected history
are preserved. Native provider alerts require explicit recovery to resolve automatically.

## 9. Operate

Read [the 1.0 release and upgrade guide](RELEASING.md) before upgrading a pre-release installation.
Back up the database, deployment environment and trust file; older authentication migrations can
invalidate sessions and remove tables, so an image-only downgrade is not a general rollback.

| Task                                          | How                                                                                                                                                                                        |
| :-------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Upgrade**                                   | Build the new image, run step 4's migration, then replace the container.                                                                                                                   |
| **Backups**                                   | Postgres backups with point-in-time recovery. Intelligence holds derived observations, not a system of record, but it does hold connector configuration and history. Test a restore once.  |
| **Lost passkey**                              | Recover the INTYGA account, link a replacement application passkey, and refresh the mounted application trust anchor. Revocation/recovery invalidates embedded signing eligibility.        |
| **Rotate the SERVICE secret or trust anchor** | Update the deployment secret or mounted application anchor and restart. The anchor must name the connected workspace. INTYGA rechecks eligibility at redemption.                           |
| **Change workspace**                          | Replace deployment configuration and the mounted anchor, register the application in the new workspace, and restart. The binding fingerprint invalidates old sessions and pending actions. |
| **Watch**                                     | Alert on `/ready` failing, and on the tick scheduler's failures. Nothing else pages you if ticks stop: findings simply stop appearing.                                                     |

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
