# Running Intelligence in production

A step-by-step guide for self-hosting. Each step ends with **Done when**, a check you can run. Do
them in order: later steps assume earlier ones.

What you will run:

```
            your scheduler ──POST /internal/tick (1/min)──┐
                                                          ▼
 browser ──TLS──▶ reverse proxy ──▶ Intelligence (1 container) ──▶ your Postgres
 GitHub/Sentry/… webhooks ─────────────────────▲                 └──▶ INTYGA (approvals only)
```

One container, one Postgres database and one scheduler. Intelligence holds no INTYGA
credential beyond a platform key scoped to its own users, and INTYGA's availability does not
depend on it.

---

## 0. Decisions to make first — these are hard to change later

| Decision | Why it is sticky |
| :--- | :--- |
| **The hostname** Intelligence is served from, e.g. `intelligence.example.com` | It is the WebAuthn RP ID. Every administrator's passkey is bound to it; moving hosts means everyone re-enrols. |
| **`SECRETS_ENC_KEY`** | Encrypts every stored credential: connector tokens, webhook secrets, alert destinations and the INTYGA key. Losing it means entering all of them again. Keep it in your secret manager with a backup. |
| **Single instance** | Rate limits and the tick guard are in-process. Run exactly one container. Two replicas would double the allowances; correctness holds, but the guards weaken. |

## 1. Prerequisites

- An **INTYGA workspace**, with an administrator who can use the console's `/platform` page and create API keys.
- A **Postgres** database for Intelligence alone, never INTYGA's database. The project is developed and
  tested against Postgres 16.
- A place to run one container (Fly.io, Cloud Run with `--max-instances=1`, a VM, Kubernetes with
  `replicas: 1`) behind **TLS**.
- A **scheduler** that can POST to a URL once a minute (Upstash QStash, a cron job, GitHub Actions
  as a last resort; its 5-minute floor is fine for the detectors, just slower).

**Done when:** you can reach an empty Postgres from where the container will run.

## 2. INTYGA side — register Intelligence as a platform Relying Party

In the INTYGA console:

1. **`/platform` → register a Relying Party.** RP ID = your hostname (bare host, no scheme). Origin = `https://<hostname>`.
   Register it **live**: test mode only admits loopback origins. It counts toward your plan's live-RP
   allowance until the dedicated integration RP type ships.
2. **Create a platform API key** with exactly these scopes: `subjects:write`, `credentials:write`,
   `receipts:create`, `receipts:read`. It authenticates with `private_key_jwt`. Generate the key pair
   locally, ES256 (P-256):
   ```bash
   openssl ecparam -name prime256v1 -genkey -noout -out ec.key
   openssl pkcs8 -topk8 -nocrypt -in ec.key -out rp.pk8
   openssl ec -in ec.key -pubout -out rp.pub.pem     # upload this public key when creating the key
   ```
   Keep `rp.pk8` secret; only the public key goes to INTYGA.

**Done when:** you have the client ID, `rp.pk8`, and the RP shows as live in `/platform`.

## 3. Configure the environment

Copy [`.env.production.example`](../.env.production.example) into your secret store and fill it in.
Generate each secret with `openssl rand -base64 32`. The server **refuses to start** when
`DATABASE_URL`, `TICK_TOKEN` or `SECRETS_ENC_KEY` is missing or a placeholder, so a bad config fails at
deploy instead of later.

Set `SETUP_TOKEN` only if you will finish setup in the browser (step 6a). Remove it afterwards.

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

## 6. Bind the workspace and enrol the first administrator

Choose one:

**6a. In the browser.** With `SETUP_TOKEN` set, open `https://<hostname>/`, enter the setup token,
the INTYGA details from step 2 and the first administrator. You are taken straight to passkey
enrolment. Then **remove `SETUP_TOKEN`** and redeploy.

**6b. From the CLI**, with no browser setup at all:
```bash
docker exec <container> node_modules/.bin/tsx scripts/provision-tenant.ts default <admin-subject-id>
docker exec <container> node_modules/.bin/tsx scripts/bind-workspace.ts \
  --base-url https://api.intyga.com --client-id <id> \
  --rp-id <hostname> --origin https://<hostname> --key /run/secrets/rp.pk8
```
`--key` is read inside the container, so mount `rp.pk8` there (as a secret file, e.g. at
`/run/secrets/rp.pk8`); it is stored encrypted in the database after this and the file can go.
`bind-workspace` prints a **one-time enrolment link** per administrator. Treat it like a password;
it expires in 72 hours. The first person to open it becomes that administrator.

Then sign in at `https://<hostname>/login` and press **Settings → Test connection**.

**Done when:** you are signed in and Test connection succeeds. Before relying on Intelligence, add
a second administrator (**Members → Add**) on a separate device, so one lost device cannot lock
everyone out.

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
| **Lost passkey, one admin left** | An administrator issues a new link: **Members → Enrolment link**. |
| **Lost passkey, no admins left** | `docker exec … tsx scripts/invite-member.ts <subject-id>` (requires database access, by design). |
| **Rotate the INTYGA key** | Settings → replace the key (not a signed action: it must work when the old key no longer does). |
| **Watch** | Alert on `/ready` failing, and on the tick scheduler's failures. Nothing else pages you if ticks stop: findings simply stop appearing. |

## Security properties to know

- Intelligence **may ask INTYGA for approval and may never grant or bypass it** (`pnpm check:boundary`).
- **Administrators are passkeys only.** Enrolment needs an admin-issued one-time link; subject IDs are not secrets.
- **Single-tenant per deployment, no row-level security.** Do not host two unrelated organisations on
  one instance (see the header of `prisma/schema.prisma`).
- **What leaves the host:** approval digests to INTYGA; alert payloads to destinations you activated;
  judgment requests only if you enabled that provider.
