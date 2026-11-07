# Self-host Intelligence

Intelligence is free to run on your infrastructure. It requires an INTYGA workspace for sign-in and
approval. Members link an application passkey once, then sign in and approve inside Intelligence.
Your INTYGA deployment must support **Integrations → Member applications**, SERVICE API keys and
application trust-anchor exports. OIDC App sign-in is optional. Upgrade INTYGA if these controls are missing.

The app correlates observations from existing sources. It does not run uptime probes or provide
on-call escalation schedules. Keep those monitors running and send their incident events here.
No AI subscription or model key is needed for deterministic findings.

## Install

You need Node 24+ for the setup script, Docker with Compose, and an HTTPS origin for public access.
Local trials can use `http://localhost:4100`.

```sh
git clone https://github.com/intyga-dev/intyga-intelligence.git
cd intyga-intelligence
node scripts/self-host.mjs --origin https://intelligence.example.com
docker compose --env-file .env.selfhost -f compose.selfhost.yml up -d --build
```

The script generates `.env.selfhost`, readable only by your OS user. It refuses to
overwrite an existing installation. The stack includes Postgres, a migration job, the app and a
non-overlapping detection scheduler. Postgres has no published port. The app binds only to
`127.0.0.1:4100`; point your host reverse proxy there and terminate HTTPS at the proxy.
Use `--port 4200` if port 4100 is occupied. `PUBLIC_URL` must be the address your browser uses.
This stack uses a separate Compose project from `docker-compose.yml` for local development.

For example, a host Caddy configuration is:

```caddyfile
intelligence.example.com {
  reverse_proxy 127.0.0.1:4100
}
```

Use a hostname you control with DNS pointing to this server. Register this exact origin under INTYGA’s Member applications. Application passkeys are scoped to
this hostname; changing it requires a new registration and passkeys. A containerized proxy needs its own network arrangement; loopback is the host's loopback.

## Connect INTYGA

Connection configuration lives in the deployment environment and a mounted public trust-anchor
file. The browser shows status; it cannot replace the service key, workspace or anchor.

1. In INTYGA, create a SERVICE and its key, then configure the workspace approval rules for it.
2. Set `PUBLIC_URL`, `INTYGA_URL`, `INTYGA_CONSOLE_URL`, `INTYGA_WORKSPACE_ID`,
   `INTYGA_SERVICE_CLIENT_ID` and `INTYGA_SERVICE_CLIENT_SECRET` in `.env.selfhost`.
3. In **Integrations → Member applications**, register Intelligence’s exact origin and service
   client ID. Save the ownership proof to `config/intyga-embedded-registration.json`. Set
   `INTYGA_EMBEDDED_REGISTRATION_FILE` to that file and `INTYGA_EMBEDDED_APPLICATION_ID` to the
   returned UUID. Restart the app, then **Verify ownership** in INTYGA within 15 minutes.
4. From Intelligence’s sign-in page, choose **Link my INTYGA membership**. Authorize linking with
   your console passkey, return to Intelligence, and create an application passkey. Each member
   links their own membership; the service key cannot enroll people on its own.
5. Export the **application** trust anchor from Member applications, save it as
   `config/intyga-trust-anchor.json`, and restart the app. Its `tenantId` must match the workspace.
   Refresh this file when application passkeys change.
6. Sign in with the application passkey and approve a protected change in Intelligence. Workspace
   ADMINs administer; MEMBERs read. Each action requires its own verified, redeemed approval.

The initial status page can run before a usable trust anchor has been mounted; the well-known
ownership proof remains available. Members can link before an anchor is mounted; sign-in and execution require a valid anchor.
`INTYGA_OIDC_CLIENT_ID` is optional: an OIDC client uses the exact `/auth/callback` URI. Without
embedded configuration, the normal approval sign-in flow opens INTYGA and grants its initiating
browser administrator access for 12 hours. Keep the corresponding console-origin trust anchor
for that mode. There is no password login or authentication bypass.

An INTYGA outage prevents new sign-ins and approvals; enabled collection and detection continue.
For local development use host `pnpm dev`, `PUBLIC_URL=http://localhost:4100` and loopback gateway
URLs. The INTYGA console operator must enable `EMBEDDED_ALLOW_LOCALHOST=true` in development.

## Get useful evidence

Create a **Service** (for example, Production API), add your deployment and error sources under
**Connectors**, and assign them to that service. Activate each source and choose its detectors.
These changes require passkey approval. Source assignment groups unassigned history; changing an
assignment later preserves already-grouped observations. Deploy regression detection compares signals
within the same service. Use separate connections for separate services or environments.

The service page shows open findings and the most recent 100 events from the last seven days. Follow
a finding to investigate, annotate, resolve or mute it. Connector health distinguishes failed polling,
stale data and a quiet source. Configure an alert target if findings should notify your existing tools.
See [CONNECTORS.md](CONNECTORS.md) for source setup and supported event kinds.

## Operate and upgrade

```sh
docker compose --env-file .env.selfhost -f compose.selfhost.yml ps
docker compose --env-file .env.selfhost -f compose.selfhost.yml logs --tail=100 app scheduler migrate
```

`/ready` checks the app's database connection. The scheduler has its own health check based on the
last successful detection tick. A fresh install has no sources until you activate them.

Back up Postgres, `.env.selfhost`, and `config/intyga-trust-anchor.json` securely. The installer
does not create `.selfhost/` or an approval signing key. Passkey private keys remain in members’
authenticators. The encryption key restores connector secrets and encrypted browser state; the
INTYGA service secret is supplied only through the environment. Do not regenerate secrets during an upgrade.

```sh
docker compose --env-file .env.selfhost -f compose.selfhost.yml exec -T postgres \
  pg_dump -U intelligence -d intelligence -Fc > intelligence.backup
git pull --ff-only
docker compose --env-file .env.selfhost -f compose.selfhost.yml build migrate
docker compose --env-file .env.selfhost -f compose.selfhost.yml stop app scheduler
docker compose --env-file .env.selfhost -f compose.selfhost.yml run --rm migrate
docker compose --env-file .env.selfhost -f compose.selfhost.yml up -d
```

Only restart the app after migration succeeds. This prevents Prisma missing-column errors when new
code expects a newer schema. For a non-Compose install, run `pnpm db:deploy` before restarting the app.
`docker compose down` preserves the database volume; adding `-v` deletes it.
