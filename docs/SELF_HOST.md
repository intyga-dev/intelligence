# Self-host Intelligence

Intelligence is free to run on your infrastructure. It requires an INTYGA workspace for sign-in and
approval. Your users are the workspace's members and sign in with their existing INTYGA passkeys.
Your INTYGA deployment must support **Integrations → App sign-in**, SERVICE API keys and online
trust-anchor exports from **Approval Rules**. Upgrade INTYGA if these controls are missing.

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

Use a hostname you control with DNS pointing to this server. Register its exact `/auth/callback` URL in INTYGA; update that registration if the
hostname changes. Passkeys belong to the INTYGA console domain. A containerized proxy needs its own network arrangement; loopback is the host's loopback.

## Connect INTYGA

1. Open your instance. **Example incident** is static and creates no findings, users or alerts.
2. Open your INTYGA workspace. In **Integrations → App sign-in**, register this instance with the
   exact redirect URI `https://intelligence.example.com/auth/callback` (or
   `http://localhost:4100/auth/callback` locally). Copy its public client ID; it has no secret.
3. In **API Keys → Create a service and its key**, create a SERVICE identity and save the client ID
   and secret. Configure its approval rules and approvers under **Approval Rules**, then export the
   online trust anchor. Copy the workspace ID from **Settings**.
4. In Intelligence's setup form, enter `SETUP_TOKEN` from `.env.selfhost`, the gateway and console
   URLs, workspace ID, instance origin, OIDC client ID, SERVICE client ID and secret, and trust-anchor
   JSON. The anchor must name this workspace. The service secret is stored encrypted in the database.
5. Sign in with INTYGA. Workspace ADMINs administer Intelligence; MEMBERs can read it. There is no
   separate Intelligence passkey to enrol. Use **Settings → Test connection**, then create a Service
   and follow its approval link to INTYGA. Approval is verified and redeemed before the change runs.
6. Clear `SETUP_TOKEN` in `.env.selfhost` and recreate the app after setup. Preserve the other secrets.

For a private INTYGA deployment, set `INTYGA_CONSOLE_URL` before starting the stack.
There is no password login or auth bypass. An INTYGA outage prevents new sign-ins and approvals;
already-enabled collection and detection continue locally.

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

Back up the Postgres database and `.env.selfhost` securely. The installer no longer creates
`.selfhost/` or a signing key; approval keys remain with the INTYGA approvers. The encryption key is required
to restore connector and INTYGA credentials. Do not regenerate secrets during an upgrade.

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
