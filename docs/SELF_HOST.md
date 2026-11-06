# Self-host Intelligence

Intelligence is free to run on your infrastructure. It requires an INTYGA workspace for sign-in and
passkey approval. Register it through **Integrations → Intelligence** in the INTYGA console: this
first-party integration is outside the Embedded contract and usage gates, including on public domains.
Your INTYGA deployment must include the Intelligence integration page and first-party RP migration.
If that page is missing, update INTYGA before connecting a public instance.

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

The script generates `.env.selfhost` and `.selfhost/`, readable only by your OS user. It refuses to
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

Use a hostname you control with DNS pointing to this server. Keep it stable: passkeys bind to that
hostname. A containerized proxy needs its own network arrangement; loopback is the host's loopback.

## Connect INTYGA

1. Open your instance. You can explore **Example incident** before connecting anything; its data is
   static and it creates no findings, users or alerts.
2. Follow **Create or open your INTYGA workspace**, then **Integrations → Intelligence**. Register
   the RP ID (hostname only) and the exact origin, such as `https://intelligence.example.com`.
   Approve the registration with your INTYGA passkey. Use this first-party flow for localhost too.
3. In **API Keys**, create a platform-scoped key with `subjects:write`, `credentials:write`,
   `receipts:create` and `receipts:read`. Paste the public key from `.selfhost/rp-public.txt`.
   Copy the client ID and the gateway URL shown by INTYGA.
4. In Intelligence's setup form, enter `SETUP_TOKEN` from `.env.selfhost`, the client ID, gateway
   URL, RP ID and origin. Paste the contents of `.selfhost/rp.pk8` into the private-key field.
   This key is encrypted in Intelligence's own database; never paste it into INTYGA's public-key field.
5. Choose your administrator subject ID and name, submit, and enrol the administrator passkey.
   This passkey signs in on Intelligence's domain through INTYGA. It is separate from the passkey
   used on the INTYGA console's domain.
6. Clear `SETUP_TOKEN` in `.env.selfhost` and recreate the app after successful setup to disable
   browser bootstrap. Preserve the other secrets.

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

Back up the Postgres database, `.env.selfhost` and `.selfhost/` securely. The encryption key is required
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
