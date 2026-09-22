# Security policy

## Reporting a vulnerability

**Do not open a public issue.**

Report privately through either channel:

* GitHub → **Security** → **Report a vulnerability** (private advisory), or
* email **security@intyga.com** — PGP key on request.

Please include what you need to make it reproducible: affected version or commit, the shape of the
request or configuration, and what you observed versus what you expected. A proof of concept helps
and is not required to file.

**What to expect.** Intyga Intelligence is maintained by a very small team. An acknowledgement
within 5 working days and an initial assessment within 10. If a report is valid you will hear what
the fix is and when it lands; if it is not, you will hear why, rather than silence. Credit in the
advisory unless you prefer otherwise.

We will not pursue legal action over good-faith research that stays within your own deployment. There
is no bug bounty.

## Scope

**In scope** — this repository:

* Authentication and session handling (`src/auth/`)
* The Intyga RP gate and intent digesting (`src/gate/`)
* Webhook signature verification and ingest (`src/connectors/*/signature.ts`, `src/server/app.ts`)
* Encryption of connector secrets at rest (`src/store/crypto.ts`)
* The judgment projection — anything that causes data outside the allowlist to leave the host
  (`src/redaction/project.ts`)
* The trust boundary itself (`scripts/check-no-intyga-client.mjs` and the design it ratchets)

**Out of scope here, but we still want to know:**

* Anything in the Intyga gateway or console. Those are a separate codebase — report them the same
  way and say which system you mean.
* Vulnerabilities in third-party connectors' own APIs (GitHub, Vercel, Sentry, Fly, Prometheus).
  Report those to their vendors; tell us if Intelligence handles the result unsafely.

**Known and documented, so not a finding on its own** — each of these is written down with its
reasoning, and a report that shows the reasoning is *wrong* is very much in scope:

* **No row-level security.** Tenant scoping is application-level; the deployment is single-tenant.
  See the header of `prisma/schema.prisma`. Cross-tenant reads on a multi-tenant deployment are a
  known consequence of a configuration we tell you not to run.
* **Ingest rate limits are in-process and per-instance**, and are a cost guard rather than an
  authentication control. See `src/server/ratelimit.ts`.
* **`trustProxy` is off**, so `req.ip` is the socket peer. This is deliberate: trusting a forwarded
  header would let anyone reaching the origin directly spoof it.
* **The boundary check is a text scan.** It stops the ordinary accident, not a determined author.
  Its own comments say so.

## Supported versions

`0.1.0` is pre-release. Fixes land on `main` and there are no backports. Run `main`.

## Handling

Confirmed vulnerabilities get a GitHub security advisory and a CVE where one applies. We will not
publish an advisory before a fix is available, unless the issue is already being exploited.
