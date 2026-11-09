---

name: intelligence-operate
description: Set up, upgrade or troubleshoot an INTYGA Intelligence deployment, including application passkeys, receipt verification, scheduler health and failed collection.
---

# Operate Intelligence

Follow [AGENTS.md](../../../AGENTS.md). For installation read [SELF_HOST.md](../../../docs/SELF_HOST.md);
for independently managed infrastructure read [PRODUCTION.md](../../../docs/PRODUCTION.md).
Use [CONNECTORS.md](../../../docs/CONNECTORS.md) for source-specific configuration.

Check the running revision and environment before changing configuration. Report variable names and
whether they are configured; do not expose credentials, cookies, ownership proofs or database URLs.

## Sign-in and approvals

- In-page passkeys use **Member applications** at INTYGA's `/embedded`. Customer applications at
  `/platform` and OIDC clients at `/oidc-clients` are separate registrations.
- Match the exact browser origin, SERVICE client ID and workspace. Reuse a matching verified
  registration. Each active member links their own membership and creates an application passkey.
- The mounted application trust anchor must match the workspace and current application credentials.
  Check stale/revoked keys and origin/RP mismatches when WebAuthn signatures fail.
- Embedded actions require the deployed gateway's application-specific authorize endpoint. An SDK
  update alone cannot add it. Do not fall back to console approval to hide missing routing.
- Request, verify against the frozen action and trusted keys, then redeem once before execution.
  The human completes passkey approval and workspace quorum. Never manufacture a receipt, relax
  verification or write directly to the database to simulate an approved change.

## Collection and operation

- Check `/health`, `/ready`, scheduler results and the affected connector's health independently.
  Empty successful polls are healthy. Failed polls warrant checking credential scope, configured
  resources, provider availability and rate limits without exposing tokens.
- Run one app instance and one scheduler: overlap protection and rate limits are in-process.
- Provider silence is not recovery. Match explicit recovery events and configured operational
  targets before concluding a finding should resolve.
- Back up the database, configuration and trust anchor before an authorized upgrade. Preserve
  `SECRETS_ENC_KEY`; an image-only rollback may be unsafe after authentication migrations.
- Use disposable fixtures for tests. Describe remaining live-account or human-passkey checks
  separately from local automated verification.
