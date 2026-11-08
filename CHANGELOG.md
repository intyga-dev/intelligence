# Changelog

## 1.0.0 — 2026-11-07

First stable release of INTYGA Intelligence, a single-tenant, self-hosted application for
evidence-backed operational findings. See the [release guide](docs/RELEASING.md) before upgrading.

### Findings and collection

- 21 connectors covering code delivery, monitoring, cloud, identity, business alerts and custom events.
- Ten deterministic detectors, including collection health, CI health, GitHub merge-policy exceptions,
  overdue jobs, service-objective degradation and native provider alerts.
- Services group related sources. Deployment correlation stays within a service and reports timing,
  not proof of cause. Operational targets and maintenance windows are configured explicitly.
- Sensitive-path changes appear as informational observations, separate from actionable findings.
  They do not generate alerts or model anomaly scores. Historical observations can be reclassified
  with a preview-first operator utility.
- Searchable findings, saved URL filters, investigation notes and attributed activity.

### Identity and approvals

- Members link their INTYGA workspace membership and create an application passkey. Embedded
  sign-in and protected changes take place inside Intelligence under workspace approval rules.
- Application approval links support additional quorum approvers. New embedded requests use the
  application-specific authorization route and suppress INTYGA console approval notifications.
- Receipts are verified against the frozen action and mounted application trust anchor, then
  redeemed once before execution. An older gateway without application routing fails closed.
- Persistent personal display names, GitHub connector editing that retains credentials and history,
  and clearer approval progress and toast feedback.
- INTYGA SDK 2.3.1 with receipt verifier 2.4.0.

### Deployment and limits

- Docker Compose installation includes PostgreSQL, migrations and a detection scheduler.
  Runtime, Docker and CI use Node 26.13.0 / Node 26 LTS, with matching Node 26 typings.
  Docker installs the repository-pinned pnpm explicitly; it does not depend on bundled Corepack.
- Configuration and public trust anchors are deployment-controlled. There is no local password,
  approval bypass, shared INTYGA database or automatic remediation.
- Run one application instance and one scheduler per deployment. Connector coverage varies by
  provider; validate credentials and representative events in your own account.
- Optional model judgment remains off by default. No support SLA is added by this release.

### Upgrade notes

Back up the database, environment and trust anchor before applying migrations. Earlier sign-in
migrations remove obsolete authentication/configuration tables and invalidate sessions; rolling
back only the application image is insufficient. Deploy an INTYGA gateway with application
approval routing before starting new embedded requests. Existing hosted requests retain their
original routing; start a fresh request to use the application ceremony.
