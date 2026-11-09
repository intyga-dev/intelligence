---

name: intelligence-integrations
description: Add or change INTYGA Intelligence connectors and deterministic detectors, including event normalization, polling health, evidence and provider recovery behavior.
---

# Develop integrations

Follow [AGENTS.md](../../../AGENTS.md) and [CONTRIBUTING.md](../../../CONTRIBUTING.md).
Read the relevant source family in [CONNECTORS.md](../../../docs/CONNECTORS.md), then compare with
the current registry in `src/connectors/registry.ts` and a similar existing connector.

## Connector seam

- Register connectors in `src/connectors/index.ts`; normalize into `NormalizedEvent`. Keep
  stable source IDs, source timestamps, connection identity and correlation references. Detectors
  consume normalized records rather than provider responses.
- Verify signatures against raw request bytes. Use the provider's actual authentication scheme;
  shared-secret headers and Basic authentication must not be described as signed payloads.
- Bound requests, pages and timeouts. Report recoverable upstream failures through `ctx.log`,
  which marks polling unhealthy; do not use it for debug output. An empty successful poll is healthy.
- Advance cursors only over events returned for persistence. Inspect the tick's buffered cursor
  handling before changing this contract. Preserve idempotency across retries.
- Request read-only provider scopes and minimize stored attributes. Do not expose tokens in events,
  logs or UI. Preserve collected history and credentials when editing connector settings.

## Detector seam

- Keep detection pure in `src/domain/detectors/`, with an explicit time window and deterministic
  evidence first. Update the registry and tick wiring where needed.
- Scope correlation to the intended service. Report temporal correlation without claiming a cause.
  Optional model judgment cannot originate a finding.
- Path-only matches remain observations and do not send alerts. Native provider incidents require
  explicit recovery; absence of events alone does not resolve them.
- Settings that change behavior still use the normal signed approval flow. A new integration must
  not bypass it.

Test meaningful boundaries next to the code: tampering, malformed input, deduplication, failure vs
empty polling, cursor bounds, service isolation and recovery as relevant. Prefer local fixtures;
do not poll live providers to test parsing. Run the appropriate local checks from CONTRIBUTING,
update capability descriptions to match implemented coverage, and report remaining provider-account
validation.
