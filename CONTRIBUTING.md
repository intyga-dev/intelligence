# Contributing

Contributions are welcome. This is a small project maintained alongside other work, so please open
an issue before starting anything large — it is a poor trade for both of us if you build something
that turns out to conflict with a design decision that was never written down.

## The two rules

**1. The trust boundary is not negotiable.**

> Intelligence may ask Intyga for permission. It may never hold the power to grant it, bypass it, or
> read across it.

`pnpm check:boundary` enforces the shape of this, and it is a text scan — it stops the ordinary
accident, not a determined author. If a change of yours needs the script relaxed, that is the
conversation to have in the issue, not a line to add to the allowlist in the same pull request.

**2. Evidence leads; a model never does.**

`EvidenceList` is `readonly [DeterministicEvidence, ...Evidence[]]` on purpose. A finding exists
because something measurable happened. The optional judgment layer may reorder, downgrade or
suppress; it may never be the reason a finding was raised. A change that lets a model originate a
finding is a change to what this product is.

## Before you open a pull request

```bash
pnpm verify   # typecheck, lint, boundary check, unit tests — all four must pass
```

CI runs exactly this. There is no separate set of checks to discover after review.

## What a good change looks like here

**Match the comment style.** This codebase explains *why*, at length, where the reasoning is not
recoverable from the code. Several comments exist specifically because an earlier, more obvious
version was wrong — the bare-identifier boundary check that fired on documentation, the eager
config getter that threw on import, the 2xx on a failed normalize. If your change reverses a
decision like that, say so in the comment. If it adds one, write down what you tried first.

**Tests go next to the code**, as `*.test.ts`, run by `node --test`. Prefer unit tests with no
database and no Fastify instance — `src/domain/`, `src/gate/` and `src/redaction/` are all testable
as pure functions, and that is not an accident. Inject a clock rather than sleeping.

**New connectors** implement the registry interface in `src/connectors/registry.ts` and normalize
into `NormalizedEvent`. A connector never reaches a detector directly and never writes anywhere but
through the store. If it is `push`, signature verification covers the **raw bytes**; re-serializing
a parsed body verifies only by luck.

**New detectors** live in `src/domain/detectors/`, take their window as a parameter, and return
findings with deterministic evidence first. Register in `src/jobs/tick.ts`. Detector failures are
isolated, so yours cannot take the others down — do not rely on that.

**Schema changes** need a migration in `prisma/migrations/`. Read the header of
`prisma/schema.prisma` first, particularly about what `tenantId` is and is not.

**Anything that widens what leaves the host** — a new field in `src/redaction/project.ts`, a new
outbound call — is a data-protection decision. Flag it explicitly in the pull request description;
it will be reviewed as one.

## What to expect

Review from one person, in and around other work. Small, focused pull requests get looked at
quickly. A large one with no prior issue may sit for a while, which is why the first paragraph asks
you to open one.

## Security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).

## License

Contributions are licensed under [Apache License 2.0](LICENSE), the same as the project. There is no
CLA.
