---

name: intelligence-release
description: Prepare an INTYGA Intelligence release locally by aligning application versions, Node runtime, dependencies, deployment documentation and verification evidence.
---

# Prepare a release

Follow [AGENTS.md](../../../AGENTS.md) and the current [release guide](../../../docs/RELEASING.md).
The old HTML runbook is historical. A version bump prepares a candidate; it does not publish it.

- Confirm the current branch and existing edits. Ask before switching branches. Keep commits local;
  the maintainer handles pushes and GitHub CI. Never start or rerun Actions or mark a PR ready.
- Align `package.json` and the application version in `src/embedded/registration.ts`. The marker
  protocol version is separate; do not increment it for an ordinary application release.
- Keep the lockfile consistent with the declared SDK and transitive verifier. Confirm required
  gateway capabilities independently; package installation does not add required server endpoints.
- For runtime updates align `.nvmrc`, package engines, Node typings, CI and Docker. Use the pinned
  package manager and image digest. Check whether the chosen image bundles Corepack before relying
  on it; the current Docker recipe installs pnpm explicitly.
- Review README, changelog, security support policy and deployment/connector guides against the
  implemented behavior. Show optional variables as optional rather than placeholder values.
  Explain rollback limits, one-instance scheduling and any required gateway rollout.
- Run the agreed local checks under the intended Node runtime. The normal verification includes
  typecheck, lint, boundary checks and tests, plus production dependency audit and Docker build.
  Database tests need an isolated disposable test database and generated Prisma client; migrate
  only that test database and never truncate development data.
- Respect an explicit agreement to leave expensive suites to maintainer-run CI. Distinguish
  checks passed, checks skipped and live staging/passkey checks still required. Do not claim full
  compatibility solely because unit tests passed.
- Validate repository skills if changed, review the final diff and commit the intended files when
  authorized. Report the branch and commit. Do not tag, publish an npm package, release or deploy
  merely because local release preparation is complete; Intelligence is a private application.
