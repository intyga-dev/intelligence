# Releasing INTYGA Intelligence 1.0.0

Use this guide with [SELF_HOST.md](SELF_HOST.md), [PRODUCTION.md](PRODUCTION.md) and the
[changelog](../CHANGELOG.md).

## Release contents and prerequisites

The application version and public advisory marker are `1.0.0`; the marker protocol remains `1`.
The package is private because Intelligence is deployed as an application, not published to npm.
Its published dependencies resolve to `@intyga/sdk` 2.3.1 and `@intyga/verify` 2.4.0.

Intelligence's deployment recipe and CI use Node 26 and PostgreSQL 16. `.nvmrc` pins Node 26.13.0
for local development; run `nvm install && nvm use` if you use nvm. Upgrade an existing host runtime
to Node 26 before installing or starting 1.0.0; the Docker image includes it.
Use the pnpm version in `package.json` and install from the committed lockfile.

Before deploying, the INTYGA gateway and console must support:

- Member applications, ownership verification and member-bound application passkeys.
- SERVICE credentials, workspace approval rules and application trust-anchor exports.
- `POST /embedded/applications/:applicationId/authorize` with application-bound approval routing.

Confirm the deployed gateway supports application-bound approval routing; an SDK upgrade alone
does not add that server endpoint. Do not weaken the workspace rules or receipt checks to work around a refused ceremony.

## Verify the release candidate

1. Confirm the branch contains the intended changes and the version is `1.0.0` in `package.json`
   and `src/embedded/registration.ts`. Review the changelog and deployment instructions.
2. Install dependencies with `pnpm install --frozen-lockfile` and generate the Prisma client with
   `pnpm db:generate` (`DIRECT_URL` is needed to load the Prisma configuration).
3. Use a dedicated, disposable test database whose name includes `test`. Apply migrations with
   `DATABASE_URL` and `DIRECT_URL` pointing to that database, then set `TEST_DATABASE_URL` for tests.
   The database-backed tests truncate tables. Never use a development or production database.
4. Require the candidate's CI checks: typecheck, lint, boundary check, all tests with the test
   database configured, and `pnpm audit --prod --audit-level high`.
5. Build the Docker image and verify `/health`, `/ready`, the scheduler, application-passkey sign-in,
   an intended protected change, one-use receipt redemption, and representative connector input
   in a staging deployment. Exercise multi-approver quorum if the workspace uses it.

Automated tests validate their fixtures and boundaries. They do not establish that every provider
account is configured correctly or that a live passkey ceremony works on every target browser.

## Upgrade an existing installation

1. Back up PostgreSQL, deployment configuration and the mounted trust anchor. Preserve
   `SECRETS_ENC_KEY`; replacing it makes stored secrets unreadable.
2. Record the current image/commit and confirm the backup can be restored. Deploy the required
   INTYGA gateway capabilities before creating new embedded approval requests.
3. Select the reviewed Intelligence release commit. Once published, `v1.0.0` identifies that commit.
   Use the build, stop, migrate and restart sequence in [SELF_HOST.md](SELF_HOST.md#operate-and-upgrade).
4. Refresh the application trust anchor if passkeys changed. Sign in, make an intended protected
   change, and confirm both receipt verification and successful application of the change.
5. Verify scheduler health, connector health and one expected finding or observation. Configure
   operational targets explicitly; an enabled detector with no targets cannot monitor them.
6. If historical path-only findings need reclassification, preview first:

   ```sh
   pnpm exec tsx scripts/reclassify-observations.ts <tenant-id>
   ```

   Review the result before running the same command with `--apply`. It preserves identifiers,
   feedback and history and does not poll providers, call a model or send alerts.

Earlier authentication migrations can clear sessions and remove tables. Prefer a forward fix.
If rollback is necessary, stop the app and scheduler and restore a reviewed matching database,
image and configuration together, accounting for writes since the backup. Do not assume an
image-only downgrade is safe.

## Publish

After the reviewed commit passes CI and staging checks, merge it into `main`, create an immutable
`v1.0.0` tag at that exact commit, and publish GitHub release notes from the changelog. Record the
commit and image digest used for deployment. Do not run `npm publish` for this private application.

Updating the version files prepares the release; it does not create the tag, publish a GitHub
release or deploy an instance. Those steps are completed separately by the maintainer.
