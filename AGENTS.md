# Working in INTYGA Intelligence

- Ask the user before switching branches. Keep changes on the current branch unless they approve a switch.
- Keep commits local. The maintainer handles pushes, GitHub Actions starts/reruns, PR-ready transitions and releases. Do not trigger remote CI.
- Follow [CONTRIBUTING.md](CONTRIBUTING.md) for the trust boundary and local checks. Honor an explicit agreement to leave full testing to maintainer-run CI; report what was actually checked.
- Database-backed tests truncate data. Use a disposable database whose name contains `test`, with the migration and test URLs pointing only to that database. Never use development or production data.
- Intelligence may request approval, verify receipts and redeem them; it may not grant approval or bypass passkey, quorum or trust-anchor checks.

Use the repository skill that fits the task:

- [intelligence-operate](.agents/skills/intelligence-operate/SKILL.md): deployment, member application setup and operational troubleshooting.
- [intelligence-integrations](.agents/skills/intelligence-integrations/SKILL.md): connector and deterministic detector changes.
- [intelligence-release](.agents/skills/intelligence-release/SKILL.md): version, runtime, documentation and release verification.

Read only the relevant skill and its task-specific references. Skills do not authorize deployment or protected application actions.
