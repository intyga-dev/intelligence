#!/usr/bin/env node
// The trust boundary, enforced.
//
// The rule is NOT "never talk to Intyga". Intelligence is a legitimate CONSUMER of Intyga: its own
// privileged actions (enabling the judgment provider, connecting a source, purging data) are gated
// by a human approval obtained through Intyga, exactly as any other integrating application would.
// That direction is the boundary working, not leaking — Intelligence submits to enforcement.
//
// The rule is: **Intelligence may ask Intyga for permission, and may never hold the power to grant
// it, bypass it, or read across it.**
//
// So this check allows the approval-request path and refuses:
//   · operator / service credentials (METRICS_TOKEN, SWEEP_TOKEN) — those open dozens of routes
//   · direct database access to Intyga — that walks around RLS entirely
//   · admin, policy, sweep and internal endpoints — enforcement and operator surfaces
//
// It is a text scan, not a type checker. It cannot stop someone determined to smuggle a URL through
// a variable — it stops the ordinary, well-intentioned version, which is the one that actually
// happens. The design invariant is the real control; this is the ratchet that makes breaking it
// deliberate.

import { readdir, readFile } from "node:fs/promises"
import path from "node:path"

const root = process.cwd()
const roots = ["src", "scripts"]

/**
 * Intyga endpoints this service must never call.
 *
 * `/authorize`, `/authorize/:nonce`, `/authorize/verify` and `/oauth/token` are deliberately NOT
 * here — they are the approval-request path, the one legitimate outbound direction.
 */
const FORBIDDEN_PATH_PATTERNS = [
  /["'`][^"'`]*\/admin\//,
  /["'`][^"'`]*\/internal\/(sweep|metrics)/,
  /["'`][^"'`]*\/policy\//,
  /["'`][^"'`]*\/graph\/nodes/,
  /["'`][^"'`]*\/audit\/(evidence|proof)/,
  /["'`][^"'`]*\/wallet\//,
]

/**
 * Credentials that would make this a bypass rather than a gate.
 *
 * Matched as ENVIRONMENT READS (`process.env.X`, or destructured from it), not as bare identifiers.
 * The bare-word version fired on prose — a connector's help text saying "use the read-only scrape
 * token, never METRICS_TOKEN" was flagged as holding the thing it was warning against. A check that
 * matches documentation teaches people to reword comments instead of fixing code, which is worse
 * than no check.
 *
 * What is actually forbidden is READING one of Intyga's own secrets from this process's
 * environment. Tokens a customer pastes into a connector are a different thing entirely: they
 * arrive through the UI, are encrypted at rest, and are scoped by whoever issued them.
 *
 * The RP gate's own variables are absent on purpose — they name a platform-scoped key that can
 * only ask for a human approval.
 */
const FORBIDDEN_ENV = [
  "METRICS_TOKEN",
  "SWEEP_TOKEN",
  "INTYGA_DATABASE_URL",
  "DATABASE_URL_INTYGA",
  "APP_DATABASE_URL",
  "INTYGA_OWNER",
  "JWT_SECRET",
  "SECRETS_ENC_KEY_INTYGA",
]

const CREDENTIAL_PATTERNS = FORBIDDEN_ENV.flatMap((name) => [
  new RegExp(`process\\.env\\.${name}\\b`),
  new RegExp(`process\\.env\\[["'\`]${name}["'\`]\\]`),
  // Destructured: const { METRICS_TOKEN } = process.env
  new RegExp(`\\{[^}]*\\b${name}\\b[^}]*\\}\\s*=\\s*process\\.env`),
])

/**
 * Lines allowed to mention an Intyga host: documentation of the INBOUND direction.
 * A comment explaining the boundary must not trip the check that enforces it.
 */
const COMMENT = /^\s*(\/\/|\*|\/\*|#)/

const failures = []

async function files(dir) {
  let entries
  try {
    entries = await readdir(dir, { withFileTypes: true })
  } catch {
    return []
  }
  const nested = await Promise.all(
    entries.map((e) => {
      const full = path.join(dir, e.name)
      if (e.isDirectory()) return e.name === "node_modules" ? [] : files(full)
      return [full]
    }),
  )
  return nested.flat()
}

for (const dir of roots) {
  for (const file of await files(path.join(root, dir))) {
    if (!/\.(ts|tsx|mjs|js)$/.test(file)) continue
    if (file.endsWith("check-no-intyga-client.mjs")) continue
    const relative = path.relative(root, file).split(path.sep).join("/")
    const lines = (await readFile(file, "utf8")).split("\n")

    lines.forEach((line, i) => {
      if (COMMENT.test(line)) return
      if (FORBIDDEN_PATH_PATTERNS.some((p) => p.test(line))) {
        failures.push(
          `${relative}:${i + 1} references an Intyga host in executable code.\n` +
            `    Intelligence is a sink: Intyga pushes to us, we never call Intyga.\n` +
            `    ${line.trim().slice(0, 120)}`,
        )
      }
      if (CREDENTIAL_PATTERNS.some((p) => p.test(line))) {
        failures.push(
          `${relative}:${i + 1} reads one of Intyga's own secrets from the environment.\n` +
            `    Allowed: the platform-scoped RP key, which can only ASK for a human approval,\n` +
            `    and tokens a customer pastes into a connector (encrypted, scoped by them).\n` +
            `    ${line.trim().slice(0, 120)}`,
        )
      }
    })
  }
}

if (failures.length > 0) {
  console.error(`\ncheck-no-intyga-client: ${failures.length} violation(s)\n`)
  for (const f of failures) console.error(`  ${f}\n`)
  process.exit(1)
}
console.log("check-no-intyga-client: ok — no privileged path into Intyga")
