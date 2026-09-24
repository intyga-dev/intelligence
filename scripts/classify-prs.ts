#!/usr/bin/env -S pnpm exec tsx
// Run the sensitivity map over the pull requests already ingested.
//
// A dry run of what detector 5 will do, against real stored data rather than fixtures — the point
// being to see whether the thresholds produce a list worth reading before wiring it to findings.

import "../src/loadenv.ts"
import { classifyChangedPaths, pathMapFor } from "../src/domain/sensitivity.ts"
import { prisma } from "../src/store/client.ts"

const rows = await prisma.event.findMany({
  where: { source: "github", kind: { startsWith: "github.pull_request" } },
  orderBy: { at: "desc" },
  take: 40,
})

let flagged = 0
for (const r of rows) {
  const a = r.attrs as Record<string, unknown>
  const paths: string[] = JSON.parse(String(a.paths ?? "[]"))
  if (paths.length === 0) continue

  // PATH_MAP selects the map, as the connection's `pathMap` setting does: generic unless told otherwise.
  const res = classifyChangedPaths(paths, {
    truncated: Boolean(a.pathsTruncated),
    map: pathMapFor(process.env.PATH_MAP),
  })
  if (res.hits.length === 0 && !res.mirror) continue
  flagged++

  console.log(`\n#${a.number}  ${String(a.title).slice(0, 62)}`)
  console.log(`   ${paths.length} paths (${res.excluded.length} noise) · floor: ${res.severityFloor ?? "—"}`)
  for (const h of res.hits) {
    console.log(`   · ${h.component.id.padEnd(22)} ${h.paths.length} file(s)`)
  }
  if (res.mirror) {
    const m = res.mirror
    console.log(
      `   · canonical-payload mirror: ${m.touched.length}/${m.touched.length + m.missing.length} ports, vectors ${
        m.vectorsUpdated ? "updated" : "NOT updated"
      }` +
        (m.complete
          ? " — COMPLETE"
          : m.reliable
            ? ` — INCOMPLETE, missing: ${m.missing.join(", ")}`
            : " — cannot tell (path list truncated)"),
    )
  }
}

console.log(`\n${flagged} of ${rows.length} pull requests touched something security-sensitive.`)
await prisma.$disconnect()
