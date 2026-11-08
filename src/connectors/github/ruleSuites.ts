import type { ConnectorContext } from "../registry.ts"
import type { NormalizedEvent } from "../types.ts"

interface RuleSuite {
  id: number
  ref: string
  after_sha: string
  pushed_at: string
  result: string
  actor_name?: string
  rule_evaluations?: { enforcement: string; result: string; rule_type: string }[]
}

/** GitHub's historical rule evaluations, not today's rules applied retroactively to an old merge. */
export async function pollRuleSuites(
  ctx: ConnectorContext,
  targets: { repo: string; branch: string }[],
  get: <T>(path: string) => Promise<T | null>,
): Promise<NormalizedEvent[]> {
  const events: NormalizedEvent[] = []
  let budget = 40
  for (const { repo, branch } of targets.slice(0, 20)) {
    const key = `rule-suite:${repo}:${branch}`
    const since = await ctx.getCursor(key)
    const suites: RuleSuite[] = []
    let listedAll = false
    for (let page = 1; page <= 5; page++) {
      const batch = await get<RuleSuite[]>(
        `/repos/${repo}/rulesets/rule-suites?ref=${encodeURIComponent(`refs/heads/${branch}`)}&time_period=day&evaluate_status=active&per_page=100&page=${page}`,
      )
      if (!Array.isArray(batch)) break
      suites.push(...batch)
      if (batch.length < 100 || (since && batch.some((s) => s.pushed_at < since))) {
        listedAll = true
        break
      }
    }
    let newest = since
    let complete = listedAll
    for (const suite of suites) {
      if (since && suite.pushed_at < since) continue
      if (suite.result !== "bypass") {
        if (!newest || suite.pushed_at > newest) newest = suite.pushed_at
        continue
      }
      if (budget-- <= 0) {
        complete = false
        ctx.log("rule suite detail limit reached")
        break
      }
      const detail = await get<RuleSuite>(`/repos/${repo}/rulesets/rule-suites/${suite.id}`)
      if (!detail || !Array.isArray(detail.rule_evaluations)) {
        complete = false
        continue
      }
      if (detail.ref !== `refs/heads/${branch}` || detail.result !== "bypass") continue
      const failures = detail.rule_evaluations.filter(
        (r) =>
          r.enforcement === "active" &&
          r.result === "fail" &&
          ["pull_request", "required_status_checks", "workflows"].includes(r.rule_type),
      )
      events.push({
        connectionId: ctx.connectionId,
        source: "github",
        sourceId: `rule-suite:${repo}:${suite.id}`,
        kind: "github.rule_suite",
        at: new Date(detail.pushed_at),
        subjectRef: detail.actor_name ?? null,
        correlationRef: detail.after_sha,
        attrs: {
          repo,
          branch,
          sha: detail.after_sha,
          result: detail.result,
          activeMergeRuleFailed: failures.length > 0,
          failedRules: JSON.stringify(failures.map((r) => r.rule_type)),
        },
      })
      if (!newest || suite.pushed_at > newest) newest = suite.pushed_at
    }
    // A full page may hide earlier unobserved suites. Re-read instead of declaring full coverage.
    if (!listedAll) ctx.log("rule suite history truncated")
    if (complete && newest) await ctx.setCursor(key, newest)
  }
  return events
}
