import type { ConnectorContext, PollConnector } from "../registry.ts"
import type { NormalizedEvent } from "../types.ts"

// Fly.io machines.
//
// GitHub tells you a deploy WORKFLOW ran. Fly tells you what is actually running, and the two
// disagree more often than anyone expects: a workflow that went green while machines crash-looped,
// a rollback nobody recorded, an OOM three hours after a release that looked clean.
//
// Polling the Machines API rather than taking a webhook: Fly's event stream is per-app and needs
// separate configuration per app, while one read-only token covers the org. Restarts are derived by
// watching the restart count move, which is why the previous value is kept in a cursor.

const MAX_APPS = 10
const TIMEOUT_MS = 12_000

interface FlyMachine {
  id: string
  name?: string
  state: string
  region?: string
  updated_at?: string
  config?: { image?: string }
  events?: {
    type: string
    status: string
    timestamp: number
    request?: { exit_event?: { exit_code?: number; oom_killed?: boolean } }
  }[]
}

export const flyConnector: PollConnector = {
  kind: "fly",
  mode: "poll",
  label: "Fly.io",
  blurb: "What is actually running: machine state, restarts, OOM kills and the image behind them.",

  fields: [
    {
      name: "apps",
      label: "App names",
      placeholder: "intyga-gateway, intyga-gateway-staging",
      help: "Comma separated. Up to 10.",
      required: true,
    },
    {
      name: "token",
      label: "Fly API token",
      help: "A read-only org token is sufficient. Nothing here deploys, scales or restarts anything.",
      required: true,
      secret: true,
    },
  ],

  setup: [
    "Create a Fly token scoped to the organisation that owns these apps.",
    "Paste it above. It is encrypted at rest and never returned by the API.",
    "Machine state is sampled each tick; restarts and OOM kills surface as events.",
  ],

  async poll(ctx: ConnectorContext): Promise<NormalizedEvent[]> {
    const apps = String(ctx.config.apps ?? "")
      .split(/[\s,]+/)
      .map((a) => a.trim())
      .filter((a) => /^[\w-]+$/.test(a))
      .slice(0, MAX_APPS)
    if (!ctx.secret || apps.length === 0) return []

    const out: NormalizedEvent[] = []

    for (const app of apps) {
      const ac = new AbortController()
      const timer = setTimeout(() => ac.abort(), TIMEOUT_MS)
      try {
        const res = await fetch(`https://api.machines.dev/v1/apps/${app}/machines`, {
          headers: { authorization: `Bearer ${ctx.secret}` },
          signal: ac.signal,
        })
        if (!res.ok) {
          ctx.log("fly request failed", { app, status: res.status })
          continue
        }
        const machines = (await res.json()) as FlyMachine[]

        for (const m of machines) {
          // Fly returns a rolling event list per machine. Only genuinely new ones are emitted,
          // tracked by the newest timestamp already seen for that machine.
          const cursorKey = `machine:${app}:${m.id}`
          const seen = Number((await ctx.getCursor(cursorKey)) ?? 0)
          let newest = seen

          for (const ev of m.events ?? []) {
            if (ev.timestamp <= seen) continue
            if (ev.timestamp > newest) newest = ev.timestamp

            const oom = ev.request?.exit_event?.oom_killed === true
            const exitCode = ev.request?.exit_event?.exit_code
            out.push({
              connectionId: ctx.connectionId,
              source: "fly",
              sourceId: `fly:${app}:${m.id}:${ev.timestamp}:${ev.type}`,
              kind: oom ? "fly.machine.oom" : `fly.machine.${ev.type}`,
              at: new Date(ev.timestamp),
              // The app is the subject: one machine dying is noise, an app's machines dying is not.
              subjectRef: app,
              correlationRef: m.config?.image ?? null,
              attrs: {
                app,
                machine: m.id,
                machineName: m.name ?? "",
                region: m.region ?? "",
                state: m.state,
                event: ev.type,
                status: ev.status,
                image: m.config?.image ?? "",
                oomKilled: oom,
                exitCode: typeof exitCode === "number" ? exitCode : -1,
              },
            })
          }
          if (newest > seen) await ctx.setCursor(cursorKey, String(newest))
        }
      } catch (err) {
        ctx.log("fly request errored", { app, err: (err as Error).message })
      } finally {
        clearTimeout(timer)
      }
    }
    return out
  },
}
