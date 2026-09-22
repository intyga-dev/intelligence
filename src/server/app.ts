import Fastify, { type FastifyInstance } from "fastify"
import { z } from "zod"
import { ALERT_RULE_INPUT, createAlertRule } from "../actions/registry.ts"
import { ActionError, completeAction, openAction, tenantBinding } from "../actions/execute.ts"
import { resolveGateConfig, testConnection } from "../gate/rp.ts"
import { AuthError, beginEnrol, beginLogin, completeEnrol, completeLogin } from "../auth/ceremony.ts"
import {
  clearCookie,
  COOKIE,
  readCookie,
  resolveSession,
  revokeSession,
  type SessionActor,
  sessionCookie,
} from "../auth/session.ts"
import { enrolPage, loginPage } from "../ui/auth.ts"
import { config } from "../config.ts"
import { createHash, randomBytes, timingSafeEqual } from "node:crypto"
import { createLimiter } from "./ratelimit.ts"
import { allConnectors, connectorFor, isPush } from "../connectors/index.ts"
import { NormalizeError } from "../connectors/intyga/normalize.ts"
import { DEFAULT_BURST_CONFIG } from "../domain/detectors/denialBurst.ts"
import { previewRequest, projectForJudgment } from "../redaction/project.ts"
import { runDetectors } from "../jobs/tick.ts"
import {
  eventSeries,
  latencyHistogram,
  overview,
  refusalSeries,
  topActionTypes,
  topSubjects,
} from "../store/analytics.ts"
import { prisma } from "../store/client.ts"
import { decryptSecret, encryptSecret } from "../store/crypto.ts"
import {
  connectionForIngest,
  type FeedbackVerdict,
  listFindings,
  markRawNormalized,
  recordFeedback,
  recordRawEvent,
  saveEvent,
} from "../store/repo.ts"
import {
  activityPage,
  alertsPage,
  type ConnectorRow,
  connectorCreatedPage,
  connectorsPage,
  detectorsPage,
  findingsPage,
  type JudgmentAuditRow,
  judgmentPage,
  membersPage,
  onboardingPage,
  overviewPage,
  settingsPage,
} from "../ui/pages.ts"

// HTTP surface.
//
// Three classes of route, and the distinction is the design:
//   · ingest      — the only inbound data path, authenticated by HMAC, never by a session
//   · read        — pages and JSON, safe and idempotent
//   · act         — privileged changes, which go through a passkey ceremony and nothing else
//
// There is no fourth class. A privileged change that is not in the action registry does not exist.

const WINDOW_MS = 7 * 24 * 60 * 60_000
const WINDOW_LABEL = "7 days"
const RETENTION_DAYS = 90

/**
 * Compare an `Authorization: Bearer …` header against an expected token in constant time.
 *
 * Digesting first rather than comparing the raw strings: `timingSafeEqual` throws on a length
 * mismatch, and catching that throw reintroduces exactly the length oracle it exists to avoid.
 * Two SHA-256 digests are always the same length, so the comparison is total.
 */
function bearerMatches(header: string | undefined, expected: string): boolean {
  if (!header?.startsWith("Bearer ")) return false
  const presented = createHash("sha256").update(header.slice(7)).digest()
  const want = createHash("sha256").update(expected).digest()
  return timingSafeEqual(presented, want)
}

export function buildApp(): FastifyInstance {
  // Per-instance, so a test builds its own allowance and cannot inherit another test's spent one.
  const ingestGlobalLimit = createLimiter({
    ratePerMinute: config.ingestRate.globalPerMinute,
    burst: config.ingestRate.globalPerMinute,
    maxKeys: 1,
  })
  const ingestConnectionLimit = createLimiter({
    ratePerMinute: config.ingestRate.perConnectionPerMinute,
    burst: config.ingestRate.perConnectionPerMinute,
    maxKeys: 1_000,
  })
  // Six an hour is far more than the schedule needs and far less than a stampede.
  const tickLimit = createLimiter({ ratePerMinute: 6, burst: 3, maxKeys: 1 })

  const app = Fastify({
    logger: {
      level: process.env.LOG_LEVEL ?? "info",
      redact: {
        paths: ["req.headers.authorization", 'req.headers["x-intyga-signature"]', "req.headers.cookie"],
        censor: "[redacted]",
      },
      serializers: { req: (r) => ({ method: r.method, url: r.url, id: r.id }) },
    },
    bodyLimit: 1_000_000,
  })

  // The HMAC covers the RAW bytes, so the original string has to survive parsing. Re-serializing a
  // parsed object would verify only by luck.
  app.addContentTypeParser("application/json", { parseAs: "string" }, (_req, body, done) => {
    try {
      done(null, { raw: body as string, json: JSON.parse(body as string) })
    } catch {
      done(null, { raw: body as string, json: null })
    }
  })
  app.addContentTypeParser("application/x-www-form-urlencoded", { parseAs: "string" }, (_req, body, done) =>
    done(null, Object.fromEntries(new URLSearchParams(body as string))),
  )

  const json = (req: { body: unknown }): unknown => (req.body as { json?: unknown })?.json ?? req.body
  const html = (reply: { type: (s: string) => { send: (b: string) => unknown } }, body: string) =>
    reply.type("text/html; charset=utf-8").send(body)

  // ─── health ────────────────────────────────────────────────────────────────────────────────────

  app.get("/health", async () => ({ ok: true }))
  app.get("/ready", async (_req, reply) => {
    try {
      await prisma.$queryRaw`SELECT 1`
      return { ok: true, checks: { db: "ok" } }
    } catch {
      return reply.code(503).send({ ok: false, checks: { db: "fail" } })
    }
  })

  // ─── ingest ────────────────────────────────────────────────────────────────────────────────────

  // One route for every push connector. The registry supplies verification, the idempotency key and
  // normalization, so adding a webhook source touches nothing here.
  app.post("/ingest/:kind/:connectionId", async (req, reply) => {
    const { kind, connectionId } = req.params as { kind: string; connectionId: string }

    // Before anything that costs: a DB lookup, an AES decrypt and an HMAC are all work we would
    // otherwise do for an unauthenticated caller. 429 rather than 401 here is deliberate and not a
    // leak — it is reached identically for a valid and an invented connection id, so it still says
    // nothing about which ids exist.
    if (!ingestGlobalLimit.take("ingest") || !ingestConnectionLimit.take(connectionId)) {
      const retryAfter = Math.max(
        ingestGlobalLimit.retryAfter("ingest"),
        ingestConnectionLimit.retryAfter(connectionId),
      )
      req.log.warn({ kind, connectionId }, "ingest rate limit")
      return reply.code(429).header("retry-after", String(retryAfter)).send({ error: "rate limited" })
    }

    const body = req.body as { raw: string; json: unknown } | undefined
    if (!body) return reply.code(400).send({ error: "empty body" })

    const def = connectorFor(kind)
    const connection = def && isPush(def) ? await connectionForIngest(connectionId, kind) : null
    // A uniform 401 for unknown kind, unknown connection and bad signature alike: an
    // unauthenticated prober must not be able to tell valid connection ids from invented ones.
    if (!def || !isPush(def) || !connection?.secretCiphertext) {
      return reply.code(401).send({ error: "unauthorized" })
    }

    const secret = decryptSecret(connection.secretCiphertext)
    if (!secret) {
      req.log.error({ connectionId }, "connection secret could not be decrypted")
      return reply.code(500).send({ error: "connection misconfigured" })
    }

    const verified = def.verify({ headers: req.headers, rawBody: body.raw, secret })
    if (!verified.ok) {
      req.log.warn({ kind, connectionId, reason: verified.reason }, "webhook signature rejected")
      return reply.code(401).send({ error: "unauthorized" })
    }

    // Checked only AFTER the signature verifies, for the same non-enumeration reason.
    if (!connection.active) return { ok: true, ignored: "connector inactive" }

    const sourceId = def.eventId(req.headers, body.json)
    if (!sourceId) return reply.code(400).send({ error: "delivery carried no event id" })

    const raw = await recordRawEvent({ connectionId, sourceId, body: body.json })
    if (!raw.created) return { ok: true, duplicate: true }

    try {
      const normalized = def.normalize({ connectionId, body: body.json, receivedAt: new Date() })
      if (normalized) await saveEvent(connection.tenantId, normalized)
      await markRawNormalized(raw.id)
      return { ok: true, stored: normalized !== null }
    } catch (err) {
      // The raw row is committed, so this is replayable. Answering 2xx is deliberate: a 5xx makes
      // the producer retry, back off and eventually DISABLE the endpoint — losing the feed over a
      // bug on our side that we have already durably captured.
      const message = err instanceof NormalizeError ? err.message : "normalize failed"
      req.log.error({ kind, connectionId, sourceId, err: message }, "normalize failed; raw retained")
      await markRawNormalized(raw.id, message)
      return { ok: true, stored: false, deferred: true }
    }
  })

  app.post("/internal/tick", async (req, reply) => {
    // Constant-time, because `!==` on a secret returns at the first differing byte and so leaks its
    // prefix to anyone willing to measure. The comparison is cheap; the house rule is that a token
    // check never uses `===`, so there is no category of token this was judged safe for.
    if (!bearerMatches(req.headers.authorization, config.tickToken)) {
      return reply.code(401).send({ error: "unauthorized" })
    }
    // A tick is expensive — it polls every connector and runs every detector. One bucket, so a
    // holder of the token cannot stampede the instance by scheduling it twice.
    if (!tickLimit.take("tick")) {
      return reply
        .code(429)
        .header("retry-after", String(tickLimit.retryAfter("tick")))
        .send({ error: "rate limited" })
    }
    return { ok: true, ...(await runDetectors(new Date())) }
  })

  // ─── authentication ────────────────────────────────────────────────────────────────────────────
  //
  // Everything is closed by default. The open set is small and listed here rather than marked
  // route-by-route, because an allowlist is auditable in one place and a per-route flag is one
  // forgotten decorator away from an open admin console.
  const PUBLIC_EXACT = new Set([
    "/health",
    "/ready",
    "/login",
    "/login/begin",
    "/login/complete",
    "/logout",
    "/members/enrol",
    "/members/enrol/begin",
    "/members/enrol/complete",
  ])
  const isPublic = (url: string): boolean => {
    const path = url.split("?")[0] ?? url
    // Ingest authenticates per request by signature and has no session; the tick is bearer-gated.
    if (path.startsWith("/ingest/")) return true
    if (path === "/internal/tick") return true
    return PUBLIC_EXACT.has(path)
  }

  app.decorateRequest("actor", null)

  app.addHook("preHandler", async (req, reply) => {
    const r = req as typeof req & { actor: SessionActor | null }
    r.actor = await resolveSession(readCookie(req.headers.cookie, COOKIE))
    if (isPublic(req.url)) return

    const t = await tenant()
    // No workspace at all: signup is the only thing to show, and there is nobody who could sign in.
    if (!t?.intygaKeyCipher) return

    if (!r.actor) {
      // HTML gets a redirect, JSON gets a 401 — a fetch() following a redirect to a login page and
      // parsing it as JSON produces a baffling error at the call site.
      if ((req.headers.accept ?? "").includes("text/html")) return reply.redirect("/login", 303)
      return reply.code(401).send({ error: "not signed in" })
    }
  })

  const actorOf = (req: unknown): SessionActor | null =>
    (req as { actor?: SessionActor | null }).actor ?? null

  /**
   * Spread into a page's options to attach the signed-in user.
   *
   * A spread rather than `actor: actorOf(req) ?? undefined`: under exactOptionalPropertyTypes an
   * explicit `undefined` is not the same as an absent property, and only absence is what "nobody is
   * signed in" means here.
   */
  const withActor = (req: unknown): { actor?: { label: string; externalId: string } } => {
    const a = actorOf(req)
    return a ? { actor: { label: a.label, externalId: a.externalId } } : {}
  }

  app.get("/login", async (req, reply) => {
    if (actorOf(req)) return reply.redirect("/", 303)
    const q = req.query as { id?: string }
    return html(reply, loginPage(q.id ? { prefill: q.id } : {}))
  })

  app.post("/login/begin", async (req, reply) => {
    const t = await tenant()
    if (!t) return reply.code(404).send({ error: "no workspace" })
    const parsed = z.object({ externalId: z.string().min(1).max(200) }).safeParse(json(req))
    if (!parsed.success) return reply.code(400).send({ error: "invalid request" })
    try {
      return await beginLogin(t.id, parsed.data.externalId)
    } catch (err) {
      req.log.warn({ err: (err as Error).message }, "login begin failed")
      return reply.code(err instanceof AuthError ? 400 : 502).send({ error: (err as Error).message })
    }
  })

  app.post("/login/complete", async (req, reply) => {
    const t = await tenant()
    if (!t) return reply.code(404).send({ error: "no workspace" })
    const parsed = z
      .object({ nonce: z.string().min(1).max(200), assertion: z.unknown() })
      .safeParse(json(req))
    if (!parsed.success) return reply.code(400).send({ error: "invalid request" })
    try {
      const { token, label } = await completeLogin(t.id, parsed.data.nonce, parsed.data.assertion)
      return reply.header("set-cookie", sessionCookie(token)).send({ ok: true, label })
    } catch (err) {
      req.log.warn({ err: (err as Error).message }, "login refused")
      return reply.code(err instanceof AuthError ? 401 : 502).send({ error: (err as Error).message })
    }
  })

  app.get("/logout", async (req, reply) => {
    const a = actorOf(req)
    if (a) await revokeSession(a.sessionId)
    // Cleared regardless: a cookie for a session that no longer resolves is still confusing.
    return reply.header("set-cookie", clearCookie()).redirect("/login", 303)
  })

  app.get("/members/enrol", async (req, reply) => {
    const q = req.query as { id?: string }
    if (!q.id) return reply.redirect("/login", 303)
    return html(reply, enrolPage({ externalId: q.id }))
  })

  app.post("/members/enrol/begin", async (req, reply) => {
    const t = await tenant()
    if (!t) return reply.code(404).send({ error: "no workspace" })
    const parsed = z.object({ externalId: z.string().min(1).max(200) }).safeParse(json(req))
    if (!parsed.success) return reply.code(400).send({ error: "invalid request" })
    try {
      return { options: await beginEnrol(t.id, parsed.data.externalId) }
    } catch (err) {
      return reply.code(err instanceof AuthError ? 400 : 502).send({ error: (err as Error).message })
    }
  })

  app.post("/members/enrol/complete", async (req, reply) => {
    const t = await tenant()
    if (!t) return reply.code(404).send({ error: "no workspace" })
    const parsed = z
      .object({ externalId: z.string().min(1).max(200), response: z.unknown() })
      .safeParse(json(req))
    if (!parsed.success) return reply.code(400).send({ error: "invalid request" })
    try {
      await completeEnrol(t.id, parsed.data.externalId, parsed.data.response)
      return { ok: true }
    } catch (err) {
      return reply.code(err instanceof AuthError ? 400 : 502).send({ error: (err as Error).message })
    }
  })

  // ─── tenant resolution ─────────────────────────────────────────────────────────────────────────
  //
  // V0 serves one tenant, so it is "the one that exists". Every store call still takes a tenantId,
  // so turning this into real per-request auth is a change here and nowhere else.
  async function tenant() {
    return prisma.tenant.findFirst({ orderBy: { createdAt: "asc" } })
  }
  async function counts(tenantId: string) {
    const [findings, alerts, connectors] = await Promise.all([
      prisma.finding.count({ where: { tenantId, status: { in: ["new", "investigating"] } } }),
      prisma.alertRule.count({ where: { tenantId, active: true } }),
      prisma.connection.count({ where: { tenantId, active: true } }),
    ])
    return { findings, alerts, connectors }
  }

  // ─── pages ─────────────────────────────────────────────────────────────────────────────────────

  app.get("/", async (req, reply) => {
    const t = await tenant()
    if (!t) return html(reply, onboardingPage())
    const since = new Date(Date.now() - WINDOW_MS)
    const [stats, events, refusals, findings, c] = await Promise.all([
      overview(t.id, since),
      eventSeries(t.id, since, "hour"),
      refusalSeries(t.id, since, "hour"),
      listFindings(t.id, { status: ["new", "investigating"], limit: 10 }),
      counts(t.id),
    ])
    return html(
      reply,
      overviewPage({
        stats,
        events,
        refusals,
        findings,
        counts: c,
        windowLabel: WINDOW_LABEL,
        ...withActor(req),
      }),
    )
  })

  app.get("/findings", async (req, reply) => {
    const t = await tenant()
    if (!t) return html(reply, onboardingPage())
    const filter = ((req.query as { status?: string }).status ?? "open").toLowerCase()
    const status = filter === "all" ? undefined : filter === "open" ? ["new", "investigating"] : [filter]
    const opts: { status?: string[]; limit?: number } = { limit: 200 }
    if (status) opts.status = status
    return html(
      reply,
      findingsPage({
        findings: await listFindings(t.id, opts),
        counts: await counts(t.id),
        filter,
        ...withActor(req),
      }),
    )
  })

  app.get("/activity", async (req, reply) => {
    const t = await tenant()
    if (!t) return html(reply, onboardingPage())
    const since = new Date(Date.now() - WINDOW_MS)
    const [events, refusals, subjects, actions, latency, c] = await Promise.all([
      eventSeries(t.id, since, "hour"),
      refusalSeries(t.id, since, "hour"),
      topSubjects(t.id, since),
      topActionTypes(t.id, since),
      latencyHistogram(t.id, since),
      counts(t.id),
    ])
    return html(
      reply,
      activityPage({
        events,
        refusals,
        subjects,
        actions,
        latency,
        counts: c,
        windowLabel: WINDOW_LABEL,
        ...withActor(req),
      }),
    )
  })

  app.get("/connectors", async (req, reply) => {
    const t = await tenant()
    if (!t) return html(reply, onboardingPage())
    const conns = await prisma.connection.findMany({
      where: { tenantId: t.id },
      orderBy: [{ builtIn: "desc" }, { createdAt: "asc" }],
    })
    const base = `${req.protocol}://${req.headers.host}`

    const rows: ConnectorRow[] = await Promise.all(
      conns.map(async (c) => {
        const def = connectorFor(c.kind)
        const [events, last] = await Promise.all([
          prisma.event.count({ where: { connectionId: c.id } }),
          prisma.event.findFirst({
            where: { connectionId: c.id },
            orderBy: { at: "desc" },
            select: { at: true },
          }),
        ])
        return {
          id: c.id,
          kind: c.kind,
          label: c.label,
          builtIn: c.builtIn,
          active: c.active,
          activatedAt: c.activatedAt,
          events,
          lastEventAt: last?.at ?? null,
          ingestUrl: `${base}/ingest/${c.kind}/${c.id}`,
          mode: def?.mode ?? "push",
          setup: def?.setup ?? [],
        }
      }),
    )

    const installed = new Set(conns.map((c) => c.kind))
    const available = allConnectors()
      .filter((d) => !d.builtIn)
      .map((d) => ({
        kind: d.kind,
        label: d.label,
        blurb: d.blurb,
        mode: d.mode,
        fields: d.fields,
        installed: installed.has(d.kind),
        builtIn: Boolean(d.builtIn),
      }))

    return html(reply, connectorsPage({ rows, available, counts: await counts(t.id), ...withActor(req) }))
  })

  /**
   * Create a connector, switched OFF.
   *
   * Deliberately NOT a signed action, and the split is the point: an inactive connector ingests
   * nothing, so creating one has no consequence. Turning it ON is signed, because that is the
   * moment data starts flowing. Routing the credential through a signed action would also mean
   * writing it into PendingAction.params in the clear, which is worse than the thing the signature
   * was protecting against.
   */
  app.post("/connectors/add", async (req, reply) => {
    const t = await tenant()
    if (!t) return reply.code(404).send({ error: "no tenant" })
    const body = req.body as Record<string, string>
    const def = connectorFor(String(body.kind ?? ""))
    if (!def) return reply.code(400).send({ error: "unknown connector" })
    if (def.builtIn) return reply.code(400).send({ error: "built-in connector cannot be added" })

    const missing = def.fields.filter((f) => f.required && !body[f.name]?.trim())
    if (missing.length > 0) {
      return reply.code(400).send({ error: `missing: ${missing.map((f) => f.label).join(", ")}` })
    }

    // Secret-marked fields go to the encrypted column; everything else is non-sensitive config.
    const secretField = def.fields.find((f) => f.secret)
    const configEntries = def.fields
      .filter((f) => !f.secret && f.name !== "label")
      .map((f) => [f.name, body[f.name] ?? ""] as const)

    let secret: string | null = secretField ? (body[secretField.name] ?? null) : null
    let generated: string | null = null
    if (isPush(def) && def.generatesSecret) {
      // This connector MINTS its secret rather than being given one: we generate it and the
      // producer is told, so nothing has to travel back. Shown exactly once, on the next response.
      generated = `whsec_${randomBytes(24).toString("base64url")}`
      secret = generated
    }

    const label = body.label?.trim() || def.label

    const created = await prisma.connection.create({
      data: {
        tenantId: t.id,
        kind: def.kind,
        label,
        builtIn: false,
        active: false,
        config: Object.fromEntries(configEntries),
        secretCiphertext: secret ? encryptSecret(secret) : null,
      },
      select: { id: true },
    })

    // Rendered from the POST rather than redirected with the secret in a query string: this
    // logger serialises req.url, so a secret in the URL would be written straight into the logs
    // (and into browser history, and into any proxy in front of us). It is shown once, here, and
    // never again — it exists nowhere in plaintext after this response.
    return html(
      reply,
      connectorCreatedPage({
        connection: created.id,
        def,
        secret: generated,
        base: `${req.protocol}://${req.headers.host}`,
      }),
    )
  })

  app.get("/detectors", async (req, reply) => {
    const t = await tenant()
    if (!t) return html(reply, onboardingPage())
    const cfg = await prisma.detectorConfig.findMany({ where: { tenantId: t.id } })
    const enabled = (name: string) => cfg.find((c) => c.detector === name)?.enabled ?? true
    return html(
      reply,
      detectorsPage({
        counts: await counts(t.id),
        ...withActor(req),
        rows: [
          {
            detector: "denial-burst",
            enabled: enabled("denial-burst"),
            description:
              "A subject refused far more than it usually is, judged against its own history — plus any action type it has never attempted before.",
            settings: `floor ≥ ${DEFAULT_BURST_CONFIG.floor}, ratio ≥ ${DEFAULT_BURST_CONFIG.ratio}×, window ${
              DEFAULT_BURST_CONFIG.windowMs / 60000
            }m`,
          },
          {
            detector: "sensitive-code-change",
            enabled: enabled("sensitive-code-change"),
            description:
              "A pull request touching receipt verification, gateway enforcement, canonicalization or tenant isolation — including a partial six-port mirror update.",
            settings: "component map + noise exclusions",
          },
          {
            detector: "deploy-regression",
            enabled: enabled("deploy-regression"),
            description:
              "A deployment followed by a shift in refusal or latency rates, correlated against whether the diff touched the implicated component.",
            settings: "30m post-deploy window vs 24h baseline",
          },
        ],
      }),
    )
  })

  app.get("/alerts", async (req, reply) => {
    const t = await tenant()
    if (!t) return html(reply, onboardingPage())
    const rules = await prisma.alertRule.findMany({
      where: { tenantId: t.id },
      orderBy: { createdAt: "desc" },
    })
    return html(reply, alertsPage({ rules, counts: await counts(t.id), ...withActor(req) }))
  })

  app.post("/alerts/create", async (req, reply) => {
    const t = await tenant()
    if (!t) return reply.code(404).send({ error: "no tenant" })
    const body = req.body as Record<string, string>
    const parsed = ALERT_RULE_INPUT.safeParse({
      ...body,
      cooldownMinutes: Number(body.cooldownMinutes ?? 60),
    })
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.issues[0]?.message })
    await createAlertRule(t.id, parsed.data)
    return reply.redirect("/alerts", 303)
  })

  app.get("/judgment", async (req, reply) => {
    const t = await tenant()
    if (!t) return html(reply, onboardingPage())

    const q = req.query as { page?: string }
    const pageNum = Math.max(1, parseInt(q.page ?? "1", 10) || 1)
    const pageSize = 10

    const [cfg, sampleList, totalCount, requests] = await Promise.all([
      prisma.detectorConfig.findUnique({
        where: { tenantId_detector: { tenantId: t.id, detector: "judgment" } },
      }),
      listFindings(t.id, { limit: 1 }),
      prisma.judgmentRequest.count({ where: { tenantId: t.id } }),
      prisma.judgmentRequest.findMany({
        where: { tenantId: t.id },
        orderBy: { createdAt: "desc" },
        skip: (pageNum - 1) * pageSize,
        take: pageSize,
        include: { finding: { select: { title: true } } },
      }),
    ])
    const totalPages = Math.max(1, Math.ceil(totalCount / pageSize))
    const sample = sampleList[0]
    const preview = sample
      ? previewRequest(projectForJudgment(sample, config.secretsEncKey), config.judgment.model)
      : "No findings yet — once one exists, this shows the exact request body that would be sent."

    const auditRows: JudgmentAuditRow[] = requests.map((r) => {
      const resp = r.response as {
        model?: string
        answers?: {
          anomalous?: { noul: number }
          severity?: { score: number; confidence: number }
        }
        usage?: { input_tokens: number; output_tokens: number }
      } | null
      return {
        id: r.id,
        createdAt: r.createdAt,
        findingId: r.findingId,
        findingTitle: r.finding?.title ?? "Finding",
        status: r.status,
        model: resp?.model ?? config.judgment.model,
        anomalous: resp?.answers?.anomalous?.noul,
        confidence: resp?.answers?.severity?.confidence,
        tokens: resp?.usage ?? null,
        stateDigest: r.stateDigest,
        lastError: r.lastError,
      }
    })

    return html(
      reply,
      judgmentPage({
        enabled: cfg?.enabled ?? false,
        configured: Boolean(config.judgment.apiKey),
        model: config.judgment.model,
        endpoint: config.judgment.endpoint,
        preview,
        requests: auditRows,
        pagination: {
          page: pageNum,
          pageSize,
          totalCount,
          totalPages,
        },
        counts: await counts(t.id),
        ...withActor(req),
      }),
    )
  })

  app.get("/members", async (req, reply) => {
    const t = await tenant()
    if (!t) return html(reply, onboardingPage())
    const rows = await prisma.member.findMany({
      where: { tenantId: t.id },
      orderBy: { createdAt: "asc" },
    })
    return html(reply, membersPage({ rows, counts: await counts(t.id), ...withActor(req) }))
  })

  app.get("/settings", async (req, reply) => {
    const t = await tenant()
    if (!t) return html(reply, onboardingPage())
    return html(
      reply,
      settingsPage({
        binding: {
          baseUrl: t.intygaBaseUrl,
          clientId: t.intygaClientId,
          rpId: t.intygaRpId,
          origin: t.intygaOrigin,
          hasKey: Boolean(t.intygaKeyCipher),
        },
        retentionDays: RETENTION_DAYS,
        counts: await counts(t.id),
        ...withActor(req),
      }),
    )
  })

  const BIND = z.object({
    baseUrl: z.url(),
    clientId: z.string().min(1).max(200),
    rpId: z.string().min(1).max(253),
    origin: z.url(),
    privateKey: z.string().min(1).max(8000),
    // Optional in the SCHEMA, required by the CHECK below when no administrator exists yet.
    //
    // Two paths reach this route. Signup: no tenant, so nobody could ever approve anything, and a
    // first administrator is mandatory. Settings: the tenant already has administrators, and asking
    // again would be noise. Requiring them unconditionally broke the second path; making them
    // optional unconditionally would allow a tenant that can approve nothing.
    adminExternalId: z
      .string()
      .min(1)
      .max(200)
      .regex(/^[A-Za-z0-9._:@+=-]+$/)
      .optional(),
    adminLabel: z.string().min(1).max(200).optional(),
  })

  app.post("/settings/bind", async (req, reply) => {
    const parsed = BIND.safeParse(req.body)
    if (!parsed.success) {
      // Re-render the signup with the reason rather than a bare 400: this is the first thing anyone
      // sees, and a JSON error body on a form post is a dead end.
      return html(reply, onboardingPage({ error: parsed.error.issues[0]?.message ?? "Invalid details" }))
    }
    const d = parsed.data
    // Binding is the SIGNUP step: before it there is no tenant, and therefore nobody who could
    // approve anything. It is the one privileged change that cannot itself be gated, which is
    // exactly why it can only ever run once — afterwards the gate exists.
    const existing = await tenant()
    const existingAdmins = existing
      ? await prisma.member.count({ where: { tenantId: existing.id, active: true } })
      : 0
    if (existingAdmins === 0 && !(d.adminExternalId && d.adminLabel)) {
      return html(
        reply,
        onboardingPage({
          error:
            "A first administrator is required — without one, nothing here could ever be approved, " +
            "including adding an administrator.",
        }),
      )
    }
    if (existing?.intygaKeyCipher) {
      // Already bound, so an administrator exists who could approve this. Repointing the workspace
      // is the one change that could hand the tenant to someone else, so it goes through the
      // signed path on /settings, never an unauthenticated form post.
      return reply.code(409).send({ error: "already connected — repointing requires an approved action" })
    }

    const data = {
      intygaBaseUrl: d.baseUrl,
      intygaClientId: d.clientId,
      intygaRpId: d.rpId,
      intygaOrigin: d.origin,
      intygaKeyCipher: encryptSecret(d.privateKey),
    }

    // Tenant, first administrator and the built-in Intyga connector are created together: a tenant
    // with no administrator can approve nothing, and one without its built-in connector would make
    // "the Intyga connector is built in" false on the only path that actually creates tenants.
    await prisma.$transaction(async (tx) => {
      const t = existing
        ? await tx.tenant.update({ where: { id: existing.id }, data, select: { id: true } })
        : await tx.tenant.create({
            data: { slug: "default", name: "default", ...data },
            select: { id: true },
          })

      if (d.adminExternalId && d.adminLabel) {
        await tx.member.upsert({
          where: { tenantId_externalId: { tenantId: t.id, externalId: d.adminExternalId } },
          create: { tenantId: t.id, externalId: d.adminExternalId, label: d.adminLabel },
          update: { label: d.adminLabel, active: true },
        })
      }

      const hasBuiltIn = await tx.connection.findFirst({
        where: { tenantId: t.id, kind: "intyga", builtIn: true },
        select: { id: true },
      })
      if (!hasBuiltIn) {
        await tx.connection.create({
          data: {
            tenantId: t.id,
            kind: "intyga",
            label: "INTYGA",
            builtIn: true,
            active: false,
            secretCiphertext: encryptSecret(`whsec_${randomBytes(24).toString("base64url")}`),
          },
        })
      }
    })

    return reply.redirect("/connectors", 303)
  })

  /**
   * Exercise the stored workspace binding.
   *
   * POST rather than GET: it makes an outbound request and invalidates a cached token, so it is not
   * safe to prefetch or retry blindly.
   */
  app.post("/settings/test", async (_req, reply) => {
    const t = await tenant()
    if (!t) return reply.code(404).send({ ok: false, error: "no tenant" })
    try {
      const cfg = resolveGateConfig(await tenantBinding(t.id))
      return await testConnection(cfg)
    } catch (err) {
      return { ok: false, error: (err as Error).message }
    }
  })

  /**
   * Replace the signing key without changing which workspace this tenant belongs to.
   *
   * Deliberately NOT a signed action. Signing it would require the key being replaced to still
   * work, so a compromised or expired key could never be rotated — the failure mode the rotation
   * exists for. It changes no identity and grants no access: a key the workspace does not trust
   * simply fails at the next token exchange, which `/settings/test` will show immediately.
   */
  app.post("/settings/key", async (req, reply) => {
    const t = await tenant()
    if (!t) return reply.code(404).send({ error: "no tenant" })
    const parsed = z.object({ privateKey: z.string().min(1).max(8000) }).safeParse(req.body)
    if (!parsed.success) return reply.code(400).send({ error: "invalid key" })
    await prisma.tenant.update({
      where: { id: t.id },
      data: { intygaKeyCipher: encryptSecret(parsed.data.privateKey) },
    })
    return reply.redirect("/settings", 303)
  })

  // ─── privileged actions ────────────────────────────────────────────────────────────────────────

  const OPEN = z.object({ action: z.string().min(1).max(120), params: z.record(z.string(), z.unknown()) })
  const COMPLETE = z.object({ nonce: z.string().min(1).max(200), assertion: z.unknown() })

  app.post("/api/actions/open", async (req, reply) => {
    const t = await tenant()
    if (!t) return reply.code(404).send({ error: "no tenant" })
    const parsed = OPEN.safeParse(json(req))
    if (!parsed.success) return reply.code(400).send({ error: "invalid request" })
    try {
      // The actor is whoever is signed in — never "the first administrator". Approving as someone
      // else would make the signature prove nothing about who authorised the change.
      const actor = actorOf(req)
      if (!actor) return reply.code(401).send({ error: "not signed in" })
      return await openAction({
        tenantId: t.id,
        actorExternalId: actor.externalId,
        action: parsed.data.action,
        params: parsed.data.params,
      })
    } catch (err) {
      const message = err instanceof Error ? err.message : "could not open approval"
      return reply.code(err instanceof ActionError ? 400 : 502).send({ error: message })
    }
  })

  app.post("/api/actions/complete", async (req, reply) => {
    const t = await tenant()
    if (!t) return reply.code(404).send({ error: "no tenant" })
    const parsed = COMPLETE.safeParse(json(req))
    if (!parsed.success) return reply.code(400).send({ error: "invalid request" })
    try {
      return await completeAction({
        tenantId: t.id,
        nonce: parsed.data.nonce,
        assertion: parsed.data.assertion,
      })
    } catch (err) {
      const message = err instanceof Error ? err.message : "the approval was refused"
      return reply.code(err instanceof ActionError ? 400 : 502).send({ error: message })
    }
  })

  // ─── findings API ──────────────────────────────────────────────────────────────────────────────

  const FEEDBACK = z.object({
    actor: z.string().min(1).max(200),
    verdict: z.enum(["useful", "not_useful", "investigating", "expected", "false_positive", "fixed"]),
    note: z.string().max(2000).optional(),
  })

  app.get("/api/findings", async (req) => {
    const t = await tenant()
    if (!t) return { findings: [] }
    const q = req.query as { status?: string; limit?: string }
    const opts: { status?: string[]; limit?: number } = {}
    if (q.status) opts.status = q.status.split(",")
    if (q.limit) opts.limit = Math.min(Number(q.limit) || 100, 500)
    return { findings: await listFindings(t.id, opts) }
  })

  app.post("/api/findings/:id/feedback", async (req, reply) => {
    const t = await tenant()
    if (!t) return reply.code(404).send({ error: "not found" })
    const parsed = FEEDBACK.safeParse(json(req))
    if (!parsed.success) return reply.code(400).send({ error: "invalid feedback" })
    const { id } = req.params as { id: string }
    const ok = await recordFeedback(t.id, id, {
      actor: parsed.data.actor,
      verdict: parsed.data.verdict as FeedbackVerdict,
      ...(parsed.data.note !== undefined ? { note: parsed.data.note } : {}),
    })
    if (!ok) return reply.code(404).send({ error: "not found" })
    return { ok: true }
  })

  return app
}

export { tenantBinding }
