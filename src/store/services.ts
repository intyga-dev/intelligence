import { prisma } from "./client.ts"
import { countFindings, listFindings } from "./repo.ts"

export async function listServices(tenantId: string) {
  const rows = await prisma.service.findMany({
    where: { tenantId },
    orderBy: { name: "asc" },
    include: { connections: { where: { removedAt: null }, select: { id: true, label: true, active: true } } },
  })
  return Promise.all(
    rows.map(async (service) => {
      const [open, lastEvent] = await Promise.all([
        countFindings(tenantId, { kind: "finding", serviceId: service.id, status: ["new", "investigating"] }),
        prisma.event.findFirst({
          where: { tenantId, serviceId: service.id },
          orderBy: { at: "desc" },
          select: { at: true },
        }),
      ])
      return { ...service, open, lastEventAt: lastEvent?.at ?? null }
    }),
  )
}

export async function serviceDetail(tenantId: string, id: string, now = new Date()) {
  const service = await prisma.service.findFirst({
    where: { tenantId, id },
    include: {
      connections: {
        where: { removedAt: null },
        select: { id: true, label: true, kind: true, active: true },
      },
    },
  })
  if (!service) return null
  const since = new Date(now.getTime() - 7 * 86400_000)
  const [findings, events, totalEvents] = await Promise.all([
    listFindings(tenantId, { kind: "finding", serviceId: id, status: ["new", "investigating"], limit: 20 }),
    prisma.event.findMany({
      where: { tenantId, serviceId: id, at: { gte: since, lte: now } },
      orderBy: [{ at: "desc" }, { id: "asc" }],
      take: 100,
      select: {
        id: true,
        kind: true,
        at: true,
        source: true,
        attrs: true,
        correlationRef: true,
        connection: { select: { label: true } },
      },
    }),
    prisma.event.count({ where: { tenantId, serviceId: id, at: { gte: since, lte: now } } }),
  ])
  return { service, findings, events, totalEvents }
}

export type ServiceSummary = Awaited<ReturnType<typeof listServices>>[number]
export type ServiceDetail = NonNullable<Awaited<ReturnType<typeof serviceDetail>>>
