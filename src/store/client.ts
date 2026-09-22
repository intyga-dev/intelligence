import { PrismaPg } from "@prisma/adapter-pg"
import { PrismaClient } from "../generated/prisma/client.ts"

// One client for the process. Prisma 7 takes the connection through a driver adapter rather than a
// URL in the schema, which is also what keeps the CLI's migration connection separate from the
// runtime one.
//
// There is no owner/app split here and no row-level security, unlike the system this observes —
// this database has a single trusted writer. Tenant isolation is therefore carried entirely by the
// query layer in repo.ts, where every function takes a tenantId and no query omits it.

const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL })

export const prisma = new PrismaClient({ adapter })

export async function disconnect(): Promise<void> {
  await prisma.$disconnect()
}
