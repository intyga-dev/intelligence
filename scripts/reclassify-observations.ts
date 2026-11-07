import "../src/loadenv.ts"
import { prisma } from "../src/store/client.ts"
import { reclassifyObservations } from "../src/store/reclassifyObservations.ts"

const tenantId = process.argv[2]
if (!tenantId || !/^[0-9a-f-]{36}$/i.test(tenantId)) {
  throw new Error("Usage: pnpm exec tsx scripts/reclassify-observations.ts <tenant-id> [--apply]")
}
try {
  console.log(JSON.stringify(await reclassifyObservations(tenantId, process.argv.includes("--apply"))))
} finally {
  await prisma.$disconnect()
}
