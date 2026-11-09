import path from "node:path"
import { fileURLToPath } from "node:url"
import { config as loadEnv } from "dotenv"
import { defineConfig, env } from "prisma/config"

const here = path.dirname(fileURLToPath(import.meta.url))
loadEnv({ path: path.resolve(here, ".env") })

// Prisma 7 keeps CLI connection URLs here rather than in the schema. DIRECT_URL bypasses any
// connection pooler, which schema changes require; runtime queries use the adapter instead.
export default defineConfig({
  schema: "prisma/schema.prisma",
  migrations: { path: "prisma/migrations" },
  datasource: { url: env("DIRECT_URL") },
})
