// Load .env before anything reads process.env.
//
// Imported for its side effect at the top of every entrypoint (server, scripts). Deliberately a
// separate module rather than a line inside config.ts: import order is what makes this work, and a
// side-effect import is visible at the top of a file in a way a buried call is not.
import { config as loadEnv } from "dotenv"
import path from "node:path"
import { fileURLToPath } from "node:url"

const here = path.dirname(fileURLToPath(import.meta.url))
loadEnv({ path: path.resolve(here, "..", ".env"), quiet: true })
