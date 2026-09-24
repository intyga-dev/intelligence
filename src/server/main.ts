import "../loadenv.ts"
import { config } from "../config.ts"
import { disconnect } from "../store/client.ts"
import { buildApp } from "./app.ts"

// Entrypoint. Owns the socket and the shutdown sequence; buildApp() owns the routes, so tests can
// drive the app with inject() without ever binding a port.

// Fail closed at BOOT. config.ts resolves these lazily — deliberately, so a unit test that imports one
// connector does not need a database URL or production secrets — which meant a misconfigured server
// started, passed a liveness check, and threw only at the first tick or the first encrypted write.
// The server is the one place that must refuse to start without them. Names only are logged.
try {
  void config.databaseUrl
  void config.tickToken
  void config.secretsEncKey
  // Unset is legitimate (browser setup off); a placeholder or short value in production throws.
  void config.setupToken
} catch (err) {
  console.error(`refusing to start: ${(err as Error).message}`)
  process.exit(1)
}

const app = buildApp()

async function shutdown(signal: string): Promise<void> {
  app.log.info({ signal }, "shutting down")
  try {
    // Close the server first so in-flight requests finish before the database goes away —
    // the reverse order turns a graceful deploy into a burst of 500s.
    await app.close()
    await disconnect()
    process.exit(0)
  } catch (err) {
    app.log.error({ err: (err as Error).message }, "unclean shutdown")
    process.exit(1)
  }
}

for (const sig of ["SIGTERM", "SIGINT"] as const) {
  process.on(sig, () => void shutdown(sig))
}

try {
  // "::" so the container listens on both stacks; Fly and most orchestrators route over IPv6.
  await app.listen({ port: config.port, host: "::" })
  app.log.info(
    { port: config.port, judgment: config.judgment.apiKey ? "configured" : "null-provider" },
    "intelligence listening",
  )
} catch (err) {
  app.log.error({ err: (err as Error).message }, "failed to start")
  process.exit(1)
}
