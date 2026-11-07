import { randomBytes } from "node:crypto"
import { existsSync, writeFileSync } from "node:fs"
import path from "node:path"

export function publicOrigin(value: string): string {
  const url = new URL(value)
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)
  if (
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== "/" ||
    !(url.protocol === "https:" || (url.protocol === "http:" && local))
  ) {
    throw new Error(
      "Use an HTTPS origin with no path, credentials or query, or HTTP localhost for local use.",
    )
  }
  return url.origin
}

/** Creates new installation secrets only. Existing secrets must never be silently rotated. */
export function initialiseSelfHost(directory: string, origin: string, port = 4100): void {
  const base = publicOrigin(origin)
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error("Port must be 1024–65535")
  const envPath = path.join(directory, ".env.selfhost")
  if (existsSync(envPath))
    throw new Error(
      "Self-host configuration already exists; keep it for upgrades. Refusing to rotate secrets.",
    )
  // No key material: Intelligence holds no signing key of its own. The INTYGA credentials (an OIDC
  // client id, a service key and the exported trust anchor) are entered in the setup form after the
  // stack is up, and stored encrypted under SECRETS_ENC_KEY.
  writeFileSync(
    envPath,
    [
      "# Generated locally. Back up this file securely; do not commit it.",
      `PUBLIC_URL=${base}`,
      `SELFHOST_HTTP_PORT=${port}`,
      `POSTGRES_PASSWORD=${randomBytes(32).toString("hex")}`,
      `SECRETS_ENC_KEY=${randomBytes(32).toString("base64")}`,
      `SETUP_TOKEN=${randomBytes(32).toString("hex")}`,
      `TICK_TOKEN=${randomBytes(32).toString("hex")}`,
      "INTYGA_CONSOLE_URL=https://app.intyga.com",
      "",
    ].join("\n"),
    { flag: "wx", mode: 0o600 },
  )
}
