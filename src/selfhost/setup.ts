import { generateKeyPairSync, randomBytes } from "node:crypto"
import { mkdirSync, writeFileSync, existsSync, rmSync } from "node:fs"
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

/** Creates new installation material only. Existing secrets must never be silently rotated. */
export function initialiseSelfHost(directory: string, origin: string, port = 4100): void {
  const base = publicOrigin(origin)
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error("Port must be 1024–65535")
  const envPath = path.join(directory, ".env.selfhost")
  const keyDir = path.join(directory, ".selfhost")
  if (existsSync(envPath) || existsSync(keyDir))
    throw new Error(
      "Self-host configuration already exists; keep it for upgrades. Refusing to rotate secrets.",
    )
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" })
  const written: string[] = []
  try {
    mkdirSync(keyDir, { mode: 0o700 })
    written.push(keyDir)
    writeFileSync(path.join(keyDir, "rp.pk8"), privateKey.export({ type: "pkcs8", format: "pem" }), {
      flag: "wx",
      mode: 0o600,
    })
    writeFileSync(
      path.join(keyDir, "rp-public.txt"),
      `${publicKey.export({ type: "spki", format: "der" }).toString("base64")}\n`,
      { flag: "wx", mode: 0o600 },
    )
    writeFileSync(
      envPath,
      [
        "# Generated locally. Back up this file and .selfhost/ securely; do not commit them.",
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
    written.push(envPath)
  } catch (error) {
    for (const file of written.reverse()) rmSync(file, { recursive: true, force: true })
    throw error
  }
}
