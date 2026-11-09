import { createHash } from "node:crypto"
import { readFileSync, statSync } from "node:fs"
import { publicOrigin } from "../selfhost/setup.ts"
import { GateNotConfigured, type GateConfig, parseTrustAnchor } from "./client.ts"

export interface DeploymentConfig extends GateConfig {
  embeddedApplicationId?: string
  oidcClientId: string | null
  origin: string
  /** Public identity fingerprint: old sessions and pending actions cannot cross a deployment rebind. */
  bindingId: string
}

export type DeploymentConnection = Omit<DeploymentConfig, "trustAnchor">

/** Deployment-controlled configuration only. No database value can override these settings. */
export function resolveConnectionConfig(env: NodeJS.ProcessEnv = process.env): DeploymentConnection {
  const required = (name: string): string => {
    const value = env[name]?.trim()
    if (!value) throw new GateNotConfigured(`Set ${name} in the server environment and restart.`)
    return value
  }
  const origin = (name: string): string => {
    try {
      return publicOrigin(required(name))
    } catch {
      throw new GateNotConfigured(`Set ${name} to an HTTPS origin (HTTP localhost is allowed).`)
    }
  }
  const baseUrl = origin("INTYGA_URL")
  const consoleUrl = origin("INTYGA_CONSOLE_URL")
  const workspaceId = required("INTYGA_WORKSPACE_ID")
  const embeddedApplicationId = env.INTYGA_EMBEDDED_APPLICATION_ID?.trim()
  if (embeddedApplicationId && !/^[0-9a-f-]{36}$/i.test(embeddedApplicationId))
    throw new GateNotConfigured("Set INTYGA_EMBEDDED_APPLICATION_ID to the registered application UUID.")
  const oidcClientId = env.INTYGA_OIDC_CLIENT_ID?.trim() || null
  const serviceClientId = required("INTYGA_SERVICE_CLIENT_ID")
  const serviceSecret = required("INTYGA_SERVICE_CLIENT_SECRET")
  const publicUrl = origin("PUBLIC_URL")
  return {
    ...(embeddedApplicationId ? { embeddedApplicationId } : {}),
    baseUrl,
    consoleUrl,
    workspaceId,
    oidcClientId,
    serviceClientId,
    serviceSecret,
    origin: publicUrl,
    bindingId: createHash("sha256")
      .update(
        JSON.stringify([
          baseUrl,
          workspaceId,
          oidcClientId,
          serviceClientId,
          publicUrl,
          embeddedApplicationId ?? null,
        ]),
      )
      .digest("hex"),
  }
}

/** A usable anchor is mandatory for sign-in and execution, but not first-time member linking. */
export function resolveGateConfig(env: NodeJS.ProcessEnv = process.env): DeploymentConfig {
  const connection = resolveConnectionConfig(env)
  const anchorPath = env.INTYGA_TRUST_ANCHOR_FILE?.trim() ?? ""
  let raw: string
  try {
    if (statSync(anchorPath).size > 200_000) throw new Error("too large")
    raw = readFileSync(anchorPath, "utf8")
  } catch {
    throw new GateNotConfigured(
      "INTYGA_TRUST_ANCHOR_FILE must name a readable trust anchor file (up to 200 KB).",
    )
  }
  const parsed = parseTrustAnchor(raw)
  if (!parsed.ok) throw new GateNotConfigured(parsed.error)
  if (parsed.anchor.tenantId !== connection.workspaceId)
    throw new GateNotConfigured("The trust anchor must name INTYGA_WORKSPACE_ID.")
  if (
    connection.embeddedApplicationId &&
    (parsed.anchor.webauthn?.origin !== connection.origin ||
      parsed.anchor.webauthn.rpId !== new URL(connection.origin).hostname)
  )
    throw new GateNotConfigured(
      "Export the application trust anchor from INTYGA Member applications and mount it before signing in.",
    )
  return { ...connection, trustAnchor: parsed.anchor }
}

export function deploymentStatus():
  | { configured: true; config: DeploymentConfig }
  | { configured: false; error: string } {
  try {
    return { configured: true, config: resolveGateConfig() }
  } catch (err) {
    return {
      configured: false,
      error: err instanceof GateNotConfigured ? err.message : "Invalid INTYGA configuration.",
    }
  }
}
