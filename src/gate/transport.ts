import { config } from "../config.ts"

/** Route one operator-configured gateway internally without changing its public OIDC issuer. */
export function gatewayTransportUrl(
  baseUrl: string,
  routing: { publicUrl: string | null; internalUrl: string | null } = {
    publicUrl: config.intyga.baseUrl,
    internalUrl: config.intyga.internalUrl,
  },
): string {
  // A later workspace rebind to another gateway must not inherit the old internal route.
  return routing.internalUrl && routing.publicUrl?.replace(/\/$/, "") === baseUrl.replace(/\/$/, "")
    ? routing.internalUrl
    : baseUrl
}
