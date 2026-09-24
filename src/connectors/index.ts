// Connector registration.
//
// Imported for its side effect, once, at startup. Adding a source is: write the definition, add one
// line here. Nothing else in the codebase learns a new name — the ingest route, the tick job and
// the admin UI all resolve through the registry.

import { cloudflareConnector } from "./cloudflare/index.ts"
import { datadogConnector } from "./datadog/index.ts"
import { flyConnector } from "./fly/index.ts"
import { githubConnector } from "./github/index.ts"
import { gitlabConnector } from "./gitlab/index.ts"
import { intygaConnector } from "./intyga/index.ts"
import { metricsConnector } from "./metrics/index.ts"
import { netlifyConnector } from "./netlify/index.ts"
import { opsgenieConnector } from "./opsgenie/index.ts"
import { pagerdutyConnector } from "./pagerduty/index.ts"
import { registerConnector } from "./registry.ts"
import { sentryConnector } from "./sentry/index.ts"
import { vercelConnector } from "./vercel/index.ts"
import { webhookConnector } from "./webhook/index.ts"

registerConnector(intygaConnector)
registerConnector(githubConnector)
registerConnector(metricsConnector)
registerConnector(sentryConnector)
registerConnector(flyConnector)
registerConnector(vercelConnector)
registerConnector(webhookConnector)
registerConnector(gitlabConnector)
registerConnector(pagerdutyConnector)
registerConnector(opsgenieConnector)
registerConnector(datadogConnector)
registerConnector(cloudflareConnector)
registerConnector(netlifyConnector)

export { allConnectors, connectorFor, isPoll, isPush } from "./registry.ts"
