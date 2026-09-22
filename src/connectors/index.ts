// Connector registration.
//
// Imported for its side effect, once, at startup. Adding a source is: write the definition, add one
// line here. Nothing else in the codebase learns a new name — the ingest route, the tick job and
// the admin UI all resolve through the registry.

import { flyConnector } from "./fly/index.ts"
import { githubConnector } from "./github/index.ts"
import { intygaConnector } from "./intyga/index.ts"
import { metricsConnector } from "./metrics/index.ts"
import { registerConnector } from "./registry.ts"
import { sentryConnector } from "./sentry/index.ts"
import { vercelConnector } from "./vercel/index.ts"

registerConnector(intygaConnector)
registerConnector(githubConnector)
registerConnector(metricsConnector)
registerConnector(sentryConnector)
registerConnector(flyConnector)
registerConnector(vercelConnector)

export { allConnectors, connectorFor, isPoll, isPush } from "./registry.ts"
