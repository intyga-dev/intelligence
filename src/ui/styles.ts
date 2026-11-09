// Server-rendered HTML has no CSS import transformer. Serve component styles as separate assets.
// Only these files are public; URL parameters are never used as filesystem paths.
export const STYLESHEETS = [
  "theme",
  "charts",
  "auth",
  "approval",
  "feedback",
  "findings",
  "connector-edit",
  "services",
  "findings-page",
  "operational-settings",
  "connectors",
] as const
export type Stylesheet = (typeof STYLESHEETS)[number]

export function stylesheetLinks(...names: Stylesheet[]): string {
  return names.map((name) => `<link rel="stylesheet" href="/assets/ui/${name}.module.css">`).join("\n")
}
