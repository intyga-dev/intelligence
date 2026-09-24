// The detectors this build ships, and how the console describes them.
//
// One list, read by the tick (what runs), the signed on/off actions (what may be switched) and the
// detectors page (what is shown). A detector that is not in this list does not exist anywhere —
// which is the point: the console once listed two detectors that had no code behind them.

export const DETECTORS = ["denial-burst", "sensitive-code-change", "deploy-regression"] as const
export type DetectorId = (typeof DETECTORS)[number]

export const DETECTOR_INFO: Readonly<Record<DetectorId, { description: string; needs: string }>> = {
  "denial-burst": {
    description:
      "A subject refused far more than it usually is, judged against its own history — plus any action type it has never attempted before.",
    needs: "INTYGA connector",
  },
  "sensitive-code-change": {
    description:
      "A pull request touching security-sensitive code — authentication, authorization, crypto, migrations, infrastructure, CI — and, with a map that declares one, a partial update of code that must change together.",
    needs: "GitHub or GitLab connector",
  },
  "deploy-regression": {
    description:
      "Errors, machine crashes, incidents or the approval refusal rate rising in the 30 minutes after a production deploy, against the 24 hours before — with the shipped pull request and whether it touched sensitive code.",
    needs:
      "a deploy source (GitHub, GitLab, Vercel, Netlify, Cloudflare Pages, custom) and a signal source (Sentry, Fly, PagerDuty, Opsgenie, Datadog, INTYGA, custom)",
  },
}
