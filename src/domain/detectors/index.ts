// The detectors this build ships, and how the console describes them.
//
// One list, read by the tick (what runs), the signed on/off actions (what may be switched) and the
// detectors page (what is shown). A detector that is not in this list does not exist anywhere —
// which is the point: the console once listed two detectors that had no code behind them.

export const DETECTORS = [
  "denial-burst",
  "sensitive-code-change",
  "deploy-regression",
  "metrics-health",
  "collection-health",
  "ci-health",
  "merge-policy",
  "job-overdue",
  "service-degradation",
  "provider-alerts",
] as const
export type DetectorId = (typeof DETECTORS)[number]

export const DETECTOR_INFO: Readonly<Record<DetectorId, { description: string; needs: string }>> = {
  "provider-alerts": {
    description:
      "Imports medium-or-higher provider alerts with evidence. Explicit recovery resolves the matching finding; silence never means recovery.",
    needs: "AWS, Google Cloud, Workspace, Azure, Grafana, Alertmanager, Stripe or Better Stack",
  },
  "collection-health": {
    description:
      "Consecutive failed polls across any polling connector, and recorded collection gaps when polling resumes. Quiet webhooks are not failures.",
    needs: "an active polling connector",
  },
  "ci-health": {
    description:
      "Repeated or prolonged failures of configured workflows on a monitored branch. Later successes supersede failures; cancelled and feature-branch runs are ignored.",
    needs: "configured workflows, GitHub Actions or signed CI events",
  },
  "merge-policy": {
    description:
      "GitHub explicitly recorded a bypass with failed active review or required-check rules. Reports the exception for review, not an inferred violation from absent data.",
    needs: "configured repositories and GitHub Administration read permission",
  },
  "job-overdue": {
    description:
      "A backup, scheduled task, sync or integrity check missed its configured successful-completion interval and grace period. Maintenance windows suppress detection.",
    needs: "configured job expectations and signed job completion events",
  },
  "service-degradation": {
    description:
      "An error or latency objective burns its error budget too quickly in both short and long windows, with complete samples and minimum traffic.",
    needs: "configured service objectives and signed one-minute request aggregates",
  },
  "metrics-health": {
    description:
      "New failures in known INTYGA health counters, or broken ledger blocks/checkpoints. Ignores initial counter values, resets and gaps over 15 minutes. Only bare metric queries are evaluated.",
    needs: "Metrics connector with the default INTYGA queries",
  },
  "denial-burst": {
    description:
      "A subject refused far more than it usually is, judged against its own history — plus any action type it has never attempted before.",
    needs: "INTYGA connector",
  },
  "sensitive-code-change": {
    description:
      "Review observations for pull requests touching sensitive paths. Path matches alone do not trigger alerts or anomaly scoring. A configured mirror rule can separately flag incomplete cross-port updates.",
    needs: "GitHub or GitLab connector",
  },
  "deploy-regression": {
    description:
      "Errors, machine crashes, incidents or the approval refusal rate rising in the 30 minutes after a production deploy, against the 24 hours before — with the shipped pull request and whether it touched sensitive code.",
    needs:
      "a deploy source (GitHub, GitLab, Vercel, Netlify, Cloudflare Pages, custom) and a signal source (Sentry, Fly, PagerDuty, Opsgenie, Datadog, INTYGA, custom)",
  },
}
