// Which parts of a connected repository are security-sensitive, and what a changed-file list means.
//
// Pure and data-driven on purpose: the map is CONFIG, so adding a component is an edit to a table
// rather than a change to matching logic. Everything here is a FACT about a diff — no judgement,
// no model. The semantic question ("does this change actually affect authorization?") is asked
// separately, of a judgment provider, and only after these facts are established.

/** A named area of a codebase whose behaviour we care about changing. Unique within one map. */
export type ComponentId = string

export interface Component {
  id: ComponentId
  /** Why a change here deserves a human, in one line. Rendered in the finding. */
  rationale: string
  /** Severity floor for a change touching this component, before any model input. */
  floor: "medium" | "high" | "critical"
  patterns: string[]
}

/**
 * Paths that match a component glob but carry no behaviour.
 *
 * Measured, not guessed: running this map over intyga-dev/core PR #100 (89 files) matched 25 paths,
 * a third of which were CHANGELOG.md, README.md, go.sum and Cargo.lock. A map that fires on a
 * changelog trains people to ignore the list, which is worse than not having one.
 *
 * `**` + vectors/*.json is deliberately NOT here: a changed pinned vector means the canonical
 * payload moved, which is the highest-signal diff in a spec-mirrored repository.
 */
export const NOISE_PATTERNS: readonly string[] = [
  "**/CHANGELOG.md",
  "**/README.md",
  "**/README.*.md",
  "**/LICENSE",
  "**/*.lock",
  "**/go.sum",
  "**/go.mod",
  "**/Cargo.toml",
  "**/package.json",
  "**/*.test.ts",
  "**/*.test.tsx",
  "**/*_test.go",
  "**/*.md",
]

/**
 * The component map for the INTYGA monorepo itself (`intyga-dev/core`).
 *
 * Exact paths, measured against real pull requests. It is the worked example of a tuned map, and it
 * is only right for that one repository: anywhere else it matches nothing. Select it per GitHub
 * connection (`pathMap: intyga-core`); every other repository gets `GENERIC_COMPONENTS`.
 */
export const COMPONENTS: readonly Component[] = [
  {
    id: "receipt-verification",
    rationale: "Changes what a relying party accepts as a valid approval receipt.",
    floor: "critical",
    patterns: [
      "packages/verify/src/**",
      "packages/verify-*/src/**",
      "packages/verify-*/**/*.go",
      "packages/verify-*/**/*.rs",
      "packages/verify-*/**/*.java",
    ],
  },
  {
    id: "canonicalization",
    rationale: "Changes the exact bytes a human signs. A mismatch invalidates receipts silently.",
    floor: "critical",
    patterns: [
      "packages/mcp-schemas/src/**",
      "packages/mcp-schemas/vectors/**",
      "**/ledger-leaf.*",
      "**/checkpoint.ts",
    ],
  },
  {
    id: "gateway-enforcement",
    rationale: "Changes what the gateway permits, refuses, or auto-approves.",
    floor: "critical",
    patterns: [
      "apps/gateway/src/authorization.ts",
      "apps/gateway/src/evaluator.ts",
      "apps/gateway/src/approval-policy.ts",
      "apps/gateway/src/approvalMatch.ts",
      "apps/gateway/src/authorityBoundary.ts",
      "apps/gateway/src/agentAuthority.ts",
      "apps/gateway/src/auth.ts",
      "apps/gateway/src/scopes.ts",
      "apps/gateway/src/platform/signing.ts",
    ],
  },
  {
    id: "tenant-isolation",
    rationale: "Changes the boundary between one customer's data and another's.",
    floor: "critical",
    patterns: ["**/rls.sql", "packages/db/src/tenant.ts", "packages/db/src/client.ts"],
  },
  {
    id: "step-up",
    rationale: "Changes whether a console mutation requires a fresh signature.",
    floor: "high",
    patterns: ["apps/web/lib/step-up.ts", "apps/web/lib/auth.ts", "apps/web/app/**/actions.ts"],
  },
  {
    id: "crypto",
    rationale: "Changes key handling, signing or encryption-at-rest.",
    floor: "high",
    patterns: [
      "apps/gateway/src/crypto.ts",
      "apps/gateway/src/secrets.ts",
      "**/crypto-at-rest.ts",
      "apps/gateway/src/webauthn.ts",
    ],
  },
  {
    id: "policy",
    rationale: "Changes how policy is relayed or how its freshness is judged.",
    floor: "high",
    patterns: ["apps/gateway/src/policyRelay.ts", "apps/gateway/src/policyHash.ts"],
  },
  {
    id: "ci-supply-chain",
    rationale: "Changes what the build gate checks, or what it is allowed to publish.",
    floor: "medium",
    patterns: [".github/workflows/**", "scripts/check-*.mjs"],
  },
]

/**
 * The six ports the canonical payload builder is mirrored across.
 *
 * Source: the host repository's own contributor guide — "Any change must update all six and the
 * pinned vectors together". That makes a PARTIAL mirror update a defect detectable with nothing but
 * a file list, which is why it gets its own rule rather than being folded into the component map.
 */
export const MIRROR_PORTS: Readonly<Record<string, string[]>> = Object.freeze({
  "mcp-schemas": ["packages/mcp-schemas/src/**"],
  verify: ["packages/verify/src/**"],
  "verify-go": ["packages/verify-go/**"],
  "verify-rust": ["packages/verify-rust/src/**"],
  "verify-java": ["packages/verify-java/src/**"],
  "sdk-python": ["packages/sdk-python/**"],
})

export const MIRROR_VECTOR_PATTERNS: readonly string[] = ["packages/mcp-schemas/vectors/**"]

/**
 * A map for any repository, by naming convention rather than by measured path.
 *
 * Deliberately a heuristic, and labelled as one: it cannot know that `billing/limits.ts` is where
 * YOUR authorization lives. What it can do is flag the names security-relevant code conventionally
 * carries — auth, sessions, permissions, crypto, migrations, CI — so that a change there reaches a
 * human rather than being one line in a merge queue. Substrings were chosen against false matches
 * that actually occur in code (`*acl*` is in "oracle", `*iam*` is in "diameter", `*token*` is in
 * "tokenizer"), so those appear only as directory names.
 */
export const GENERIC_COMPONENTS: readonly Component[] = [
  {
    id: "authentication",
    rationale: "Changes how users or services prove who they are, or how sessions are issued.",
    floor: "high",
    patterns: [
      "**/auth/**",
      "**/authn/**",
      "**/login/**",
      "**/oauth/**",
      "**/oidc/**",
      "**/sso/**",
      "**/saml/**",
      "**/sessions/**",
      "**/*auth*.*",
      "**/*session*.*",
      "**/*login*.*",
      "**/*password*.*",
      "**/*jwt*.*",
    ],
  },
  {
    id: "authorization",
    rationale: "Changes who is allowed to do what.",
    floor: "high",
    patterns: [
      "**/authz/**",
      "**/rbac/**",
      "**/acl/**",
      "**/permissions/**",
      "**/policies/**",
      "**/guards/**",
      "**/middleware/**",
      "**/middleware.*",
      "**/*permission*.*",
      "**/*policy*.*",
      "**/*rbac*.*",
      "**/*guard*.*",
    ],
  },
  {
    id: "crypto-and-secrets",
    rationale: "Changes key handling, signing, hashing or encryption.",
    floor: "high",
    patterns: [
      "**/crypto/**",
      "**/*crypto*.*",
      "**/*encrypt*.*",
      "**/*cipher*.*",
      "**/*signing*.*",
      "**/*secret*.*",
      "**/*.pem",
      "**/*.key",
    ],
  },
  {
    id: "data-schema",
    rationale: "Changes the shape of stored data, or the rules that protect it.",
    floor: "medium",
    patterns: ["**/migrations/**", "**/*.sql", "**/*.prisma"],
  },
  {
    id: "infrastructure-access",
    rationale: "Changes infrastructure, network exposure or cloud permissions.",
    floor: "medium",
    patterns: [
      "**/*.tf",
      "**/*.tfvars",
      "**/terraform/**",
      "**/iam/**",
      "**/k8s/**",
      "**/kubernetes/**",
      "**/helm/**",
      "**/Dockerfile",
      "**/docker-compose*.yml",
      "**/fly.toml",
      "**/vercel.json",
    ],
  },
  {
    id: "ci-supply-chain",
    rationale: "Changes what the build gate checks, or what it is allowed to publish.",
    floor: "medium",
    patterns: [
      ".github/workflows/**",
      ".github/actions/**",
      ".github/CODEOWNERS",
      "CODEOWNERS",
      ".gitlab-ci.yml",
      ".circleci/**",
      "**/Jenkinsfile",
    ],
  },
]

/** One named component map, with an optional mirror rule. */
export interface PathMap {
  id: "generic" | "intyga-core"
  components: readonly Component[]
  /**
   * Sets of paths that must change together. Only a map that KNOWS its repository has one: the
   * rule reasons from absence, which is only safe when the list of ports is a fact, not a guess.
   */
  mirror?: { ports: Readonly<Record<string, string[]>>; vectorPatterns: readonly string[] }
}

export const PATH_MAPS: Readonly<Record<PathMap["id"], PathMap>> = Object.freeze({
  generic: { id: "generic", components: GENERIC_COMPONENTS },
  "intyga-core": {
    id: "intyga-core",
    components: COMPONENTS,
    mirror: { ports: MIRROR_PORTS, vectorPatterns: MIRROR_VECTOR_PATTERNS },
  },
})

/** Resolve a connection's configured map. Anything unrecognised is the generic map, never nothing. */
export function pathMapFor(id: unknown): PathMap {
  return id === "intyga-core" ? PATH_MAPS["intyga-core"] : PATH_MAPS.generic
}

// ─── Matching ────────────────────────────────────────────────────────────────────────────────────

/**
 * Minimal glob matcher: `**` spans separators, `*` does not, `?` is one non-separator character.
 *
 * Deliberately hand-rolled rather than a dependency. The patterns above are the only input this
 * ever sees, the semantics fit in one regex, and a path matcher is precisely the kind of thing you
 * want to be able to read in full when it decides whether a security finding fires.
 */
export function matchesGlob(path: string, pattern: string): boolean {
  const re = pattern
    .split(/(\*\*\/|\*\*|\*|\?)/)
    .map((part) => {
      if (part === "**/") return "(?:.*/)?"
      if (part === "**") return ".*"
      if (part === "*") return "[^/]*"
      if (part === "?") return "[^/]"
      return part.replace(/[.+^${}()|[\]\\]/g, "\\$&")
    })
    .join("")
  return new RegExp(`^${re}$`).test(path)
}

export function isNoise(path: string): boolean {
  return NOISE_PATTERNS.some((p) => matchesGlob(path, p))
}

export interface ComponentHit {
  component: Component
  paths: string[]
}

export interface MirrorFinding {
  /** Ports the diff actually touched. */
  touched: string[]
  /** Ports it did not — non-empty means the mirror is incomplete. */
  missing: string[]
  vectorsUpdated: boolean
  complete: boolean
  /**
   * Whether absence can be trusted.
   *
   * The mirror rule reasons from what is NOT in the path list, so a truncated list — a PR larger
   * than the connector will fetch, or a rate-limited page — would manufacture a critical-severity
   * "partial mirror" finding on exactly the large refactors most likely to be truncated. When this
   * is false, `missing` is unknowable and a detector must not report incompleteness.
   */
  reliable: boolean
}

export interface SensitivityResult {
  /** Paths left after noise exclusion — what the rest of the analysis ran on. */
  considered: string[]
  excluded: string[]
  hits: ComponentHit[]
  /** Null when the diff touches no mirrored port at all, so the rule does not apply. */
  mirror: MirrorFinding | null
  /** Highest floor across all hits, or null when nothing matched. */
  severityFloor: "medium" | "high" | "critical" | null
}

const FLOOR_RANK = { medium: 0, high: 1, critical: 2 } as const

/**
 * Classify a changed-file list.
 *
 * Order matters and is the whole correction from the first draft: noise is removed FIRST, so a
 * changelog in `packages/verify/` can never make a diff look like it touched receipt verification.
 */
export function classifyChangedPaths(
  paths: readonly string[],
  opts: { truncated?: boolean; map?: PathMap } = {},
): SensitivityResult {
  const map = opts.map ?? PATH_MAPS.generic
  const considered: string[] = []
  const excluded: string[] = []
  for (const p of paths) (isNoise(p) ? excluded : considered).push(p)

  const hits: ComponentHit[] = []
  for (const component of map.components) {
    const matched = considered.filter((p) => component.patterns.some((pat) => matchesGlob(p, pat)))
    if (matched.length > 0) hits.push({ component, paths: matched })
  }

  const ports = map.mirror?.ports ?? {}
  const vectorPatterns = map.mirror?.vectorPatterns ?? []
  const touched = Object.entries(ports)
    .filter(([, pats]) => considered.some((p) => pats.some((pat) => matchesGlob(p, pat))))
    .map(([port]) => port)

  const mirror: MirrorFinding | null =
    touched.length === 0
      ? null
      : {
          touched,
          missing: Object.keys(ports).filter((p) => !touched.includes(p)),
          vectorsUpdated: considered.some((p) => vectorPatterns.some((pat) => matchesGlob(p, pat))),
          complete: false,
          reliable: !opts.truncated,
        }
  // A COMPLETE mirror stays trustworthy on a truncated list: truncation can only hide paths, never
  // invent them, so seeing all six ports is a positive observation. Only the inference from
  // ABSENCE is lost, which is what `reliable` gates.
  if (mirror) mirror.complete = mirror.missing.length === 0 && mirror.vectorsUpdated

  const severityFloor =
    hits.length === 0
      ? null
      : hits.reduce<"medium" | "high" | "critical">(
          (worst, h) => (FLOOR_RANK[h.component.floor] > FLOOR_RANK[worst] ? h.component.floor : worst),
          "medium",
        )

  return { considered, excluded, hits, mirror, severityFloor }
}
