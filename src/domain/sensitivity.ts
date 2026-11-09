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

/** Documentation, tests and styling are excluded from path-based review observations. */
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
  "**/*.test.mts",
  "**/*.test.js",
  "**/*.spec.ts",
  "**/*.spec.tsx",
  "**/*_test.go",
  "**/*_test.rs",
  "**/test_*.py",
  "**/tests/**",
  "**/__tests__/**",
  "**/*.css",
  "**/*.scss",
  "**/blog/articles/**",
  "**/docs/**",
  "**/authors.*",
  "**/*.md",
]

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

/** Conventional path names provide review context, never proof of a defect. */
export interface PathMap {
  id: "generic"
  components: readonly Component[]
}

export const PATH_MAPS: Readonly<Record<PathMap["id"], PathMap>> = Object.freeze({
  generic: { id: "generic", components: GENERIC_COMPONENTS },
})

/** Retired or unknown connection settings always use the generic map. */
export function pathMapFor(_id: unknown): PathMap {
  return PATH_MAPS.generic
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

export interface SensitivityResult {
  /** Paths left after noise exclusion — what the rest of the analysis ran on. */
  considered: string[]
  excluded: string[]
  hits: ComponentHit[]
  /** Highest floor across all hits, or null when nothing matched. */
  severityFloor: "medium" | "high" | "critical" | null
}

const FLOOR_RANK = { medium: 0, high: 1, critical: 2 } as const

/** Exclude noise before matching conventional component names. */
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

  const severityFloor =
    hits.length === 0
      ? null
      : hits.reduce<"medium" | "high" | "critical">(
          (worst, h) => (FLOOR_RANK[h.component.floor] > FLOOR_RANK[worst] ? h.component.floor : worst),
          "medium",
        )

  return { considered, excluded, hits, severityFloor }
}
