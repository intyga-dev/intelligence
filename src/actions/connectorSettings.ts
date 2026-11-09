import { z } from "zod"
import { connectorFor, isPush } from "../connectors/index.ts"

export const GITHUB_REPOS = z
  .string()
  .trim()
  .min(1)
  .max(4000)
  .refine((value) => {
    const repos = value.split(/[\s,]+/).filter(Boolean)
    return (
      repos.length > 0 &&
      repos.length <= 20 &&
      repos.every(
        (repo) =>
          /^[\w.-]+\/[\w.-]+$/.test(repo) && repo.split("/").every((part) => part !== "." && part !== ".."),
      )
    )
  }, "Use 1–20 repositories in owner/name format")

export const CONFIGURE_CONNECTOR = z
  .object({
    connectionId: z.uuid(),
    kind: z.string().min(1).max(80),
    label: z.string().trim().min(1).max(80),
    config: z.record(z.string(), z.string().max(16000)),
    secretDigest: z
      .string()
      .regex(/^[a-f0-9]{64}$/)
      .optional(),
  })
  .strict()
  .superRefine((value, ctx) => {
    const def = connectorFor(value.kind)
    const invalid = (message: string) => ctx.addIssue({ code: "custom", message })
    if (!def) return invalid("Unknown connector kind")
    // Use the registry's explicit non-secret fields, never arbitrary JSON from the form. A credential
    // smuggled into config would otherwise leave this host in the signed approval parameters.
    const fields = def.fields.filter((f) => !f.secret)
    if (Object.keys(value.config).some((key) => !fields.some((f) => f.name === key)))
      return invalid("Only the connector's non-secret settings can be configured")
    for (const field of fields) {
      if (field.required && !value.config[field.name]?.trim()) return invalid(`Missing ${field.label}`)
    }
    if (value.kind === "github" && !GITHUB_REPOS.safeParse(value.config.repos).success)
      return invalid("Use 1–20 repositories in owner/name format")
    if (value.secretDigest && !def.fields.some((f) => f.secret) && !(isPush(def) && def.generatesSecret))
      return invalid("This connector does not use a credential")
  })
