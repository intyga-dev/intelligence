#!/usr/bin/env -S pnpm exec tsx
// Test Judgment against TypeSafe AI (JEV).
//
// Reads the latest finding from the database (or falls back to a sample finding),
// projects and anonymizes it according to the allowlist rules, and sends it to JEV.

import crypto from "node:crypto"
import "../src/loadenv.ts"
import { config } from "../src/config.ts"
import { prisma } from "../src/store/client.ts"
import { listFindings } from "../src/store/repo.ts"
import { projectForJudgment, previewRequest, type JudgmentState } from "../src/redaction/project.ts"

async function main() {
  console.log("=== TypeSafe AI · JEV Judgment Test ===")
  console.log(`Endpoint : ${config.judgment.endpoint}`)
  console.log(`Model    : ${config.judgment.model}`)
  console.log(
    `API Key  : ${config.judgment.apiKey ? `configured (${config.judgment.apiKey.slice(0, 16)}...)` : "MISSING"}`,
  )

  if (!config.judgment.apiKey) {
    console.error("\nError: Neither JEV_API_KEY nor TYPESAFE_API_KEY is set in .env")
    process.exit(1)
  }

  const tenants = await prisma.tenant.findMany({ select: { id: true, name: true } })
  let state: JudgmentState
  let liveFindingId: string | null = null

  if (tenants.length > 0) {
    const findings = await listFindings(tenants[0].id, { limit: 1 })
    if (findings.length > 0) {
      liveFindingId = findings[0].id
      console.log(
        `\nUsing live finding from database: "${findings[0].title}" (Severity: ${findings[0].severity})`,
      )
      state = projectForJudgment(findings[0], config.secretsEncKey)
    } else {
      console.log("\nNo findings found in database; using representative sample finding.")
      state = getSampleState()
    }
  } else {
    console.log("\nNo tenant found; using representative sample finding.")
    state = getSampleState()
  }

  const payload = JSON.parse(previewRequest(state, config.judgment.model))
  console.log("\n--- Projected & Redacted State to Send ---")
  console.log(JSON.stringify(payload, null, 2))

  console.log(`\nDispatching request to ${config.judgment.endpoint}...`)
  const start = Date.now()
  const ac = new AbortController()
  const timeout = setTimeout(() => ac.abort(), config.judgment.timeoutMs)

  try {
    const res = await fetch(config.judgment.endpoint, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${config.judgment.apiKey}`,
      },
      body: JSON.stringify(payload),
      signal: ac.signal,
    })

    const duration = Date.now() - start
    console.log(`\nResponse received in ${duration}ms (Status: ${res.status} ${res.statusText})`)

    if (!res.ok) {
      const errText = await res.text()
      console.error("JEV Error:", errText)
      process.exit(1)
    }

    const data = (await res.json()) as {
      model: string
      answers: {
        anomalous?: { noul: number }
        likely_expected_behavior?: { noul: number }
        requires_human_attention?: { noul: number }
        severity?: { score: number; confidence: number }
      }
      usage?: { input_tokens: number; output_tokens: number }
    }

    console.log("\n--- Judgment Results ---")
    console.log(`Model version           : ${data.model}`)
    if (data.answers.anomalous) {
      console.log(`Anomalous Probability   : ${(data.answers.anomalous.noul * 100).toFixed(1)}%`)
    }
    if (data.answers.likely_expected_behavior) {
      console.log(
        `Expected Behavior       : ${(data.answers.likely_expected_behavior.noul * 100).toFixed(1)}%`,
      )
    }
    if (data.answers.requires_human_attention) {
      console.log(
        `Needs Human Attention   : ${(data.answers.requires_human_attention.noul * 100).toFixed(1)}%`,
      )
    }
    if (data.answers.severity) {
      const scoreLabels = ["informational", "low", "medium", "high", "critical"]
      const idx = Math.min(Math.round(data.answers.severity.score), 4)
      console.log(
        `Refined Severity        : ${scoreLabels[idx]} (score: ${data.answers.severity.score.toFixed(2)}, confidence: ${(data.answers.severity.confidence * 100).toFixed(1)}%)`,
      )
    }
    if (data.usage) {
      console.log(`Tokens Consumed         : ${data.usage.input_tokens} in / ${data.usage.output_tokens} out`)
    }

    if (liveFindingId && !process.argv.includes("--no-save")) {
      console.log(`\nSaving assessment evidence to finding ${liveFindingId}...`)
      await prisma.evidence.deleteMany({ where: { findingId: liveFindingId, kind: "assessment" } })
      const count = await prisma.evidence.count({ where: { findingId: liveFindingId } })

      const stateDigest = crypto.createHash("sha256").update(JSON.stringify(payload)).digest("hex")
      const assessmentEv = {
        kind: "assessment",
        provider: "typesafe",
        model: data.model,
        question: "anomalous",
        answer: data.answers.anomalous?.noul ?? 0,
        probability: data.answers.anomalous?.noul,
        confidence: data.answers.severity?.confidence,
        stateDigest,
      }

      await prisma.evidence.create({
        data: {
          findingId: liveFindingId,
          kind: "assessment",
          ordinal: count,
          data: assessmentEv,
        },
      })

      // Also record in JudgmentRequest audit outbox
      if (tenants[0]) {
        await prisma.judgmentRequest.create({
          data: {
            tenantId: tenants[0].id,
            findingId: liveFindingId,
            questionSet: "systemone-v0",
            status: "DONE",
            attempts: 1,
            sentState: payload as object,
            stateDigest,
            response: data as object,
            completedAt: new Date(),
          },
        })
      }

      console.log(
        "✓ Saved JEV assessment to finding! It is now visible under Evidence on the finding card in the UI.",
      )
    }
  } finally {
    clearTimeout(timeout)
    await prisma.$disconnect()
  }
}

function getSampleState(): JudgmentState {
  return {
    finding: {
      category: "security",
      severity: "high",
      title: "17 refused operations from <subject>",
      occurrences: 3,
    },
    measurements: [
      { label: "challenge.denied", value: 17, baseline: 1 },
      { label: "action: grant_permission", value: 12 },
    ],
    events: [{ kind: "challenge.denied", count: 17 }],
    subjectDigest: "did_salt_hash_1234",
  }
}

main().catch((err) => {
  console.error("Failed:", err)
  process.exit(1)
})
