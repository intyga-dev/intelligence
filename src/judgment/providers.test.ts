import assert from "node:assert/strict"
import test from "node:test"
import { callReviewProvider, parseReview, reviewPayload } from "./providers.ts"
import type { ReviewProviderView } from "./settings.ts"
import type { JudgmentState } from "../redaction/project.ts"

const provider: ReviewProviderView = {
  provider: "openai",
  model: "fixture-model",
  configured: true,
  primary: true,
  dailyRequestLimit: 3,
  maxOutputTokens: 2048,
  timeoutMs: 1000,
}
const state: JudgmentState = {
  finding: {
    category: "engineering",
    severity: "high",
    title: "Detector-reported condition",
    occurrences: 1,
  },
  measurements: [],
  events: [{ kind: "intelligence.poll", count: 1 }],
  subjectDigest: null,
}
const review = {
  anomalous: null,
  requiresHumanAttention: 0.7,
  severity: "medium",
  explanation: "Collection has failed; service impact is unknown.",
  supportedEvidence: ["Repeated failed polls"],
  missingEvidence: ["Service health"],
  nextSteps: ["Check source credentials and connectivity"],
}
function response() {
  return {
    model: "fixture-model",
    status: "completed",
    output: [{ type: "message", content: [{ type: "output_text", text: JSON.stringify(review) }] }],
    usage: { input_tokens: 100, output_tokens: 90 },
  }
}

test("OpenAI and Anthropic receive structured output requests without tools or prior responses", () => {
  const openai = reviewPayload(provider, state) as Record<string, unknown>
  assert.equal(openai.store, false)
  assert.equal(openai.max_output_tokens, 2048)
  assert.ok(openai.text)
  const anthropic = reviewPayload({ ...provider, provider: "anthropic" }, state) as Record<string, unknown>
  assert.equal(anthropic.max_tokens, 2048)
  assert.ok(anthropic.output_config)
  for (const body of [openai, anthropic]) {
    assert.equal(body.tools, undefined)
    assert.equal(body.previous_response_id, undefined)
  }
  const jev = reviewPayload({ ...provider, provider: "typesafe" }, state) as Record<string, unknown>
  assert.deepEqual(Object.keys(jev), ["model", "state", "questions"])
})

test("unknown assessments remain unknown and malformed, refused or truncated responses fail closed", () => {
  assert.deepEqual(parseReview("openai", response()).review, review)
  assert.deepEqual(
    parseReview("anthropic", {
      model: "fixture-model",
      stop_reason: "end_turn",
      content: [{ type: "text", text: JSON.stringify(review) }],
    }).review,
    review,
  )
  for (const body of [
    { ...response(), status: "incomplete" },
    { ...response(), output: [{ type: "message", content: [{ type: "refusal", refusal: "no" }] }] },
    {
      ...response(),
      output: [
        {
          type: "message",
          content: [{ type: "output_text", text: JSON.stringify({ ...review, anomalous: 19 }) }],
        },
      ],
    },
    {
      ...response(),
      output: [
        {
          type: "message",
          content: [
            { type: "output_text", text: JSON.stringify({ ...review, nextSteps: ["x".repeat(301)] }) },
          ],
        },
      ],
    },
  ])
    assert.throws(() => parseReview("openai", body))
  assert.throws(() =>
    parseReview("anthropic", {
      model: "fixture",
      stop_reason: "max_tokens",
      content: [{ type: "text", text: "{}" }],
    }),
  )
  const partial = parseReview("typesafe", {
    model: "fixture",
    answers: { severity: { score: 2, confidence: 0.4 } },
  })
  assert.equal(partial.review.anomalous, null)
  assert.equal(partial.severityConfidence, 0.4)
  assert.throws(() => parseReview("typesafe", { model: "fixture", answers: {} }))
})

test("credentials are headers only, redirects fail, response sizes are bounded, and errors never echo bodies", async () => {
  for (const kind of ["openai", "anthropic"] as const) {
    let calls = 0
    const fetcher: typeof fetch = async (_url, init) => {
      calls++
      assert.equal(init?.redirect, "error")
      assert.doesNotMatch(String(init?.body), /fixture-secret/)
      const headers = new Headers(init?.headers)
      assert.equal(
        headers.get(kind === "openai" ? "authorization" : "x-api-key"),
        kind === "openai" ? "Bearer fixture-secret" : "fixture-secret",
      )
      return new Response("credential=fixture-secret private-error", { status: 401 })
    }
    await assert.rejects(
      callReviewProvider(
        {
          provider: { ...provider, provider: kind },
          endpoint: "https://api.example.test",
          credential: "fixture-secret",
          payload: {},
        },
        fetcher,
      ),
      (error: Error) => /HTTP 401/.test(error.message) && !/fixture-secret|private-error/.test(error.message),
    )
    assert.equal(calls, 1, "no silent retries or fallback providers")
  }
  await assert.rejects(
    callReviewProvider(
      { provider, endpoint: "https://api.example.test", credential: "fixture", payload: {} },
      async () => new Response("x".repeat(131073)),
    ),
    /size limit/,
  )
  let called = false
  await assert.rejects(
    callReviewProvider(
      {
        provider,
        endpoint: "https://api.example.test",
        credential: "fixture",
        payload: { text: "x".repeat(32768) },
      },
      async () => {
        called = true
        return new Response()
      },
    ),
    /input exceeds/,
  )
  assert.equal(called, false)
})

test("timeout is bounded and network exception text stays private", async () => {
  const input = {
    provider: { ...provider, timeoutMs: 10 },
    endpoint: "https://api.example.test",
    credential: "fixture",
    payload: {},
  }
  await assert.rejects(
    callReviewProvider(
      input,
      async (_url, init) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(new Error("fixture-secret")))
        }),
    ),
    /timed out/,
  )
  await assert.rejects(
    callReviewProvider(input, async () => {
      throw new Error("credential=fixture-secret")
    }),
    /^Error: Could not reach the review provider$/,
  )
})
