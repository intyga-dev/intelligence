import assert from "node:assert/strict"
import { test } from "node:test"
import { FINDING_QUERY, findingOptions, findingsUrl, findingUrl } from "./findingQuery.ts"

test("query defaults keep the console focused on open findings", () => {
  const query = FINDING_QUERY.parse({})
  assert.deepEqual(findingOptions(query).status, ["new", "investigating"])
  assert.equal(query.limit, 25)
  assert.equal(query.sort, "priority")
})

test("invalid filters and unbounded or fractional pagination are rejected", () => {
  for (const query of [
    { status: "unknown" },
    { status: "new,unknown" },
    { severity: "urgent" },
    { limit: "-1" },
    { limit: "1.5" },
    { limit: "Infinity" },
    { limit: "501" },
    { page: "0" },
    { page: "NaN" },
    { sort: "title" },
    { q: "a".repeat(201) },
    { status: ["new", "resolved"] },
  ])
    assert.equal(FINDING_QUERY.safeParse(query).success, false, JSON.stringify(query))
})

test("page links keep every filter and encode user text", () => {
  const query = FINDING_QUERY.parse({
    status: "new,investigating",
    severity: "high",
    category: "security",
    q: "x&status=all",
    sort: "recent",
    page: "2",
    limit: "10",
  })
  assert.equal(findingOptions(query).offset, 10)
  const url = new URL(findingsUrl(query, { page: 3 }), "http://localhost")
  assert.equal(url.searchParams.get("q"), "x&status=all")
  assert.equal(url.searchParams.get("status"), "new,investigating")
  assert.equal(url.searchParams.get("page"), "3")
  assert.match(findingUrl("id"), /status=all&q=id#id/)
})
