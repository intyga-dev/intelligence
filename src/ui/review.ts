import type { AssessmentEvidence } from "../domain/finding.ts"
import { assessmentConfidenceLabel } from "../domain/finding.ts"
import { PROVIDER_LABELS, type ReviewProviderView } from "../judgment/settings.ts"
import { esc, page } from "./layout.ts"

export function reviewEvidence(e: AssessmentEvidence): string {
  const list = (label: string, values: string[]) =>
    values.length ? `<p><b>${label}</b></p><ul>${values.map((v) => `<li>${esc(v)}</li>`).join("")}</ul>` : ""
  return `<li class="ev model"><span class="k model">AI opinion</span> <b>${esc(e.provider)} · ${esc(e.model)}</b>
  <span>${esc(e.question)}: ${esc(e.probability === undefined ? String(e.answer) : `${(e.probability * 100).toFixed(0)}% estimated`)}</span>
  ${e.confidence === undefined ? "" : `<span>${esc(assessmentConfidenceLabel(e))}</span>`}
  ${
    e.review
      ? `<p>${esc(e.review.explanation)}</p><p class="mut">Suggested impact: ${esc(e.review.severity ?? "unknown")} · Human attention: ${e.review.requiresHumanAttention === null ? "unknown" : `${(e.review.requiresHumanAttention * 100).toFixed(0)}% estimated`}. Advisory estimates are not calibrated or averaged across providers.</p>
  <details><summary>Evidence and investigation suggestions</summary>${list("Supporting evidence", e.review.supportedEvidence)}${list("Missing context", e.review.missingEvidence)}${list("Suggested human checks", e.review.nextSteps)}</details>`
      : ""
  }
  ${e.reviewedAt ? `<span class="mut">Reviewed ${esc(e.reviewedAt)}</span>` : ""}</li>`
}

export function reviewSettings(providers: ReviewProviderView[]): string {
  return `<p>Choose one primary provider for automatic reviews. Other configured providers are available for separately approved second opinions on findings. Saved API keys are never displayed.</p>
  <p class="mut">Daily request limits include failed attempts and reset at midnight UTC. Output-token limits apply to OpenAI and Anthropic; JEV uses its own response contract. These limits bound usage, not a dollar amount. Set spending controls in each provider account as well.</p>
  ${providers
    .map((p) => {
      const id = `review-${p.provider}`
      return `<div class="card"><h2>${esc(PROVIDER_LABELS[p.provider])} ${p.primary ? '<span class="badge">primary</span>' : ""}</h2>
    <p>${p.configured ? "API key configured" : "Not configured"}</p>
    <form data-review-provider="${p.provider}">
    <div class="field"><label for="${id}-model">Model ID</label><input id="${id}-model" name="model" required maxlength="120" value="${esc(p.model === "removed" ? "" : p.model)}" placeholder="Model ID from your provider account"><p class="help">OpenAI and Anthropic models must support structured JSON output.</p></div>
    <div class="field"><label for="${id}-key">${p.configured ? "Replacement API key (leave empty to keep)" : "API key"}</label><input id="${id}-key" type="password" autocomplete="new-password" maxlength="4096" ${p.configured ? "" : "required"}></div>
    <div class="field"><label for="${id}-daily">Maximum requests per UTC day</label><input id="${id}-daily" name="dailyRequestLimit" type="number" min="1" max="1000" required value="${p.dailyRequestLimit}"></div>
    <div class="field"><label for="${id}-tokens">Maximum output tokens per request${p.provider === "typesafe" ? " (not used by JEV)" : ""}</label><input id="${id}-tokens" name="maxOutputTokens" type="number" min="512" max="8192" required value="${p.maxOutputTokens}"></div>
    <div class="field"><label for="${id}-timeout">Timeout in seconds</label><input id="${id}-timeout" name="timeoutSeconds" type="number" min="1" max="30" required value="${p.timeoutMs / 1000}"></div>
    <label><input name="primary" type="checkbox" ${p.primary ? "checked" : ""}> Use as primary reviewer (otherwise keep the current primary)</label>
    <p><button type="submit" class="primary">Review and approve settings</button></p>
    </form>
    <button id="${id}-approve" data-action="intelligence.judgment.configure" data-secret-input="${id}-key" data-secret-parameter="replacementSecret" hidden></button>
    ${p.configured ? `<button class="danger" data-action="intelligence.judgment.remove" data-params="${esc(JSON.stringify({ provider: p.provider }))}">Remove provider</button>` : ""}
    </div>`
    })
    .join("")}
  <script>document.querySelectorAll('form[data-review-provider]').forEach(form => form.addEventListener('submit', event => {
    event.preventDefault(); const values=Object.fromEntries(new FormData(form)); const provider=form.dataset.reviewProvider;
    const button=document.getElementById('review-'+provider+'-approve');
    button.dataset.params=JSON.stringify({provider,model:values.model,dailyRequestLimit:Number(values.dailyRequestLimit),maxOutputTokens:Number(values.maxOutputTokens),timeoutMs:Number(values.timeoutSeconds)*1000,primary:values.primary==='on'});
    button.click();
  }));</script>`
}

export function reviewRequestPage(o: {
  findingId: string
  findingTitle: string
  provider: ReviewProviderView
  endpoint: string
  stateDigest: string
  payload: object
  actor?: { label: string; externalId: string }
}): string {
  return page({
    title: "Review a finding",
    path: "/findings",
    lede: "Inspect the evidence before requesting an independent AI opinion.",
    ...(o.actor ? { actor: o.actor } : {}),
    body: `<div class="card"><h2>${esc(o.findingTitle)}</h2><p>Send to <b>${esc(PROVIDER_LABELS[o.provider.provider])}</b>, model <code>${esc(o.provider.model)}</code> at <code>${esc(o.endpoint)}</code>.</p>
    <p>Existing opinions remain separate. The reviewer receives the evidence shown below, without previous model assessments. It cannot approve changes or alter finding severity. This request uses your provider quota.</p>
    <pre style="overflow:auto;max-height:32rem"><code>${esc(JSON.stringify(o.payload, null, 2))}</code></pre>
    <button class="primary" data-action="intelligence.judgment.review" data-params="${esc(JSON.stringify({ findingId: o.findingId, provider: o.provider.provider, model: o.provider.model, stateDigest: o.stateDigest }))}">Review and approve request</button>
    <a href="/findings?q=${encodeURIComponent(o.findingId)}&amp;status=all">Back to finding</a></div>`,
  })
}
