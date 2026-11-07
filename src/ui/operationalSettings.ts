import { stylesheetLinks } from "./styles.ts"
import { operationalSettings, type OperationalDetector } from "../domain/detectors/operationalSettings.ts"
import { esc } from "./layout.ts"

type Field = {
  name: string
  label: string
  type?: "number" | "date" | "source"
  value?: string | number
  min?: number
  max?: number
  step?: number
  optional?: boolean
}
export interface DetectorSettingsView {
  settings: Partial<Record<OperationalDetector, unknown>>
  sources: { id: string; label: string; kind: string }[]
}
const source: Field = { name: "connectionId", label: "Connector", type: "source" }
const branch: Field = { name: "branch", label: "Branch", value: "main" }
const repo: Field = { name: "repo", label: "Repository (owner/name)" }
const maintenance: Field = {
  name: "maintenanceUntil",
  label: "Maintenance until (local time, optional)",
  type: "date",
  optional: true,
}
const specs: Record<
  OperationalDetector,
  { title: string; help: string; kinds: string[]; fields: Field[]; target?: Field[] }
> = {
  "collection-health": {
    title: "Collection health",
    help: "Reports repeated failed polls and monitoring gaps when polling resumes. A stopped scheduler needs an external uptime monitor.",
    kinds: [],
    fields: [
      { name: "failures", label: "Consecutive failures", type: "number", min: 2, max: 20 },
      { name: "overdueMinutes", label: "Gap threshold (minutes)", type: "number", min: 1, max: 10080 },
    ],
  },
  "ci-health": {
    title: "CI health",
    help: "Monitor selected branch workflows. A successful retry clears the failure streak. Names must match the workflow exactly.",
    kinds: ["github", "webhook"],
    fields: [
      { name: "failures", label: "Failed runs", type: "number", min: 2, max: 20 },
      { name: "brokenMinutes", label: "Failure age (minutes)", type: "number", min: 1, max: 10080 },
    ],
    target: [source, repo, branch, { name: "workflow", label: "Workflow name" }],
  },
  "merge-policy": {
    title: "Merge controls",
    help: "Reports accepted bypasses of failed active review or required-check rules. GitHub rulesets and Administration read permission are required. An authorized exception may still be reported for review.",
    kinds: ["github"],
    fields: [],
    target: [source, repo, branch],
  },
  "job-overdue": {
    title: "Scheduled jobs",
    help: "Monitor backups, syncs or other periodic work. Send a signed job.completed event after success. Monitoring begins at the selected time; maintenance restarts the interval.",
    kinds: ["webhook"],
    fields: [],
    target: [
      source,
      { name: "job", label: "Job name" },
      { name: "startsAt", label: "Monitoring starts (local time)", type: "date", value: "now" },
      {
        name: "intervalMinutes",
        label: "Expected interval (minutes)",
        type: "number",
        value: 1440,
        min: 1,
        max: 10080,
      },
      { name: "graceMinutes", label: "Grace (minutes)", type: "number", value: 30, min: 0, max: 1440 },
      maintenance,
    ],
  },
  "service-degradation": {
    title: "Service degradation",
    help: "Send one signed slo.sample aggregate per UTC minute. Both windows must exceed the burn threshold. Missing minutes mean unknown health. Bad requests can represent errors or slow responses.",
    kinds: ["webhook"],
    fields: [],
    target: [
      source,
      { name: "objective", label: "Objective name" },
      {
        name: "successPercent",
        label: "Success objective (%)",
        type: "number",
        value: 99.9,
        min: 90,
        max: 99.9999,
        step: 0.0001,
      },
      { name: "shortMinutes", label: "Short window (minutes)", type: "number", value: 5, min: 1, max: 60 },
      { name: "longMinutes", label: "Long window (minutes)", type: "number", value: 60, min: 2, max: 1440 },
      {
        name: "burnRate",
        label: "Burn threshold (times budget)",
        type: "number",
        value: 14.4,
        min: 1,
        max: 1000,
        step: 0.1,
      },
      {
        name: "minRequests",
        label: "Minimum requests per window",
        type: "number",
        value: 100,
        min: 1,
        max: 1000000,
      },
      maintenance,
    ],
  },
}

export function operationalSettingsForms(view: DetectorSettingsView): string {
  const forms = (Object.keys(specs) as OperationalDetector[])
    .map((id) => {
      const spec = specs[id]
      let values: Record<string, unknown>
      let invalid = false
      try {
        values = operationalSettings(id, view.settings[id])
      } catch {
        values = operationalSettings(id, {})
        invalid = true
      }
      const field = (f: Field, v: unknown) => {
        const val = v ?? f.value ?? ""
        const attrs = `data-field="${f.name}" ${f.optional ? "" : "required"}`
        const input =
          f.type === "source"
            ? `<select ${attrs}><option value="">Choose connector</option>${view.sources
                .filter((s) => spec.kinds.includes(s.kind))
                .map(
                  (s) =>
                    `<option value="${esc(s.id)}" ${s.id === val ? "selected" : ""}>${esc(s.label)}</option>`,
                )
                .join("")}</select>`
            : `<input ${attrs} type="${f.type === "date" ? "datetime-local" : (f.type ?? "text")}" ${f.type === "date" ? `data-date="${esc(String(val))}"` : `value="${esc(String(val))}"`} ${f.min === undefined ? "" : `min="${f.min}"`} ${f.max === undefined ? "" : `max="${f.max}"`} ${f.step === undefined ? "" : `step="${f.step}"`}>`
        return `<label>${esc(f.label)}${input}</label>`
      }
      const target = (v: Record<string, unknown>) =>
        `<fieldset class="detectorTarget"><legend>Monitored target</legend><div class="detectorFields">${spec.target?.map((f) => field(f, v[f.name])).join("") ?? ""}</div><button type="button" class="removeTarget">Remove target</button></fieldset>`
      return `<form class="card detectorConfig" data-detector="${id}"><h2>${spec.title}</h2><p class="mut">${spec.help}</p>${invalid ? '<p class="error">Saved configuration is invalid. Review these defaults before saving.</p>' : ""}<div class="detectorFields scalars">${spec.fields.map((f) => field(f, values[f.name])).join("")}</div>${spec.target ? `<div class="targets">${(values.targets as Record<string, unknown>[]).map(target).join("")}</div><template>${target({})}</template><button type="button" class="addTarget">Add target</button>` : ""}<button type="submit">Save with INTYGA</button><p class="configError" role="alert"></p></form>`
    })
    .join("")
  return `<h2>Configure operational detectors</h2><p class="mut">Changes require your INTYGA approval. Targets are opt-in; removing every target stops that detector's monitoring. Saving settings preserves its on/off state and starts a fresh monitoring period. Webhook payload examples are in docs/CONNECTORS.md.</p>${stylesheetLinks("operational-settings")} ${forms}<script>
  (()=>{
    function dates(root){root.querySelectorAll('[data-date]').forEach(el=>{if(!el.dataset.date)return;const d=el.dataset.date==='now'?new Date():new Date(el.dataset.date);if(Number.isFinite(d.getTime()))el.value=new Date(d.getTime()-d.getTimezoneOffset()*60000).toISOString().slice(0,16)})}
    function fields(root){const out={};root.querySelectorAll('[data-field]').forEach(el=>{out[el.dataset.field]=el.type==='number'?Number(el.value):el.type==='datetime-local'?(el.value?new Date(el.value).toISOString():null):el.value});return out}
    document.querySelectorAll('.detectorConfig').forEach(form=>{
      dates(form);
      form.addEventListener('click',e=>{if(e.target.closest('.removeTarget'))e.target.closest('fieldset').remove();if(e.target.closest('.addTarget')){const targets=form.querySelector('.targets');if(targets.children.length>=20)return;const row=form.querySelector('template').content.cloneNode(true);dates(row);targets.append(row)}});
      form.addEventListener('submit',e=>{e.preventDefault();const error=form.querySelector('.configError');try{const settings=fields(form.querySelector('.scalars'));if(form.querySelector('.targets'))settings.targets=Array.from(form.querySelector('.targets').children).map(fields);const btn=document.createElement('button');btn.type='button';btn.hidden=true;btn.dataset.action='intelligence.detector.configure';btn.dataset.params=JSON.stringify({detector:form.dataset.detector,settings});form.append(btn);btn.click();btn.remove();error.textContent=''}catch(err){error.textContent=err.message}});
    });
  })();</script>`
}
