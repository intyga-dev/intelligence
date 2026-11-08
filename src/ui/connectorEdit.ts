import { stylesheetLinks } from "./styles.ts"
import { esc, page } from "./layout.ts"
import { isPush, type ConnectorDefinition } from "../connectors/registry.ts"

export function connectorEditPage(o: {
  id: string
  label: string
  config: Record<string, unknown>
  def: ConnectorDefinition
  actor: { label: string; externalId: string }
}) {
  const generated = isPush(o.def) && o.def.generatesSecret
  const secret = o.def.fields.find((f) => f.secret)
  const hasSecret = Boolean(secret || generated)
  const jsonSecret = secret?.name === "credentials"
  const fields = o.def.fields
    .filter((f) => !f.secret)
    .map((f) => {
      const value = String(o.config[f.name] ?? (f.name === "pathMap" ? "generic" : ""))
      const attrs = `id="field-${esc(f.name)}" name="${esc(f.name)}" ${f.required ? "required" : ""} maxlength="16000" aria-describedby="help-${esc(f.name)}"`
      const input =
        f.name === "pathMap"
          ? `<select ${attrs}><option value="generic"${value !== "intyga-core" ? " selected" : ""}>Generic</option><option value="intyga-core"${value === "intyga-core" ? " selected" : ""}>INTYGA core</option></select>`
          : f.name === "queries"
            ? `<textarea ${attrs} rows="5">${esc(value)}</textarea>`
            : `<input ${attrs} value="${esc(value)}" placeholder="${esc(f.placeholder ?? "")}">`
      return `<div class="field"><label for="field-${esc(f.name)}">${esc(f.label)}</label>${input}<p class="help" id="help-${esc(f.name)}">${esc(f.help ?? "")}</p></div>`
    })
    .join("")
  return page({
    title: `Edit ${o.label}`,
    path: "/connectors",
    actor: o.actor,
    lede: `Update this ${o.def.label} source. Saving requires passkey approval.`,
    body: `${stylesheetLinks("connector-edit")}<div class="card connectorEdit">
    <form id="connector-edit" data-id="${esc(o.id)}" data-kind="${esc(o.def.kind)}">
      <div class="field"><label for="connector-label">Label</label><input id="connector-label" name="label" value="${esc(o.label)}" required maxlength="80"></div>
      ${fields}
      ${
        hasSecret
          ? `<div class="field"><label for="connector-secret">Replacement ${esc(secret?.label ?? "webhook signing secret")}</label>
        ${jsonSecret ? '<textarea id="connector-secret" rows="6" maxlength="65536" autocomplete="off" spellcheck="false" aria-describedby="secret-help"></textarea>' : `<input id="connector-secret" type="password" autocomplete="new-password" maxlength="65536" ${generated ? 'minlength="32"' : ""} aria-describedby="secret-help">`}
        <p class="help" id="secret-help">Leave empty to keep the saved credential. ${esc(secret?.help ?? "Generate a new secret below, or enter at least 32 characters.")} ${isPush(o.def) ? "Copy the replacement before submitting. After approval, update your webhook sender to use it." : ""} ${jsonSecret ? "Paste the complete JSON key; the replacement is visible while you enter it." : ""}</p>
        ${generated ? '<button id="generate-secret" type="button">Generate replacement secret</button>' : ""}
        ${!jsonSecret ? '<label><input id="show-secret" type="checkbox"> Show replacement credential</label>' : ""}</div>`
          : ""
      }
      ${o.def.builtIn ? '<p class="mut">This edits the telemetry connector only. Sign-in credentials and trust anchors are managed by the deployment operator.</p>' : ""}
      <div class="editFoot"><p class="mut">Collected history and polling cursors are kept. Saved credentials are never displayed.</p>
        <div class="editActions"><button class="primary" type="submit">Review and approve changes</button><a href="/connectors">Back to connectors</a></div></div>
    </form><button id="connector-approve" type="button" data-action="intelligence.connector.configure" ${hasSecret ? 'data-secret-input="connector-secret" data-secret-parameter="replacementSecret"' : ""} hidden></button></div>
    <script>
    document.getElementById('connector-edit').addEventListener('submit', event => {
      event.preventDefault();
      const form=event.target, values=Object.fromEntries(new FormData(form)), label=values.label;
      delete values.label;
      const button=document.getElementById('connector-approve');
      button.dataset.params=JSON.stringify({connectionId:form.dataset.id,kind:form.dataset.kind,label,config:values});
      button.click();
    });
    document.getElementById('show-secret')?.addEventListener('change', event => {
      document.getElementById('connector-secret').type=event.target.checked?'text':'password';
    });
    document.getElementById('generate-secret')?.addEventListener('click', () => {
      const bytes=crypto.getRandomValues(new Uint8Array(32));
      document.getElementById('connector-secret').value='whsec_'+Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
    });
    </script>`,
  })
}

export function githubEditPage(o: {
  id: string
  label: string
  config: Record<string, unknown>
  actor: { label: string; externalId: string }
}) {
  return page({
    title: `Edit ${o.label}`,
    path: "/connectors",
    actor: o.actor,
    lede: "Update the token, repositories and settings for this GitHub source. Saving requires passkey approval.",
    body: `${stylesheetLinks("connector-edit")}
    <div class="card connectorEdit"><form id="connector-edit" data-id="${esc(o.id)}">
      <div class="field"><label for="connector-label">Label</label><input id="connector-label" name="label" value="${esc(o.label)}" required maxlength="80"></div>
      <div class="field"><label for="connector-token">Replacement GitHub token</label><input id="connector-token" type="password" autocomplete="new-password" maxlength="4096" aria-describedby="token-help">
        <p class="help" id="token-help">Leave empty to keep the saved token. A replacement takes effect after approval.</p></div>
      <div class="field"><label for="connector-repos">Repositories</label><input id="connector-repos" name="repos" value="${esc(String(o.config.repos ?? ""))}" required maxlength="4000" aria-describedby="repos-help">
        <p class="help" id="repos-help">Use owner/name, separated by commas. Up to 20 repositories.</p></div>
      <div class="field"><label for="connector-workflows">Deploy workflow names</label><input id="connector-workflows" name="deployWorkflows" value="${esc(String(o.config.deployWorkflows ?? ""))}" maxlength="2000" aria-describedby="workflows-help">
        <p class="help" id="workflows-help">Separate workflow names with commas. Leave empty if this source has no deploy workflows.</p></div>
      <div class="field"><label for="connector-pathmap">Sensitive-path map</label><select id="connector-pathmap" name="pathMap">
        <option value="generic"${o.config.pathMap !== "intyga-core" ? " selected" : ""}>Generic</option>
        <option value="intyga-core"${o.config.pathMap === "intyga-core" ? " selected" : ""}>INTYGA core</option></select></div>
      <div class="editFoot"><p class="mut">Collected history is kept. Your saved token is never displayed.</p>
        <div class="editActions"><button class="primary" type="submit">Review and approve changes</button><a href="/connectors">Back to connectors</a></div>
      </div>
    </form><button id="connector-approve" type="button" data-action="intelligence.connector.configure-github" data-secret-input="connector-token" hidden></button></div>
    <script>
    document.getElementById('connector-edit').addEventListener('submit', (event) => {
      event.preventDefault();
      const form = event.target;
      const button = document.getElementById('connector-approve');
      button.dataset.params = JSON.stringify({connectionId:form.dataset.id,...Object.fromEntries(new FormData(form))});
      button.click();
    });
    </script>`,
  })
}
