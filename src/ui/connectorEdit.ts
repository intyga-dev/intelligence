import { stylesheetLinks } from "./styles.ts"
import { esc, page } from "./layout.ts"

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
    lede: "Update the repositories and settings for this GitHub source. Saving requires passkey approval.",
    body: `${stylesheetLinks("connector-edit")}
    <div class="card connectorEdit"><form id="connector-edit" data-id="${esc(o.id)}">
      <div class="field"><label for="connector-label">Label</label><input id="connector-label" name="label" value="${esc(o.label)}" required maxlength="80"></div>
      <div class="field"><label for="connector-repos">Repositories</label><input id="connector-repos" name="repos" value="${esc(String(o.config.repos ?? ""))}" required maxlength="4000" aria-describedby="repos-help">
        <p class="help" id="repos-help">Use owner/name, separated by commas. Up to 20 repositories.</p></div>
      <div class="field"><label for="connector-workflows">Deploy workflow names</label><input id="connector-workflows" name="deployWorkflows" value="${esc(String(o.config.deployWorkflows ?? ""))}" maxlength="2000" aria-describedby="workflows-help">
        <p class="help" id="workflows-help">Separate workflow names with commas. Leave empty if this source has no deploy workflows.</p></div>
      <div class="field"><label for="connector-pathmap">Sensitive-path map</label><select id="connector-pathmap" name="pathMap">
        <option value="generic"${o.config.pathMap !== "intyga-core" ? " selected" : ""}>Generic</option>
        <option value="intyga-core"${o.config.pathMap === "intyga-core" ? " selected" : ""}>INTYGA core</option></select></div>
      <div class="editFoot"><p class="mut">Your existing GitHub token and collected history are kept.</p>
        <div class="editActions"><button class="primary" type="submit">Review and approve changes</button><a href="/connectors">Back to connectors</a></div>
      </div>
    </form><button id="connector-approve" type="button" data-action="intelligence.connector.configure-github" hidden></button></div>
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
