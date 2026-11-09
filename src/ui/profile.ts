import { esc, page } from "./layout.ts"

export function profilePage(actor: { label: string; externalId: string }) {
  return page({
    title: "Your profile",
    path: "/profile",
    actor,
    lede: "Choose the name your team sees beside your activity.",
    body: `<div class="card"><form id="profile-form">
      <div class="field"><label for="display-name">Display name</label>
        <input id="display-name" name="name" value="${esc(actor.label)}" required maxlength="80" autocomplete="name"></div>
      <button class="primary" type="submit">Save name</button>
      <p id="profile-status" role="status" aria-live="polite"></p>
    </form></div>
    <script>
    document.getElementById('profile-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      const button = event.target.querySelector('button');
      const status = document.getElementById('profile-status');
      button.disabled = true;
      window.intelligenceToast("Saving your name…", "pending", {id:"profile"});
      try {
        const response = await fetch('/api/profile', {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({name:event.target.elements.name.value})});
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || 'Could not save your name.');
        document.querySelector('.whoName').textContent = result.name;
        status.textContent = 'Name saved.';
        window.intelligenceToast('Name saved.', 'success', {id:'profile'});
      } catch (error) { status.textContent = error.message; window.intelligenceToast(error.message, "error", {id:"profile"}); }
      finally { button.disabled = false; }
    });
    </script>`,
  })
}
