// frontend/js/awareness.js
document.addEventListener("DOMContentLoaded", async () => {
  const mods = await apiGet("/api/awareness/modules");
  const root = document.getElementById("modules");
  root.innerHTML = mods.map(m => `
    <section class="card">
      <h2>${m.module_id}. ${escapeHtml(m.title)}</h2>
      <p><strong>What is it?</strong> ${escapeHtml(m.what)}</p>
      <p><strong>Why does it matter?</strong> ${escapeHtml(m.why)}</p>
      <p><strong>Warning signs:</strong> ${m.warning_signs.map(escapeHtml).join(", ")}</p>
      <p><strong>Safe practices:</strong> ${m.safe_practices.map(escapeHtml).join(", ")}</p>
      <p><strong>If something happens:</strong> ${m.if_it_happens.map(escapeHtml).join(", ")}</p>
    </section>
  `).join("");
});

function escapeHtml(s){
  return String(s).replace(/[&<>"']/g, c => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
  }[c]));
}