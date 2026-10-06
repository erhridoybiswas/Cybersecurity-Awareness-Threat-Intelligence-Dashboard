// frontend/js/executive.js
document.addEventListener("DOMContentLoaded", async () => {
  const e = await apiGet("/api/dashboard/executive");
  document.getElementById("exec").innerHTML = `
    <h2>${escapeHtml(e.headline)}</h2>
    <p><strong>High or Critical Threats:</strong> ${e.high_or_critical_threats}</p>
    <h3>Top Threat Categories</h3>
    <ul>${e.top_threat_categories.map(x =>
      `<li>${escapeHtml(x.category)} — ${x.count}</li>`).join("")}</ul>
    <h3>Top Vulnerability Categories</h3>
    <ul>${e.top_vulnerability_categories.map(x =>
      `<li>${escapeHtml(x.category)} — ${x.count}</li>`).join("")}</ul>
    <h3>Recommended Defensive Priorities</h3>
    <ul>${e.recommended_priorities.map(escapeHtml).map(x => `<li>${x}</li>`).join("")}</ul>
    <p style="color:#94a3b8"><em>All figures are derived from synthetic data.</em></p>
  `;
});

function escapeHtml(s){
  return String(s).replace(/[&<>"']/g, c => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
  }[c]));
}