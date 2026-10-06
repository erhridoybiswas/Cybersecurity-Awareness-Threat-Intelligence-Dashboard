// frontend/js/details.js
const id = new URLSearchParams(location.search).get("id");

document.addEventListener("DOMContentLoaded", load);

async function load(){
  if(!id){ document.getElementById("detail").textContent = "Missing threat id."; return; }
  try{
    const t = await apiGet("/api/threats/" + encodeURIComponent(id));
    document.getElementById("detail").innerHTML = `
      <h2>${escapeHtml(t.threat_id)} — ${escapeHtml(t.threat_name)}</h2>
      <p><strong>Category:</strong> ${t.category} ·
         <strong>Severity:</strong> <span class="sev-${t.severity}">${t.severity}</span> ·
         <strong>Risk:</strong> ${t.risk_score} ·
         <strong>Confidence:</strong> ${t.confidence_score} ·
         <strong>Status:</strong> ${t.status}</p>
      <p><strong>Description:</strong> ${escapeHtml(t.description)}</p>
      <p><strong>Source:</strong> ${escapeHtml(t.source_name)} (Reliability ${t.source_reliability})</p>
      <p><strong>First Seen:</strong> ${t.first_seen} ·
         <strong>Last Seen:</strong> ${t.last_seen}</p>
      <h3>Indicators</h3>
      <ul>${t.indicators.map(i => `<li>${i.indicator_type} — ${escapeHtml(i.indicator_value)}</li>`).join("")}</ul>
      <h3>ATT&amp;CK Mapping</h3>
      <ul>${t.attack_mappings.length ? t.attack_mappings.map(m =>
            `<li>${m.tactic} → ${m.technique} (${m.technique_id})</li>`).join("")
          : "<li>None justified by available context.</li>"}</ul>
      <h3>Related Alerts</h3>
      <ul>${t.alerts.length ? t.alerts.map(a =>
            `<li>${a.alert_type} — ${a.severity} — ${a.status}</li>`).join("")
          : "<li>No correlated alerts.</li>"}</ul>
      <h3>Analyst Notes</h3>
      <ul>${t.notes.length ? t.notes.map(n => `<li>${escapeHtml(n.note)} <em>(${n.created_at})</em></li>`).join("")
          : "<li>None yet.</li>"}</ul>
      <h3>Recommended Defensive Actions</h3>
      <ul>
        <li>Review related internal logs (no external contact).</li>
        <li>Check for authorized sightings of this indicator.</li>
        <li>Review email-security telemetry if applicable.</li>
        <li>Increase related awareness training if category is phishing.</li>
        <li>Continue monitoring correlated indicators.</li>
      </ul>
    `;
  }catch(e){
    document.getElementById("detail").textContent = "Not found: " + e.message;
  }
}

async function addNote(){
  const text = document.getElementById("note").value.trim();
  if(!text) return;
  await apiPost("/api/threats/" + encodeURIComponent(id) + "/notes", { note: text });
  document.getElementById("note-status").textContent = "Note saved.";
  document.getElementById("note").value = "";
  load();
}

function escapeHtml(s){
  return String(s).replace(/[&<>"']/g, c => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
  }[c]));
}