// frontend/js/dashboard.js
const SEV = ["INFORMATIONAL","LOW","MEDIUM","HIGH","CRITICAL"];
const CATS = ["PHISHING","MALWARE","RANSOMWARE","CREDENTIAL_THREATS",
              "WEB_THREATS","NETWORK_THREATS","VULNERABILITY_EXPOSURE",
              "SOCIAL_ENGINEERING","DATA_EXPOSURE","ACCOUNT_SECURITY"];
const STAT = ["NEW","UNDER_REVIEW","MONITORING","CLOSED","FALSE_POSITIVE"];

document.addEventListener("DOMContentLoaded", async () => {
  fillSelect("f-sev", SEV);
  fillSelect("f-cat", CATS);
  fillSelect("f-status", STAT);
  await loadStats();
  await loadThreats();
  await loadCharts();
});

function fillSelect(id, arr){
  const sel = document.getElementById(id);
  arr.forEach(v => {
    const o = document.createElement("option");
    o.value = v; o.textContent = v;
    sel.appendChild(o);
  });
}

async function loadStats(){
  const s = await apiGet("/api/dashboard/stats");
  const el = document.getElementById("top-cards");
  el.innerHTML = `
    ${card("Total Threat Records", s.total_threats)}
    ${card("Critical", s.critical)}
    ${card("High", s.high)}
    ${card("Active Indicators", s.active_indicators)}
    ${card("Open Investigations", s.open_investigations)}
    ${card("Avg Confidence", s.avg_confidence)}
    ${card("Vulnerabilities Tracked", s.vulnerabilities_tracked)}
  `;
}
function card(label, num){
  return `<div class="card"><div>${label}</div><div class="num">${num}</div></div>`;
}

async function loadThreats(){
  const params = new URLSearchParams({
    severity: document.getElementById("f-sev").value,
    category: document.getElementById("f-cat").value,
    status: document.getElementById("f-status").value,
    sort: document.getElementById("f-sort").value,
    limit: 100
  });
  const rows = await apiGet("/api/threats?" + params.toString());
  const tb = document.querySelector("#threat-table tbody");
  tb.innerHTML = rows.map(r => `
    <tr>
      <td><a href="threat-details.html?id=${encodeURIComponent(r.threat_id)}">${r.threat_id}</a></td>
      <td>${escapeHtml(r.threat_name)}</td>
      <td>${r.category}</td>
      <td>${escapeHtml(r.indicator_value || "-")}</td>
      <td class="sev-${r.severity}">${r.severity}</td>
      <td>${r.risk_score}</td>
      <td>${r.confidence_score}</td>
      <td>${r.first_seen}</td>
      <td>${r.status}</td>
    </tr>`).join("");
}

function escapeHtml(s){
  return String(s).replace(/[&<>"']/g, c => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
  }[c]));
}

async function loadCharts(){
  const t = await apiGet("/api/dashboard/trends");
  mkPie("c-sev", t.by_severity);
  mkPie("c-cat", t.by_category);
  mkPie("c-ind", t.by_indicator_type);
  mkPie("c-tac", t.by_tactic);
  mkPie("c-st", t.by_status);
  mkLine("c-day", t.by_day);
}

function mkPie(id, obj){
  new Chart(document.getElementById(id), {
    type: "doughnut",
    data: {
      labels: Object.keys(obj),
      datasets: [{ data: Object.values(obj), backgroundColor: palette(Object.keys(obj).length) }]
    },
    options: { plugins: { legend: { labels: { color: "#e2e8f0" } } } }
  });
}

function mkLine(id, arr){
  new Chart(document.getElementById(id), {
    type: "line",
    data: {
      labels: arr.map(x => x.date),
      datasets: [{
        label: "Daily Synthetic Threats",
        data: arr.map(x => x.count),
        borderColor: "#38bdf8", tension: .3
      }]
    },
    options: { plugins: { legend: { labels: { color: "#e2e8f0" } } },
               scales: { x: { ticks: { color: "#94a3b8" } },
                         y: { ticks: { color: "#94a3b8" } } } }
  });
}

function palette(n){
  const base = ["#38bdf8","#f97316","#dc2626","#22c55e","#eab308",
                "#a855f7","#06b6d4","#f43f5e","#84cc16","#64748b"];
  return Array.from({length:n}, (_,i) => base[i % base.length]);
}

async function doSearch(){
  const v = document.getElementById("ioc-input").value.trim();
  const out = document.getElementById("ioc-result");
  if(!v){ out.textContent = "Enter a value."; return; }
  const r = await apiGet("/api/indicators/search?value=" + encodeURIComponent(v));
  out.textContent =
    "Validation: " + JSON.stringify(r.validation, null, 2) + "\n\n" +
    "Lookup: " + JSON.stringify(r.lookup, null, 2) + "\n\n" +
    "Enrichment: " + JSON.stringify(r.enrichment, null, 2) + "\n\n" +
    "Note: " + r.note;
}