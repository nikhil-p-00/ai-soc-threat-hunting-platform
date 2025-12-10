// dashboard/static/main.js
const API = "/api/alerts";
const POLL_INTERVAL = 5000; // ms

let lastAlerts = [];

function makeClickable(text) {
  // convert http(s) links to anchors
  return text.replace(/(https?:\/\/[^\s]+)/g, function(url) {
    return `<a href="${url}" target="_blank" rel="noopener">${url}</a>`;
  });
}

function severityClass(sev) {
  sev = (sev||"").toLowerCase();
  if (sev.includes("high")) return "sev-high";
  if (sev.includes("suspicious")) return "sev-suspicious";
  return "sev-info";
}

async function fetchAlerts() {
  const res = await fetch(API);
  const data = await res.json();
  return data.alerts || [];
}

function renderTable(alerts, filterText="") {
  const tbody = document.querySelector("#alertsTable tbody");
  tbody.innerHTML = "";
  const filtered = alerts.filter(a => {
    if (!filterText) return true;
    const txt = (a.rule + " " + a.message).toLowerCase();
    return txt.includes(filterText.toLowerCase());
  });
  for (const a of filtered) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${a.ts}</td>
                    <td class="${severityClass(a.severity)}">${a.severity}</td>
                    <td>${a.rule}</td>
                    <td><pre style="white-space:pre-wrap">${makeClickable(a.message)}</pre></td>`;
    tbody.appendChild(tr);
  }
  return filtered;
}

let severityChart = null;
let rulesChart = null;

function updateCharts(alerts) {
  const counts = {"HIGH":0,"SUSPICIOUS":0,"INFO":0};
  const ruleCounts = {};
  for (const a of alerts) {
    const s = (a.severity||"INFO").toUpperCase();
    if (counts[s] !== undefined) counts[s]++;
    else counts["INFO"]++;
    ruleCounts[a.rule] = (ruleCounts[a.rule]||0)+1;
  }
  const sevLabels = Object.keys(counts);
  const sevData = sevLabels.map(l => counts[l]);

  // severity chart
  if (!severityChart) {
    const ctx = document.getElementById("severityChart").getContext("2d");
    severityChart = new Chart(ctx, {
      type: 'bar',
      data: { labels: sevLabels, datasets: [{ label: 'Alerts by severity', data: sevData }] },
      options: { responsive: true, maintainAspectRatio: false }
    });
  } else {
    severityChart.data.datasets[0].data = sevData;
    severityChart.update();
  }

  // rules chart (top 5)
  const sorted = Object.entries(ruleCounts).sort((a,b)=>b[1]-a[1]).slice(0,5);
  const ruleLabels = sorted.map(r=>r[0]);
  const ruleData = sorted.map(r=>r[1]);
  if (!rulesChart) {
    const ctx2 = document.getElementById("rulesChart").getContext("2d");
    rulesChart = new Chart(ctx2, {
      type:'pie',
      data: { labels: ruleLabels, datasets: [{ data: ruleData }] },
      options: { responsive: true, maintainAspectRatio: false }
    });
  } else {
    rulesChart.data.labels = ruleLabels;
    rulesChart.data.datasets[0].data = ruleData;
    rulesChart.update();
  }
}

async function refresh() {
  try {
    const alerts = await fetchAlerts();
    lastAlerts = alerts;
    const filterText = document.getElementById("filter").value || "";
    renderTable(alerts, filterText);
    updateCharts(alerts);
  } catch (e) {
    console.error("Fetch error", e);
  }
}

document.getElementById("refresh").addEventListener("click", refresh);
document.getElementById("filter").addEventListener("input", () => renderTable(lastAlerts, document.getElementById("filter").value));

refresh();
setInterval(refresh, POLL_INTERVAL);
