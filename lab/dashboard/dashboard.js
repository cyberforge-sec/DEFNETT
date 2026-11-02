const $ = (selector) => document.querySelector(selector);
const eventList = $("#event-list");
const hostFilter = $("#host-filter");
const displayedEvents = [];
const openEvents = new Set();
let latestDashboard = null;

const labels = {
  file_created: "File baru",
  file_modified: "File berubah",
  file_deleted: "File dihapus",
};

const remediationLabels = {
  DETECTED: "Canary terdeteksi",
  ISOLATING: "Mengisolasi host target",
  ISOLATED: "Host target keluar dari rotasi",
  REPAIRING: "Mengarantina artefak target",
  VERIFYING: "Memverifikasi hasil perbaikan",
  REJOINING: "Health check dan rejoin target",
  REPAIRED: "Host target aktif kembali",
  FAILED: "Pemulihan host target gagal",
};

function setNodeState(id, state, detail) {
  const node = document.getElementById(id);
  if (node) {
    node.setAttribute("class", `map-node ${state}`);
    const text = node.querySelector(".node-detail");
    if (text) {
      if (text.textContent !== detail) {
        text.style.opacity = "0";
        setTimeout(() => {
          text.textContent = detail;
          text.style.opacity = "1";
        }, 150);
      }
    }
  }
  const mobileId = id.replace("node-agent-", "mobile-agent-").replace("node-server-", "mobile-server-");
  const mobileNode = document.getElementById(mobileId);
  if (mobileNode) {
    mobileNode.setAttribute("class", `mobile-node ${state}`);
    const mobileText = mobileNode.querySelector("strong");
    if (mobileText) mobileText.textContent = detail;
  }
}

function formatTime(value) {
  if (!value) return "Waktu tidak tersedia";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "Waktu tidak valid" : new Intl.DateTimeFormat("id-ID", {
    day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit",
  }).format(date);
}

function formatClock(value) {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "-" : new Intl.DateTimeFormat("id-ID", {
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  }).format(date);
}

function backendState(value) {
  const upper = String(value || "UNKNOWN").toUpperCase();
  if (upper.startsWith("UP")) return ["up", "UP"];
  if (upper.includes("MAINT") || upper.includes("DRAIN") || upper.includes("DOWN") || upper.includes("STOP")) return ["down", "DOWN"];
  if (upper.startsWith("NOLB") || upper.startsWith("CHECK")) return ["maint", "CEK"];
  return ["stale", "?"];
}

function renderBackends(data) {
  const states = ["a", "b"].map((suffix) => {
    const host = `server-${suffix}`;
    const [state, text] = backendState(data.backends?.[host]);
    setNodeState(`node-server-${suffix}`, state, text);
    $(`#chip-backend-${suffix}`).textContent = text;
    $(`#chip-backend-${suffix}`).className = `mode-label status-${state}`;
    $(`#route-server-${suffix}`).classList.toggle("route-down", state !== "up");
    return state;
  });
  const up = states.filter((state) => state === "up").length;
  const known = Object.values(data.backends || {}).some((state) => state !== "UNKNOWN");
  const proxyState = !known || up === 0 ? "down" : up === states.length ? "up" : "maint";
  setNodeState("node-proxy", proxyState === "up" ? "online" : proxyState, known ? `${up}/${states.length} UP` : "Offline");
  $("#chip-proxy").textContent = known ? `${up}/${states.length}` : "OFF";
  $("#chip-proxy").className = `mode-label status-${proxyState}`;
}

function renderRemediation(data) {
  const enabled = Boolean(data.analysis?.auto_repair_enabled);
  const mode = $("#repair-mode");
  mode.textContent = enabled ? "Otomatis · canary lab" : "DRY RUN";
  mode.classList.toggle("active", enabled);

  const worker = $("#remediator-health");
  const workerStates = data.remediator?.by_host || {};
  const hosts = ["server-a", "server-b"];
  const workerReady = hosts.every((host) => workerStates[host]?.status === "ready");
  worker.className = `badge ${workerReady ? "ready" : "unavailable"}`;
  worker.textContent = `Worker ${hosts.filter((host) => workerStates[host]?.status === "ready").length}/${hosts.length}`;

  const run = data.remediation;
  const items = [...document.querySelectorAll("#repair-steps [data-stage]")];
  $("#repair-facts").hidden = !run;
  $("#repair-metrics").hidden = !run;
  if (!run) {
    $("#repair-status").className = "status-indicator waiting";
    $("#repair-status").textContent = enabled ? "Siap" : "Observasi";
    $("#repair-headline").textContent = "Belum ada insiden";
    $("#repair-detail").textContent = "";
    for (const item of items) {
      item.hidden = true;
      item.className = "";
    }
    return;
  }

  const history = Array.isArray(run.steps) ? run.steps : [];
  const latest = history.at(-1)?.stage || run.status;
  const failed = run.status === "FAILED";
  const successful = run.status === "REPAIRED";
  const failedBeforeIsolation = run.detail?.includes("tidak sehat; ")
    || run.detail?.includes("belum mengonfirmasi isolasi");
  const badge = $("#repair-status");
  badge.className = `status-indicator ${failed ? "failed" : successful ? "complete" : "running"}`;
  badge.textContent = remediationLabels[run.status] || run.status;
  $("#repair-headline").textContent = successful
    ? `${run.host_id} pulih`
    : failed ? failedBeforeIsolation
      ? "Respons dihentikan"
      : "Pemulihan gagal"
      : remediationLabels[run.status] || run.status;
  $("#repair-detail").textContent = failed ? run.detail || "" : "";
  const metrics = run.metrics || {};
  $("#metric-detect").textContent = formatSeconds(metrics.detect);
  $("#metric-isolate").textContent = formatSeconds(metrics.isolate);
  $("#metric-recover").textContent = formatSeconds(metrics.demo_hold ? metrics.recover_without_hold : metrics.recover);
  $("#metric-recover-label").textContent = metrics.demo_hold ? `Pulih, tanpa jeda demo ${metrics.demo_hold} dtk` : "Pulih";
  $("#repair-entry").textContent = run.entry ? `${run.entry.actor} lewat port ${run.entry.port}` : "Tidak diketahui";
  $("#repair-file").textContent = `${run.host_id || "server-a"} · ${run.path || "-"}`;
  const survivor = run.host_id === "server-a" ? "server-b" : "server-a";
  $("#repair-survivor").textContent = `${survivor} ${backendState(data.backends?.[survivor])[1]}`;
  $("#repair-quarantine").textContent = run.quarantine_path || "-";
  $("#repair-started").textContent = formatTime(run.started_at);

  const recorded = new Map(history.map((step) => [step.stage, step]));
  for (const item of items) {
    const stage = item.dataset.stage;
    const step = recorded.get(stage);
    item.hidden = !step;
    item.className = !step ? "" : stage === "FAILED" ? "failed"
      : stage === latest && !successful ? "current" : "done";
  }
}

function formatSeconds(value) {
  return Number.isFinite(value) ? `${value.toLocaleString("id-ID")} dtk` : "-";
}

async function refreshEvidence() {
  const badge = $("#evidence-status");
  try {
    const response = await fetch("/v1/evidence/verify", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const result = await response.json();
    badge.textContent = result.status === "ok" ? `Bukti utuh · ${result.events} event` : "Bukti rusak";
    badge.className = `badge ${result.status === "ok" ? "ready" : "unavailable"}`;
  } catch (error) {
    badge.textContent = "Bukti tidak terbaca";
    badge.className = "badge unavailable";
  }
}

function renderTraffic(data) {
  const traffic = data.traffic || {};
  for (const card of document.querySelectorAll(".traffic-card")) {
    const phase = card.dataset.phase;
    const window = traffic.windows?.[phase] || { ok: 0, fail: 0, total: 0, by_host: {} };
    card.classList.toggle("current", traffic.enabled !== false && traffic.phase === phase);
    card.classList.toggle("has-fail", window.fail > 0);
    card.querySelector(".traffic-ok").textContent = String(window.ok);
    card.querySelector(".traffic-rate").textContent = window.total
      ? `${Math.round((window.ok / window.total) * 100)}%`
      : "-";
    card.querySelector(".traffic-fail").textContent = String(window.fail);
    card.querySelector(".traffic-a").textContent = String(window.by_host?.["server-a"] || 0);
    card.querySelector(".traffic-b").textContent = String(window.by_host?.["server-b"] || 0);
  }
}

function renderState(data) {
  latestDashboard = data;
  const mode = data.mode || "UNKNOWN";
  $("#lab-mode").textContent = mode === "ACTIVE_LAB" ? "AKTIF" : mode === "DRY_RUN" ? "DRY RUN" : mode;
  $("#lab-mode").classList.toggle("active", mode === "ACTIVE_LAB");

  for (const suffix of ["a", "b"]) {
    const host = `server-${suffix}`;
    const agent = data.agents?.[host] || {};
    const age = agent.age_seconds;
    const fresh = Boolean(agent.online);
    const agentText = age == null ? "-" : fresh ? "Online" : "Offline";
    setNodeState(`node-agent-${suffix}`, fresh ? "online" : age == null ? "stale" : "error", agentText);
  }
  renderBackends(data);
  displayedEvents.splice(0, displayedEvents.length, ...(Array.isArray(data.events) ? data.events : []));
  renderRemediation(data);
  renderTraffic(data);
  renderEvents();
}

function createEventRow(event) {
  const row = document.createElement("details");
  row.className = "event-row";
  row.open = openEvents.has(event.id);
  row.addEventListener("toggle", () => {
    if (row.open) openEvents.add(event.id); else openEvents.delete(event.id);
  });

  const level = Number(event.level || 0);
  const summary = document.createElement("summary");
  const identity = document.createElement("div");
  identity.className = "event-head";
  const title = document.createElement("span");
  title.className = "event-type";
  title.textContent = labels[event.event_type] || event.event_type || "Event";
  const host = document.createElement("span");
  host.className = "event-host";
  host.textContent = String(event.host_id || "-").replace("server-", "").toUpperCase();
  const time = document.createElement("span");
  time.className = "event-time";
  time.textContent = formatClock(event.timestamp);
  identity.append(title, host, time);

  const file = document.createElement("div");
  file.className = "event-file";
  file.textContent = event.path || "-";
  summary.append(identity, file);

  const decision = document.createElement("div");
  decision.className = "decision";
  const risk = document.createElement("span");
  risk.className = `risk-mark${level >= 3 ? " alert" : level >= 2 ? " warn" : ""}`;
  risk.textContent = `Risiko ${Number(event.risk || 0).toFixed(2)} · L${level}`;
  const verdict = document.createElement("strong");
  verdict.textContent = event.advisor_verdict || "dicatat";
  decision.append(risk, verdict);
  row.classList.toggle("level-alert", level >= 3);
  row.classList.toggle("level-warn", level === 2);
  row.append(summary, decision);

  if (event.old_hash || event.new_hash) {
    const hashes = document.createElement("div");
    hashes.className = "event-hashes";
    const oldValue = document.createElement("span");
    oldValue.textContent = "Lama ";
    const oldHash = document.createTextNode(event.old_hash || "-");
    const newValue = document.createElement("span");
    newValue.textContent = " Baru ";
    hashes.append(oldValue, oldHash, newValue, document.createTextNode(event.new_hash || "-"));
    row.append(hashes);
  }
  return row;
}

function renderEvents() {
  const selectedHost = hostFilter.value;
  const rows = displayedEvents.filter((event) => selectedHost === "all" || event.host_id === selectedHost);
  eventList.replaceChildren();
  eventList.setAttribute("aria-busy", "false");
  if (!displayedEvents.length) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "Belum ada event.";
    eventList.append(empty);
    return;
  }
  if (!rows.length) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = `Belum ada event di ${selectedHost}.`;
    eventList.append(empty);
    return;
  }
  for (const event of rows) eventList.append(createEventRow(event));
}

async function refresh() {
  const connection = $("#connection");
  try {
    const response = await fetch("/v1/dashboard", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    renderState(await response.json());
    $("#load-error").hidden = true;
    connection.className = "connection connected";
    connection.lastChild.textContent = "Online";
  } catch (error) {
    $("#load-error").hidden = false;
    connection.className = "connection disconnected";
    connection.lastChild.textContent = "Terputus";
    eventList.setAttribute("aria-busy", "false");
    if (!displayedEvents.length) {
      eventList.replaceChildren();
      const message = document.createElement("p");
      message.className = "empty-state";
      message.textContent = "Collector tidak merespons.";
      eventList.append(message);
    }
    console.error("Dashboard refresh failed", error);
  }
}

hostFilter.addEventListener("change", renderEvents);

// Kelopak sakura mengikuti cursor, dibatasi agar tetap ringan.
let lastPetalAt = 0;
document.addEventListener("pointermove", (event) => {
  const now = performance.now();
  if (now - lastPetalAt < 90) return;
  lastPetalAt = now;

  const petal = document.createElement("i");
  const size = 7 + Math.random() * 7;
  petal.className = "sakura-petal";
  petal.style.width = `${size}px`;
  petal.style.height = `${size}px`;
  petal.style.left = `${event.clientX - size / 2}px`;
  petal.style.top = `${event.clientY - size / 2}px`;
  petal.style.animation = `fall ${1.8 + Math.random() * 0.8}s cubic-bezier(.2,.7,.4,1) forwards`;
  document.body.append(petal);
  petal.addEventListener("animationend", () => petal.remove());
});

// Sidebar tabs
const sidebarTabs = document.querySelectorAll('.s-tab');
sidebarTabs.forEach((tab) => {
  tab.addEventListener('click', () => {
    sidebarTabs.forEach((t) => t.classList.remove('active'));
    tab.classList.add('active');
    document.querySelectorAll('.s-panel').forEach((p) => p.classList.remove('active'));
    const target = document.getElementById(tab.dataset.target);
    if (target) target.classList.add('active');
  });
});

// Sidebar close (drawer mode on small screens)
const sidebarClose = $("#sidebar-close");
const sidebarOpen = $("#sidebar-open");
const detailsSidebar = $("#details-sidebar");
if (sidebarClose && detailsSidebar) {
  sidebarClose.addEventListener('click', () => {
    detailsSidebar.classList.remove('drawer-open');
  });
}
if (sidebarOpen && detailsSidebar) {
  sidebarOpen.addEventListener('click', () => {
    detailsSidebar.classList.add('drawer-open');
  });
}

function scheduleRefresh() {
  const busy = !$("#patrol-incident").hidden || Date.now() < (window.__patrol?.patrol.fastUntil || 0);
  window.setTimeout(async () => { await refresh(); scheduleRefresh(); }, busy ? 1000 : 2500);
}
refresh();
scheduleRefresh();
refreshEvidence();
window.setInterval(refreshEvidence, 15000);
