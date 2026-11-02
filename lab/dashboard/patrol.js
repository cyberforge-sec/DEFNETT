/* DEFNETT patrol — game-style visualisation of file patrol, intrusion, isolation and repair.
 * Data sources: /api/patrol/state, /api/patrol/stream (SSE), /v1/dashboard (playbook stages).
 * Everything is wrapped in an IIFE so names never collide with dashboard.js. */
(() => {
"use strict";

/* ───────────────────────── state ───────────────────────── */
const patrol = {
  files: [], events: [], demoEvents: [], selected: null, demo: false, paused: false,
  speed: 1, filter: "all", source: null, demoTimer: null, demoCycle: 0, demoKeyIdx: 0, layout: [],
  seen: new Set(), primed: false, analysis: {}, incidentHost: "server-a",
};
const canvas = document.querySelector("#patrol-canvas");
const ctx = canvas.getContext("2d", { alpha: false });
const hosts = ["server-a", "server-b"];
const HOST_LABEL = { "server-a": "Server A", "server-b": "Server B" };
const severityRank = { safe: 0, suspicious: 1, compromised: 2 };
const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
const $ = (selector) => document.querySelector(selector);

/* ───────────────────────── text helpers ───────────────────────── */
function cleanText(value, max = 180) {
  return String(value ?? "").replace(/[\u0000-\u001f\u007f<>]/g, " ").replace(/\s+/g, " ").trim().slice(0, max);
}
function cleanPath(value) {
  const path = cleanText(value, 2048).replace(/\\/g, "/");
  return path.split("/").filter((part) => part && part !== "." && part !== "..").join("/") || "root";
}
function safeSeverity(value) {
  return Object.prototype.hasOwnProperty.call(severityRank, value) ? value : "safe";
}
const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
const baseName = (path) => cleanPath(path).split("/").at(-1);
const fkey = (host, path) => `${host}:${cleanPath(path)}`;

/* ───────────────────────── sidebar data ───────────────────────── */
function latestEvents() {
  return [...patrol.events, ...patrol.demoEvents]
    .sort((a, b) => Date.parse(b.ts || 0) - Date.parse(a.ts || 0)).slice(0, 100);
}
function activeActors() {
  const cutoff = Date.now() - 60000;
  const latest = new Map();
  for (const event of latestEvents()) {
    if (event.actor === "police" || Date.parse(event.ts || 0) < cutoff) continue;
    if (patrol.filter !== "all" && severityRank[safeSeverity(event.severity)] < severityRank[patrol.filter]) continue;
    const key = `${event.host_id}:${event.actor}`;
    if (!latest.has(key)) latest.set(key, event);
  }
  return [...latest.values()];
}
function filteredEvents() {
  return latestEvents().filter((event) => patrol.filter === "all" || (severityRank[event.severity] || 0) >= severityRank[patrol.filter]);
}
function renderCounters() {
  const latest = latestEvents();
  const risky = new Map();
  for (const event of latest) {
    if (event.actor === "police" || event.severity === "safe") continue;
    const key = `${event.host_id}:${cleanPath(event.path)}`;
    const severity = safeSeverity(event.severity);
    if (!risky.has(key) || severityRank[severity] > severityRank[risky.get(key)]) risky.set(key, severity);
  }
  const values = [...risky.values()];
  const unsafeFiles = patrol.files.filter((file) => risky.has(fkey(file.host_id, file.path))).length;
  // Updated to use new KPI bar IDs
  $("#patrol-safe-count").textContent = String(Math.max(0, patrol.files.length - unsafeFiles));
  $("#patrol-suspicious-count").textContent = String(values.filter((v) => v === "suspicious").length);
  $("#patrol-compromised-count").textContent = String(values.filter((v) => v === "compromised").length);
  // Also update KPI chip
  const chipA = $("#chip-backend-a");
  const chipB = $("#chip-backend-b");
  // ... counters already update KPI chips via dashboard.js renderState
  $("#patrol-actor-count").textContent = String(activeActors().length);
  $("#patrol-event-count").textContent = String(latest.length);
}
function detailText(event) {
  const time = event.ts ? new Date(event.ts).toLocaleString("id-ID") : "—";
  const hash = (v) => (/^[a-f0-9]{64}$/.test(v || "") ? v : "—");
  const path = cleanPath(event.path);
  return `${time} · ${cleanText(event.action)} · ${path}${path ? " · " : ""}${hash(event.hash_old)} → ${hash(event.hash_new)}`;
}
function showDetail(value) {
  patrol.selected = value;
  $("#patrol-detail").textContent = typeof value === "string" ? value : detailText(value);
}
function fileCategory(path) {
  const name = baseName(path).toLowerCase();
  if (name === ".env" || name.includes("secret") || name.startsWith("id_rsa")) return "safe";
  if (name.startsWith("kunci") && name.endsWith(".dat")) return "key";
  if ([".key", ".pem", ".p12", ".pfx"].some((s) => name.endsWith(s))) return "key";
  if ([".db", ".sqlite", ".sqlite3"].some((s) => name.endsWith(s))) return "gold";
  if (name === "config" || name.startsWith("config.") || [".json", ".yml", ".yaml", ".ini", ".conf", ".toml", ".config"].some((s) => name.endsWith(s))) return "document";
  return "box";
}
function severityForFile(file) {
  const event = latestEvents().find((item) => item.host_id === file.host_id && cleanPath(item.path) === cleanPath(file.path));
  return event?.severity || "safe";
}
function emptyNote(tag, text) {
  const node = document.createElement(tag);
  node.className = "patrol-empty";
  node.textContent = text;
  return node;
}
function renderFiles() {
  const node = $("#patrol-files");
  node.replaceChildren();
  $("#patrol-file-count").textContent = String(Math.min(80, patrol.files.length));
  if (!patrol.files.length) { node.append(emptyNote("p", "Snapshot kosong.")); return; }
  for (const file of patrol.files.slice(0, 80)) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `patrol-file-row severity-${safeSeverity(severityForFile(file))}`;
    const name = document.createElement("span");
    name.textContent = `${file.host_id} · ${cleanPath(file.path)}`;
    const hash = document.createElement("small");
    hash.textContent = /^[a-f0-9]{64}$/.test(file.sha256 || "") ? file.sha256 : "—";
    button.append(name, hash);
    button.addEventListener("click", () => showDetail({
      ts: file.checked_at, actor: "police", host_id: file.host_id, action: "read",
      path: file.path, hash_new: file.sha256, severity: severityForFile(file),
    }));
    node.append(button);
  }
}
function renderActors() {
  const node = $("#patrol-actors");
  node.replaceChildren();
  const actors = activeActors();
  if (!actors.length) { node.append(emptyNote("p", "Belum ada aktor.")); return; }
  for (const event of actors.slice(0, 8)) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `actor-row severity-${safeSeverity(event.severity)}`;
    const head = document.createElement("strong");
    head.textContent = cleanText(event.actor, 96);
    const description = document.createElement("span");
    description.textContent = `${safeSeverity(event.severity)} · ${cleanPath(event.path)}`;
    const action = document.createElement("small");
    action.textContent = `${event.source === "demo" ? "DEMO · " : ""}${cleanText(event.host_id, 32)} · ${cleanText(event.action, 20)} · ${cleanText(event.status || "observed", 32)}`;
    button.append(head, description, action);
    button.addEventListener("click", () => showDetail(event));
    node.append(button);
  }
}
function renderPatrolEvents() {
  const node = $("#patrol-events");
  node.replaceChildren();
  const events = filteredEvents();
  if (!events.length) {
    node.append(emptyNote("li", patrol.filter === "all" ? "Menunggu event…" : "Tidak ada event di filter ini."));
    return;
  }
  for (const event of events.slice(0, 24)) {
    const item = document.createElement("li");
    const button = document.createElement("button");
    button.type = "button";
    button.className = `patrol-event-row severity-${safeSeverity(event.severity)}`;
    const title = document.createElement("strong");
    title.textContent = `${cleanText(event.type, 24)} · ${cleanText(event.action, 20)}`;
    const path = document.createElement("span");
    path.textContent = cleanPath(event.path);
    const actor = document.createElement("small");
    actor.textContent = `${event.source === "demo" ? "DEMO · " : ""}${cleanText(event.host_id, 32)} · ${cleanText(event.actor, 96)} · ${safeSeverity(event.severity)}`;
    button.append(title, path, actor);
    button.addEventListener("click", () => showDetail(event));
    item.append(button);
    node.append(item);
  }
}
function refreshPatrol() {
  renderCounters(); renderFiles(); renderActors(); renderPatrolEvents();
  $("#patrol-source-status").textContent = patrol.demo
    ? `Demo · ${patrol.files.length} file`
    : `${patrol.files.length} file · live`;
  layoutFiles();
}

/* ───────────────────────── world geometry ───────────────────────── */
const WORLD_W = 900;
function worldHeight() {
  const rows = Math.ceil(Math.max(1, ...hosts.map((h) => patrol.layout.filter((f) => f.host_id === h).length || patrol.files.filter((f) => f.host_id === h).length)) / 4);
  return Math.max(540, 300 + rows * 77);
}
function roomRect(host) {
  const h = worldHeight();
  return { x: host === "server-b" ? 462 : 28, y: 70, w: 410, h: h - 70 - 112 };
}
const doorOf = (host) => { const r = roomRect(host); return { x: r.x + r.w / 2, y: r.y + r.h }; };
const roadY = () => worldHeight() - 44;
const postOf = (host) => { const d = doorOf(host); return { x: d.x - 112, y: d.y + 36 }; };
const hubPos = { x: 450, y: 30 };
const cableCut = (host) => ({ x: doorOf(host).x, y: 46 });

function layoutFiles() {
  const list = [];
  const known = new Set();
  for (const host of hosts) {
    const room = roomRect(host);
    const files = patrol.files.filter((f) => f.host_id === host);
    const extra = [...fstate.keys()].filter((k) => k.startsWith(`${host}:`) && !files.some((f) => fkey(host, f.path) === k))
      .map((k) => ({ host_id: host, path: k.slice(host.length + 1), virtual: true }));
    [...files, ...extra].forEach((file, index) => {
      const col = index % 4, row = Math.floor(index / 4);
      list.push({ ...file, x: room.x + 70 + col * 88, y: room.y + 130 + row * 77 });
      known.add(fkey(host, file.path));
    });
  }
  patrol.layout = list;
}
const fileAt = (host, path) => patrol.layout.find((f) => f.host_id === host && cleanPath(f.path) === cleanPath(path));
const filesOf = (host) => patrol.layout.filter((f) => f.host_id === host);

/* ───────────────────────── simulation clock + scheduler ───────────────────────── */
const sim = { t: 0, last: 0, tasks: [], shake: 0 };
function later(ms, fn, sc) {
  sim.tasks.push({ at: sim.t + ms, fn, sc, token: sc ? sc.token : 0 });
}
function runTasks() {
  const due = sim.tasks.filter((task) => task.at <= sim.t);
  if (!due.length) return;
  sim.tasks = sim.tasks.filter((task) => task.at > sim.t);
  for (const task of due) if (!task.sc || task.sc.token === task.token) task.fn();
}

/* ───────────────────────── file effect states ───────────────────────── */
const fstate = new Map();       // host:path -> { s: stolen|tampered|deleted|infected, at }
const scanFlash = new Map();    // host:path -> sim.t
function setFileState(host, path, s) { fstate.set(fkey(host, path), { s, at: sim.t }); layoutFiles(); }
function fileState(file) { return fstate.get(fkey(file.host_id, file.path))?.s || "ok"; }
function clearFileStates(host) {
  for (const key of [...fstate.keys()]) if (key.startsWith(`${host}:`)) fstate.delete(key);
  layoutFiles();
}

/* ───────────────────────── particles / floating text / bullets ───────────────────────── */
const parts = [];
const bullets = [];
function burst(x, y, n, colors, opt = {}) {
  for (let i = 0; i < n; i++) {
    const angle = Math.random() * Math.PI * 2, speed = (opt.speed || 90) * (0.35 + Math.random() * 0.8);
    parts.push({ k: "sq", x, y, vx: Math.cos(angle) * speed, vy: Math.sin(angle) * speed - (opt.up || 0), g: opt.g ?? 160,
      life: 0, max: (opt.life || 650) * (0.6 + Math.random() * 0.7), size: opt.size || 3, c: colors[i % colors.length] });
  }
}
const sparks = (x, y, n = 10) => burst(x, y, n, ["#ffe27a", "#ffb43a", "#fff6c9"], { speed: 150, g: 260, life: 420, size: 2.5 });
const smoke = (x, y, n = 8) => burst(x, y, n, ["#d7d9d3", "#b8bcb6", "#f0f0ea"], { speed: 50, g: -30, life: 800, size: 6, up: 20 });
const greenSparks = (x, y, n = 12) => burst(x, y, n, ["#7be3b0", "#c9ffe2", "#3fbf86"], { speed: 120, g: 120, life: 700, size: 3 });
function popup(x, y, text, color = "#fff", size = 11) {
  parts.push({ k: "tx", x, y, vx: 0, vy: -26, g: 0, life: 0, max: 1500, text, c: color, size });
}
function ring(x, y, color, max = 700, radius = 34) {
  parts.push({ k: "ring", x, y, vx: 0, vy: 0, g: 0, life: 0, max, c: color, r: radius });
}
function shake(ms) { if (!reduceMotion.matches) sim.shake = Math.max(sim.shake, ms); }
function updateParts(dt) {
  for (const p of parts) {
    p.life += dt;
    p.vy += p.g * dt / 1000;
    p.x += p.vx * dt / 1000; p.y += p.vy * dt / 1000;
  }
  for (let i = parts.length - 1; i >= 0; i--) if (parts[i].life >= parts[i].max) parts.splice(i, 1);
  if (parts.length > 400) parts.splice(0, parts.length - 400);
  sim.shake = Math.max(0, sim.shake - dt);
}

/* ───────────────────────── actors ───────────────────────── */
class Actor {
  constructor(role, host, x, y, extra = {}) {
    Object.assign(this, {
      role, host, x, y, dir: 1, pose: "idle", queue: [], cur: null, phase: 0, moving: false,
      alpha: 1, bubble: null, ko: false, hit: 0, t: 0, carry: false, hold: null, loop: null,
      aimUntil: 0, flashUntil: 0, inside: false, trapped: false, dead: false, beam: null, nextSpark: 0, tag: "",
    }, extra);
  }
  go(x, y, speed = 70, pose = "walk") { this.queue.push({ k: "walk", x, y, speed, pose }); return this; }
  wait(ms, pose = "idle", say = null, tone = "info") { this.queue.push({ k: "wait", ms, pose, say, tone }); return this; }
  call(fn) { this.queue.push({ k: "call", fn }); return this; }
  stop() { this.queue = []; this.cur = null; this.moving = false; this.loop = null; return this; }
  say(text, ms = 1800, tone = "info") { this.bubble = { text, until: sim.t + ms, tone }; return this; }
}
function updateActor(a, dt) {
  a.t += dt;
  if (a.hit > 0) a.hit = Math.max(0, a.hit - dt);
  if (a.bubble && a.bubble.until < sim.t) a.bubble = null;
  if (a.ko) {
    a.moving = false; a.pose = "ko";
    if (a.slideTo) {
      const dx = a.slideTo.x - a.x, dy = a.slideTo.y - a.y, d = Math.hypot(dx, dy), step = 70 * dt / 1000;
      if (d <= step) { a.x = a.slideTo.x; a.y = a.slideTo.y; a.slideTo = null; } else { a.x += dx / d * step; a.y += dy / d * step; }
    }
    return;
  }
  for (let guard = 0; guard < 14; guard++) {
    if (!a.cur && !a.queue.length && a.loop && !a.looping) { a.looping = true; a.loop(a); a.looping = false; }
    if (!a.cur) {
      a.cur = a.queue.shift() || null;
      if (a.cur) { a.cur.t = 0; if (a.cur.k === "wait" && a.cur.say) a.say(a.cur.say, Math.max(1300, a.cur.ms), a.cur.tone); }
    }
    const s = a.cur;
    if (!s) { a.moving = false; a.pose = a.hold || "idle"; return; }
    if (s.k === "call") { a.cur = null; s.fn(a); continue; }
    if (s.k === "wait") {
      a.pose = s.pose; a.moving = false; s.t += dt;
      if (s.t >= s.ms) { a.cur = null; continue; }
      return;
    }
    const dx = s.x - a.x, dy = s.y - a.y, dist = Math.hypot(dx, dy);
    const step = (reduceMotion.matches ? 1e5 : s.speed) * dt / 1000;
    a.pose = s.pose;
    if (dist <= step) { a.x = s.x; a.y = s.y; a.cur = null; a.moving = false; continue; }
    a.x += dx / dist * step; a.y += dy / dist * step;
    if (Math.abs(dx) > 1.5) a.dir = dx > 0 ? 1 : -1;
    a.moving = true; a.phase += step * 0.2;
    return;
  }
}

/* ───────────────────────── scenes (one per server) ───────────────────────── */
const STAGES = ["DETECTED", "ISOLATING", "ISOLATED", "REPAIRING", "VERIFYING", "REJOINING", "REPAIRED"];
const MIN_MS = { DETECTED: 2200, ISOLATING: 2000, ISOLATED: 1600, REPAIRING: 6000, VERIFYING: 2200, REJOINING: 2000, REPAIRED: 8000, FAILED: 0 };
const STAGE_TEXT = {
  DETECTED: ["INTRUDER TERDETEKSI", "#e0584a"], ISOLATING: ["MEMUTUS KONEKSI", "#e68a2e"], ISOLATED: ["SERVER TERISOLASI", "#e0584a"],
  REPAIRING: ["MAINTENANCE", "#e6b23a"], VERIFYING: ["VERIFIKASI FILE", "#5aa9e6"], REJOINING: ["SAMBUNG ULANG", "#3fb7a4"],
  REPAIRED: ["SERVER ONLINE", "#3fbf86"], FAILED: ["PEMULIHAN GAGAL", "#e0584a"],
};
const scene = {};
const police = {};
const guards = {};
const thieves = new Map();
let thiefSeq = 0;

function makeScene(host) {
  return {
    host, token: 0, runId: null, ignored: null, vis: null, visSince: 0, queue: [], seen: new Set(), stageTs: {},
    shutter: 0, shutTarget: 0, cut: 0, cutTarget: 0, door: 0, alarm: false, banner: null, thief: null,
    sealed: false, backend: "UNKNOWN", ended: true, demoRun: false, progressMs: 0, repairStart: 0, delayMs: 0,
    cutFx: false, joinFx: false, run: null,
  };
}
function initActors() {
  for (const host of hosts) {
    scene[host] = makeScene(host);
    const d = doorOf(host), p = postOf(host);
    police[host] = new Actor("police", host, d.x + 30, d.y - 40, { tag: "POLISI·AI" });
    guards[host] = new Actor("guard", host, p.x, p.y, { tag: "SATPAM" });
  }
}
const incidentActive = (host) => Boolean(scene[host].vis) && !scene[host].ended;

/* ───────────────────────── thieves (attackers) ───────────────────────── */
const thiefList = () => [...thieves.values()].filter((t) => !t.dead);
function sideOf(host) { return host === "server-a" ? -1 : 1; }

function panicLoop(a) {
  const R = roomRect(a.host);
  const x = R.x + 40 + Math.random() * (R.w - 80), y = R.y + 150 + Math.random() * Math.max(60, R.h - 210);
  const lines = ["Tolong!", "Kok terkunci?!", "Ampun!", "Keluarkan aku!"];
  a.go(x, y, 125, "run").wait(280, "panic", Math.random() < 0.28 ? lines[Math.floor(Math.random() * lines.length)] : null, "bad");
}
function trapThief(th) {
  th.trapped = true; th.loop = panicLoop; th.leaving = false;
}
function thiefLeave(th) {
  if (th.dead) return;
  const D = doorOf(th.host), side = sideOf(th.host), pose = th.carry ? "carry" : "run";
  th.leaving = true; th.loop = null; th.stop();
  th.go(D.x, D.y - 26, 130, pose).go(D.x, D.y + 12, 130, pose)
    .call((a) => { a.inside = false; if (a.carry) { popup(D.x, D.y - 26, "EXFIL!", "#e0584a", 12); } })
    .go(D.x, roadY(), 135, pose).go(side < 0 ? -50 : 950, roadY(), 150, pose)
    .call((a) => { a.dead = true; });
}
function thiefNext(th) {
  if (th.dead) return;
  const next = th.more.shift();
  if (next) { thiefWork(th, next.ev, next.action); return; }
  if (incidentActive(th.host) || scene[th.host].shutTarget > 0.5) { trapThief(th); return; }
  if (th.lurk && !th.carry) {
    th.lurkUntil = th.lurkUntil || sim.t + 9000;
    th.loop = (a) => {
      if (incidentActive(a.host)) { trapThief(a); return; }
      if (sim.t > a.lurkUntil) { a.loop = null; thiefLeave(a); return; }
      const fs = filesOf(a.host), f = fs[Math.floor(Math.random() * fs.length)];
      if (f) a.go(f.x + (Math.random() - 0.5) * 40, f.y + 30, 48, "sneak").wait(900, "peek");
      else a.wait(900, "idle");
    };
    return;
  }
  thiefLeave(th);
}
function thiefWork(th, ev, action) {
  const host = th.host, R = roomRect(host);
  let f = fileAt(host, ev.path);
  if (!f && action === "plant") { fstate.set(fkey(host, ev.path), { s: "pending", at: sim.t }); layoutFiles(); f = fileAt(host, ev.path); }
  const fx0 = f ? f.x : R.x + R.w / 2 + (Math.random() - 0.5) * 120;
  const fy0 = f ? f.y : R.y + 190;
  const color = { compromised: "#e0584a", suspicious: "#e68a2e" }[safeSeverity(ev.severity)] || "#e6b23a";
  th.sev = safeSeverity(ev.severity);
  th.go(fx0, fy0 + 30, 82, "sneak");
  th.call((a) => { a.dir = fx0 >= a.x ? 1 : -1; });
  if (action === "download") {
    th.wait(850, "grab").call((a) => { setFileState(host, ev.path, "stolen"); a.carry = true; popup(fx0, fy0 - 24, "STOLEN!", color, 12); a.say("Dapat!", 1200, "bad"); });
  } else if (action === "modify") {
    th.wait(1900, "hammer").call((a) => { setFileState(host, ev.path, "tampered"); sparks(fx0, fy0, 12); popup(fx0, fy0 - 24, "MODIFIED", color, 12); });
  } else if (action === "delete") {
    th.wait(1000, "grab").call(() => { smoke(fx0, fy0, 10); setFileState(host, ev.path, "deleted"); popup(fx0, fy0 - 24, "DELETED", color, 12); });
  } else if (action === "plant") {
    th.wait(1600, "plant").call(() => { smoke(fx0, fy0, 8); setFileState(host, ev.path, "infected"); popup(fx0, fy0 - 28, "MALWARE DROP", color, 11); });
  } else {
    th.call((a) => { a.beam = { x: fx0, y: fy0 }; }).wait(2400, "peek", "Cek isi file…")
      .call((a) => { a.beam = null; popup(fx0, fy0 - 24, "READ", color, 11); });
  }
  th.call(() => thiefNext(th));
}
function spawnThief(host, id, ev, action, opts = {}) {
  const sc = scene[host], D = doorOf(host), side = sideOf(host);
  if (!sc) return null;
  const existing = thiefList().find((t) => t.host === host && t.id === id && !t.leaving && !t.ko);
  if (existing) { existing.more.push({ ev, action }); return existing; }
  if (thiefList().length >= 8) return null;
  const th = new Actor("thief", host, clamp(D.x + side * 150, 20, 880), roadY(), {
    id, uid: ++thiefSeq, more: [], lurk: Boolean(opts.lurk), tag: cleanText(opts.tag || id, 15),
  });
  thieves.set(th.uid, th);
  th.go(D.x, roadY(), 115, "walk");
  if (action === "denied" || sc.shutTarget > 0.5) {
    th.go(D.x, D.y + 16, 95, "sneak").call((a) => { shake(120); a.say("Terkunci!", 1400, "bad"); popup(D.x, D.y + 2, "DENIED ✕", "#e0584a", 12); })
      .wait(700, "panic").call((a) => { a.leaving = true; }).go(D.x, roadY(), 140, "run").go(side < 0 ? -50 : 950, roadY(), 150, "run").call((a) => { a.dead = true; });
    return th;
  }
  th.go(D.x, D.y + 12, 95, "sneak").go(D.x, D.y - 26, 80, "sneak").call((a) => { a.inside = true; });
  thiefWork(th, ev, action);
  return th;
}
function ensureThief(sc) {
  const host = sc.host, D = doorOf(host);
  let th = thiefList().find((t) => t.host === host && !t.leaving && !t.ko && t.inside)
    || thiefList().find((t) => t.host === host && !t.leaving && !t.ko);
  if (!th) {
    th = new Actor("thief", host, D.x, D.y - 26, { id: "intruder", uid: ++thiefSeq, more: [], tag: "INTRUDER", inside: true });
    thieves.set(th.uid, th); smoke(th.x, th.y - 10, 8);
  } else if (!th.inside) {
    th.stop(); th.x = D.x; th.y = D.y - 26; th.inside = true; smoke(th.x, th.y - 10, 6);
  }
  th.incident = true; th.more = []; sc.thief = th;
  return th;
}
function koThief(th) {
  th.stop(); th.ko = true; th.trapped = false; th.carry = false; th.beam = null; th.hit = 520; th.koAt = sim.t;
  sparks(th.x, th.y - 22, 14); popup(th.x, th.y - 50, "KO!", "#ffd24a", 15); shake(240);
}

/* ───────────────────────── police agent + guard ───────────────────────── */
function recentAlertFile(host) {
  const ev = latestEvents().find((e) => e.host_id === host && safeSeverity(e.severity) !== "safe" && Date.now() - Date.parse(e.ts || 0) < 12000);
  return ev ? fileAt(host, ev.path) : null;
}
function patrolNext(p) {
  const files = filesOf(p.host), R = roomRect(p.host);
  p.idx = (p.idx || 0) + 1;
  if (!files.length) {
    const pts = [[90, 190], [320, 190], [320, 330], [90, 330]];
    const [px, py] = pts[p.idx % pts.length];
    p.go(R.x + px, R.y + py - 60, 55).wait(900, "scan", "Menunggu snapshot…");
    return;
  }
  const f = recentAlertFile(p.host) || files[p.idx % files.length];
  const bad = fileState(f) !== "ok" || severityForFile(f) !== "safe";
  p.go(f.x, f.y + 34, bad ? 100 : 58, bad ? "run" : "walk");
  p.call((a) => { a.beam = { x: f.x, y: f.y }; scanFlash.set(fkey(f.host_id, f.path), sim.t); });
  p.wait(1300, "scan", `Cek ${baseName(f.path).slice(0, 12)}… ${bad ? "ALERT !" : "OK ✓"}`, bad ? "bad" : "good");
  p.call((a) => { a.beam = null; });
}
function updatePolice(host) {
  const p = police[host], sc = scene[host];
  if (sc.policeScript) {
    if (p.hold === "aim" && sc.thief && !sc.thief.dead) p.dir = sc.thief.x >= p.x ? 1 : -1;
    return;
  }
  const th = thiefList().find((t) => t.host === host && t.inside && !t.leaving && !t.ko);
  if (th) {
    if (sim.t >= (p.chaseAt || 0)) {
      p.chaseAt = sim.t + 750; p.stop(); p.beam = null;
      const dist = Math.hypot(th.x - p.x, th.y - p.y);
      if (dist > 105) p.go(th.x + (p.x >= th.x ? 70 : -70), th.y + 8, 115, "run");
      else { p.dir = th.x >= p.x ? 1 : -1; p.wait(760, "aim", "BERHENTI!", "bad"); }
    }
    return;
  }
  if (!p.cur && !p.queue.length) patrolNext(p);
}
function updateGuard(host) {
  const g = guards[host], sc = scene[host];
  if (sc.guardScript) return;
  if (g.cur || g.queue.length) return;
  const post = postOf(host);
  if (Math.hypot(g.x - post.x, g.y - post.y) > 8) { g.go(post.x, post.y, 80); return; }
  g.wait(2200 + Math.random() * 2600, "idle").call((a) => { a.dir = -a.dir; });
}
function fireShot(shooter, target, hit) {
  if (!target || target.dead) return;
  const dir = target.x >= shooter.x ? 1 : -1;
  shooter.dir = dir; shooter.aimUntil = sim.t + 650; shooter.flashUntil = sim.t + 110;
  const sx = shooter.x + dir * 29, sy = shooter.y - 27;
  let tx = target.x, ty = target.y - 18;
  if (!hit) { ty += 40; tx += dir * 30; }
  const dx = tx - sx, dy = ty - sy, dist = Math.max(1, Math.hypot(dx, dy)), speed = 640;
  bullets.push({ x: sx, y: sy, vx: dx / dist * speed, vy: dy / dist * speed, life: 0, max: dist / speed * 1000 + (hit ? 400 : 40), target: hit ? target : null, trail: [] });
  burst(sx, sy, 7, ["#fff3b0", "#ffd24a"], { speed: 130, g: 0, life: 170, size: 3 });
  shake(120);
  if (!hit) target.say("Hii!", 900, "bad");
}
function updateBullets(dt) {
  for (let i = bullets.length - 1; i >= 0; i--) {
    const b = bullets[i];
    if (b.target && !b.target.dead) {
      const tx = b.target.x, ty = b.target.y - 18, dx = tx - b.x, dy = ty - b.y, d = Math.max(1, Math.hypot(dx, dy));
      b.vx = dx / d * 640; b.vy = dy / d * 640;
      if (d < 16) { koThief(b.target); bullets.splice(i, 1); continue; }
    }
    b.trail.push({ x: b.x, y: b.y }); if (b.trail.length > 5) b.trail.shift();
    b.x += b.vx * dt / 1000; b.y += b.vy * dt / 1000; b.life += dt;
    if (b.life > b.max) { sparks(b.x, b.y, 7); bullets.splice(i, 1); }
  }
}

/* ───────────────────────── incident choreography ───────────────────────── */
const KEY_PATHS = ["etc/kunci1.dat", "etc/kunci2.dat"];
function keyFiles(host) {
  return KEY_PATHS.map((p) => fileAt(host, p)).filter(Boolean);
}
function affectedFiles(host) {
  const R = roomRect(host);
  let list = filesOf(host).filter((f) => fileState(f) !== "ok");
  const runPath = scene[host].run?.path;
  if (!list.length && runPath) { const f = fileAt(host, runPath); if (f) list = [f]; }
  if (list.some((f) => KEY_PATHS.includes(f.path))) {
    const rest = list.filter((f) => !KEY_PATHS.includes(f.path));
    list = [...rest, ...keyFiles(host)];  // pasangan kunci diperbaiki dan diverifikasi bersama
  }
  if (!list.length) list = keyFiles(host);
  if (!list.length) list = filesOf(host).slice(0, 2);
  if (!list.length) list = [{ host_id: host, path: "artifact", x: R.x + R.w / 2, y: R.y + 200, virtual: true }];
  return list;
}
function repairLoop(a) {
  const sc = scene[a.host], list = affectedFiles(a.host);
  sc.repairIdx = (sc.repairIdx || 0) + 1;
  const f = list[sc.repairIdx % list.length];
  a.go(f.x + 28, f.y + 22, 80).call((g) => { g.dir = -1; })
    .wait(2700, "repair").call(() => { sparks(f.x, f.y, 9); popup(f.x, f.y - 26, "fixing…", "#ffd24a", 10); });
}
function settleKo(sc) {
  const th = ensureThief(sc), R = roomRect(sc.host);
  th.stop(); th.x = R.x + R.w / 2 + 70; th.y = R.y + 250; th.ko = true; th.koAt = sim.t - 3000; th.inside = true; th.dir = 1;
}
function resetIncident(sc) {
  sc.token++; sc.queue = []; sc.seen = new Set(); sc.stageTs = {}; sc.vis = null; sc.ended = true;
  sc.policeScript = false; sc.guardScript = false; sc.alarmStage = false; sc.maint = false;
  sc.thief = null; sc.repairIdx = 0; sc.banner = null;
  police[sc.host].hold = null; guards[sc.host].loop = null;
}
function endIncident(sc) {
  const host = sc.host;
  sc.vis = null; sc.ended = true; sc.policeScript = false; sc.guardScript = false; sc.alarmStage = false; sc.maint = false; sc.thief = null;
  police[host].hold = null; police[host].stop(); guards[host].loop = null; guards[host].stop();
  clearFileStates(host);
}
function enterStage(sc, stage, opt = {}) {
  const host = sc.host, D = doorOf(host), R = roomRect(host), P = postOf(host);
  const pol = police[host], gd = guards[host], settle = Boolean(opt.settle);
  const snap = (shut, cut) => { sc.shutter = sc.shutTarget = shut; sc.cut = sc.cutTarget = cut; sc.cutFx = cut > 0.5; };
  const stand = { x: D.x + 72, y: D.y - 96 };
  sc.vis = stage; sc.visSince = sim.t; sc.ended = false; sc.policeScript = true;
  const [text, color] = STAGE_TEXT[stage] || [stage, "#fff"];
  sc.banner = { text, color, at: sim.t, until: sim.t + 2800 };
  sc.alarmStage = ["DETECTED", "ISOLATING", "ISOLATED", "FAILED"].includes(stage);
  sc.maint = ["REPAIRING", "VERIFYING"].includes(stage);
  switch (stage) {
    case "DETECTED": {
      const th = ensureThief(sc);
      th.stop(); th.say("Ketahuan!", 1800, "bad"); th.wait(2600, "panic");
      ring(th.x, th.y - 20, "#e0584a", 900, 42); shake(260);
      const sgn = pol.x >= th.x ? 1 : -1;
      pol.stop(); pol.hold = null; pol.beam = null;
      pol.go(th.x + sgn * 78, th.y + 8, 125, "run").call((a) => { a.hold = "aim"; a.say("BERHENTI!", 1600, "bad"); });
      gd.stop(); gd.say("Alarm! Ada intruder!", 2200, "bad");
      break;
    }
    case "ISOLATING": {
      if (settle) snap(1, 1);
      else {
        later(450, () => { sc.shutTarget = 1; popup(D.x, D.y - 66, "GERBANG DITUTUP", "#e68a2e", 11); }, sc);
        later(1500, () => { sc.cutTarget = 1; }, sc);
      }
      const th = ensureThief(sc);
      th.stop(); th.go(D.x, D.y - 30, 150, "run").call((a) => { a.say("Pintunya nutup!", 1900, "bad"); shake(200); }).wait(500, "panic");
      trapThief(th);
      pol.stop(); pol.hold = "aim"; pol.go(stand.x, stand.y, 115, "run");
      break;
    }
    case "ISOLATED": {
      sc.shutTarget = 1; sc.cutTarget = 1; if (settle) snap(1, 1);
      const th = ensureThief(sc);
      if (!th.trapped) { th.stop(); trapThief(th); }
      pol.stop(); pol.hold = "aim"; pol.go(stand.x, stand.y, 100, "run");
      popup(D.x, D.y - 84, "Intruder terjebak di dalam", "#ffd0c8", 10);
      gd.say("Siap maintenance", 2200);
      break;
    }
    case "REPAIRING": {
      sc.guardScript = true; sc.repairStart = sim.t; sc.repairIdx = 0;
      const th = ensureThief(sc);
      if (settle) {
        snap(1, 1); settleKo(sc);
        pol.stop(); pol.hold = null; pol.x = th.x + 46; pol.y = th.y + 6; pol.dir = -1;
        gd.stop(); gd.x = R.x + 120; gd.y = R.y + 230; gd.loop = repairLoop;
        break;
      }
      sc.shutTarget = 1; sc.cutTarget = 1;
      gd.stop(); gd.hold = null; gd.say("Maintenance dimulai", 1800);
      gd.go(D.x - 22, D.y + 30, 90).wait(750, "badge")
        .call(() => { sc.shutTarget = 0; popup(D.x, D.y + 40, "AKSES DIBERIKAN", "#7be3b0", 10); });
      later(3200, () => {
        if (th.ko || th.dead) return;
        th.stop(); th.trapped = false; th.say("KABUR!", 1500, "bad"); th.go(D.x, D.y - 24, 150, "run");
      }, sc);
      later(3900, () => fireShot(pol, th, false), sc);
      later(4600, () => fireShot(pol, th, true), sc);
      later(5400, () => {
        const spot = { x: R.x + R.w / 2 + 70, y: R.y + 250 };
        th.slideTo = spot;
        pol.stop(); pol.hold = null; pol.go(spot.x + 46, spot.y + 6, 72).call((a) => { a.dir = -1; a.say("Intruder dilumpuhkan", 2600, "good"); });
        gd.stop(); gd.go(D.x - 14, D.y - 22, 85).call(() => { sc.shutTarget = 1; }).go(R.x + R.w / 2 - 60, R.y + 215, 80);
        gd.loop = repairLoop;
      }, sc);
      break;
    }
    case "VERIFYING": {
      sc.guardScript = true;
      if (settle) { snap(1, 1); settleKo(sc); pol.hold = null; }
      gd.loop = null; gd.stop(); gd.hold = null; gd.say("Verifikasi file…", 1800);
      for (const f of affectedFiles(host)) {
        gd.go(f.x + 26, f.y + 22, 85).wait(1000, "clip").call(() => {
          fstate.delete(fkey(host, f.path)); layoutFiles();
          popup(f.x, f.y - 26, "✓ bersih", "#7be3b0", 11); greenSparks(f.x, f.y, 10); ring(f.x, f.y, "#7be3b0", 700, 30);
        });
      }
      gd.go(R.x + R.w / 2, R.y + 175, 80).wait(1500, "clip");
      break;
    }
    case "REJOINING": {
      sc.guardScript = true;
      if (settle) { snap(1, 1); settleKo(sc); }
      gd.loop = null; gd.stop(); gd.say("Health check HAProxy…", 2400);
      later(700, () => { sc.cutTarget = 0; }, sc);
      later(2900, () => { sc.shutTarget = 0; popup(D.x, D.y - 66, "GERBANG DIBUKA", "#7be3b0", 11); }, sc);
      later(3300, () => { gd.stop(); gd.go(D.x - 10, D.y - 22, 85).go(D.x - 10, D.y + 26, 85).go(P.x, P.y, 80); }, sc);
      break;
    }
    case "REPAIRED": {
      sc.guardScript = true; sc.shutTarget = 0; sc.cutTarget = 0;
      if (settle) snap(0, 0);
      clearFileStates(host);
      for (let i = 0; i < 6; i++) later(i * 260, () => greenSparks(R.x + 40 + Math.random() * (R.w - 80), R.y + 60 + Math.random() * 80, 10), sc);
      gd.loop = null; gd.stop(); gd.go(P.x, P.y, 80).call((a) => { a.say("Server aman", 2400, "good"); });
      const th = sc.thief;
      if (th && !th.dead) {
        pol.stop(); pol.hold = null; pol.go(th.x + 46, th.y + 6, 80).call((a) => { a.say("Diamankan!", 2000, "good"); });
        later(2600, () => { smoke(th.x, th.y - 10, 14); popup(th.x, th.y - 44, "DIAMANKAN", "#7be3b0", 12); th.dead = true; }, sc);
      }
      break;
    }
    case "FAILED": {
      sc.guardScript = true;
      if (sc.seen.has("ISOLATING")) { sc.shutTarget = 1; sc.cutTarget = 1; }
      gd.loop = null; gd.stop(); gd.say("Gagal! Perlu operator", 3000, "bad");
      break;
    }
    default: break;
  }
}
function advanceScene(sc) {
  if (sc.queue.length) {
    const wait = sc.vis ? (MIN_MS[sc.vis] ?? 0) : 0;
    if (!sc.vis || sim.t - sc.visSince >= wait) enterStage(sc, sc.queue.shift());
  } else if (sc.vis === "REPAIRED" && sim.t - sc.visSince >= MIN_MS.REPAIRED) {
    endIncident(sc);
  }
}
function applyRemediation(run, meta = {}) {
  if (!run || !hosts.includes(run.host_id)) return;
  const sc = scene[run.host_id];
  const steps = Array.isArray(run.steps) ? run.steps : [];
  const stages = steps.map((s) => s.stage).filter(Boolean);
  if (!stages.length && run.status) stages.push(run.status);
  const firstTs = Date.parse(steps[0]?.timestamp || run.started_at || "") || Date.now();
  if (sc.runId !== run.event_id) {
    if (sc.ignored === run.event_id) return;
    const doneTs = run.completed_at ? Date.parse(run.completed_at) : 0;
    if (doneTs && Date.now() - doneTs > 25000) { sc.ignored = run.event_id; return; }
    resetIncident(sc);
    sc.runId = run.event_id; sc.attackPending = false;
    sc.joinedLate = Date.now() - firstTs > 9000;
  }
  sc.run = run;
  const analysis = patrol.analysis || {};
  const delayHost = analysis.demo_repair_host;
  sc.delayMs = delayHost === "all" || run.host_id === delayHost ? Number(analysis.demo_repair_delay_seconds || 0) * 1000 : 0;
  for (const step of steps) if (step.stage && step.timestamp) sc.stageTs[step.stage] = Date.parse(step.timestamp);
  for (const stage of stages) if (!sc.seen.has(stage)) { sc.seen.add(stage); sc.queue.push(stage); }
  if (sc.joinedLate && sc.vis === null && sc.queue.length) {
    const last = sc.queue.at(-1);
    sc.queue = []; sc.joinedLate = false;
    enterStage(sc, last, { settle: true });
  }
}
/* Status server diambil dari HAProxy asli lewat collector; tidak ada status simulasi. */
const LB_TEXT = { UP: ["UP", "#6ee3b0"], MAINT: ["DOWN", "#ff6b5c"], DRAIN: ["DOWN", "#ff6b5c"], DOWN: ["DOWN", "#ff6b5c"], NOLB: ["CEK", "#e6b23a"] };
function lbStatus(host) {
  const status = scene[host].backend;
  const known = Object.keys(LB_TEXT).find((key) => status.startsWith(key));
  return LB_TEXT[known] || ["?", "#b8c4cc"];
}
function lbFlash(host, down) {
  const [color, text] = down ? ["#e0584a", "DOWN"] : ["#3fbf86", "UP"];
  popup(hubPos.x, hubPos.y + 42, `${HOST_LABEL[host]} ${text}`, color, 13);
  ring(hubPos.x, hubPos.y, color, 800, 64);
  if (down) shake(220); else greenSparks(hubPos.x, hubPos.y, 14);
}
function applyBackend(host, status) {
  const sc = scene[host];
  const previous = sc.backend;
  sc.backend = String(status || "UNKNOWN").toUpperCase();
  if (previous !== "UNKNOWN" && sc.backend !== "UNKNOWN") {
    if (previous.startsWith("UP") && !sc.backend.startsWith("UP")) lbFlash(host, true);
    else if (!previous.startsWith("UP") && sc.backend.startsWith("UP")) lbFlash(host, false);
  }
  if (incidentActive(host)) return;
  const isolated = sc.backend.startsWith("MAINT");
  if (isolated && !sc.sealed) { sc.sealed = true; sc.shutTarget = 1; sc.cutTarget = 1; }
  else if (!isolated && sc.sealed && sc.backend.startsWith("UP")) { sc.sealed = false; sc.shutTarget = 0; sc.cutTarget = 0; }
}
function repairProgress(sc) {
  if (sc.vis !== "REPAIRING") return null;
  if (sc.delayMs <= 0) return { pct: null, label: "memperbaiki…" };
  const elapsed = !sc.stageTs.REPAIRING ? sim.t - sc.repairStart : Date.now() - sc.stageTs.REPAIRING;
  const pct = clamp(elapsed / sc.delayMs, 0, 1), remain = Math.max(0, Math.ceil((sc.delayMs - elapsed) / 1000));
  const mm = String(Math.floor(remain / 60)).padStart(2, "0"), ss = String(remain % 60).padStart(2, "0");
  return { pct, label: `${Math.round(pct * 100)}% · sisa ${mm}:${ss}` };
}

/* ───────────────────────── event ingestion + demos ───────────────────────── */
function ingestLive(event) {
  if (!event || event.id == null || patrol.seen.has(event.id)) return;
  patrol.seen.add(event.id);
  const host = event.host_id;
  if (!hosts.includes(host) || Date.now() - Date.parse(event.ts || 0) > 25000) return;
  const sev = safeSeverity(event.severity);
  if (event.actor === "police") {
    if (sev === "safe") { scanFlash.set(fkey(host, event.path), sim.t); return; }
    if (incidentActive(host)) return;
    const action = event.type === "alert" && event.action === "read" ? "plant" : event.action;
    spawnThief(host, "fim", event, action, { lurk: Boolean(patrol.analysis.auto_repair_enabled), tag: "INTRUDER" });
    return;
  }
  if (incidentActive(host)) return;
  spawnThief(host, event.actor, event, event.status === "blocked" ? "denied" : event.action);
}
function makeDemoEvent(actor, host, action, severity, path, offset) {
  return {
    id: `demo-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
    ts: new Date(Date.now() + offset).toISOString(),
    type: severity === "safe" ? "access" : "alert", actor, action, host_id: host, path, severity,
    hash_old: severity === "compromised" ? "a".repeat(64) : null,
    hash_new: severity === "compromised" ? "b".repeat(64) : null,
    status: action === "denied" ? "blocked" : "demo", source: "demo",
  };
}
function addDemoPair() {
  const pick = (host) => { const fs = filesOf(host); return fs.length ? fs[Math.floor(Math.random() * fs.length)].path : "index.txt"; };
  const cycle = patrol.demoCycle++;
  const actions = [["read", "modify"], ["download", "read"], ["denied", "delete"], ["read", "download"]][cycle % 4];
  const list = [];
  if (!incidentActive("server-a")) list.push(makeDemoEvent("198.51.100.23", "server-a", actions[0], "suspicious", pick("server-a"), 0));
  if (!incidentActive("server-b")) list.push(makeDemoEvent("203.0.113.42", "server-b", actions[1], actions[1] === "denied" ? "suspicious" : "compromised", pick("server-b"), 1));
  patrol.demoEvents.unshift(...list);
  patrol.demoEvents = patrol.demoEvents.slice(0, 30);
  list.forEach(ingestLive);
  refreshPatrol();
}
/* SERANG: minta collector mengubah kunci demo di server target. Agent mendeteksinya,
 * lalu playbook sungguhan mengeluarkan server dari HAProxy, memulihkan file, dan memasukkannya lagi. */
const ATTACK_ERRORS = {
  lab_drain_mode_disabled: "Mode lab belum aktif",
  attack_in_progress: "Serangan sedang berjalan",
  target_not_up: "Server sedang tidak UP",
  survivor_not_healthy: "Server lain tidak sehat",
  attack_simulation_disabled: "Simulasi nonaktif di server",
  key_not_pristine: "Kunci belum pulih",
};
function attackNotice(text) {
  const node = $("#attack-status");
  node.textContent = text;
  window.clearTimeout(attackNotice.timer);
  if (text) attackNotice.timer = window.setTimeout(() => { node.textContent = ""; }, 7000);
}
async function launchAttack(host) {
  const sc = scene[host];
  if (!sc || sc.attackPending || incidentActive(host) || sc.queue.length) return;
  sc.attackPending = true;
  updateAttackButton();
  attackNotice("");
  try {
    const response = await fetch(`/v1/lab/attack/${host}`, { method: "POST" });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(ATTACK_ERRORS[body.error] || body.error || `HTTP ${response.status}`);
    patrol.fastUntil = Date.now() + 60000;
    pollDashboard();
    window.setTimeout(() => { sc.attackPending = false; updateAttackButton(); }, 25000);
  } catch (error) {
    sc.attackPending = false;
    attackNotice(error.message);
    updateAttackButton();
  }
}

/* ───────────────────────── drawing helpers ───────────────────────── */
let view = { scale: 1, ox: 0, oy: 0, dpr: 1 };
const OUT = "#18222b", SKIN = "#e8c7a1";
const COLORS = {
  police: { shirt: "#2f5575", pants: "#1d3248", hat: "#1f3a56", accent: "#e0b84a", shoe: "#10202d" },
  thief: { shirt: "#25252d", stripe: "#f1f1f1", pants: "#34343f", hat: "#16161b", accent: "#c9ccd3", shoe: "#16161b" },
  guard: { shirt: "#365067", vest: "#f08b25", pants: "#3d434d", hat: "#f3c437", accent: "#f4f4f0", shoe: "#1c2128" },
};
function rrect(g, x, y, w, h, r) {
  const rad = Math.min(r, w / 2, h / 2);
  g.beginPath(); g.moveTo(x + rad, y);
  g.arcTo(x + w, y, x + w, y + h, rad); g.arcTo(x + w, y + h, x, y + h, rad);
  g.arcTo(x, y + h, x, y, rad); g.arcTo(x, y, x + w, y, rad); g.closePath();
}
function pill(g, x, y, w, h, fill, stroke) {
  rrect(g, x, y, w, h, 4); g.fillStyle = fill; g.fill();
  if (stroke) { g.strokeStyle = stroke; g.lineWidth = 1.5; g.stroke(); }
}
function hazard(g, x, y, w, h, alpha) {
  g.save(); g.globalAlpha = alpha; g.beginPath(); g.rect(x, y, w, h); g.clip();
  g.fillStyle = "#f2c230"; g.fillRect(x, y, w, h);
  g.fillStyle = "#1c2128";
  for (let sx = x - h; sx < x + w; sx += 16) {
    g.beginPath(); g.moveTo(sx, y + h); g.lineTo(sx + 8, y + h); g.lineTo(sx + 8 + h, y); g.lineTo(sx + h, y); g.closePath(); g.fill();
  }
  g.restore();
}
function mulberry(seed) {
  let a = seed;
  return () => { a |= 0; a = (a + 0x6d2b79f5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}
const alarmOn = (host) => scene[host].alarmStage || Boolean(recentAlertFile(host)) || thiefList().some((t) => t.host === host && t.inside && !t.leaving && !t.ko && !scene[host].vis);

/* ── static background (cached) ── */
const bg = { canvas: document.createElement("canvas"), key: "" };
function paintStatic(g) {
  const H = worldHeight(), rnd = mulberry(11);
  g.fillStyle = "#8fab8b"; g.fillRect(-200, -200, WORLD_W + 400, H + 400);
  for (let i = 0; i < 520; i++) { g.fillStyle = rnd() < 0.5 ? "#86a383" : "#9ab596"; g.fillRect(Math.round(rnd() * WORLD_W), Math.round(rnd() * H), 3, 2); }
  g.fillStyle = "#a9b3a8"; g.fillRect(0, 0, WORLD_W, 62);
  g.fillStyle = "#9aa699"; for (let x = 0; x < WORLD_W; x += 30) g.fillRect(x, 0, 1, 62);
  g.fillStyle = "#b8bbaf"; g.fillRect(0, H - 112, WORLD_W, 112 - 26);
  g.fillStyle = "#5f6b69"; g.fillRect(0, H - 62, WORLD_W, 36);
  g.fillStyle = "#4b5755"; g.fillRect(0, H - 62, WORLD_W, 2); g.fillRect(0, H - 28, WORLD_W, 2);
  g.fillStyle = "#d8cf8a"; for (let x = 6; x < WORLD_W; x += 46) g.fillRect(x, H - 45, 26, 2);
  g.font = "bold 10px ui-monospace, Menlo, monospace"; g.fillStyle = "#e8e3c4";
  g.fillText("<< INTERNET", 10, H - 50); g.textAlign = "right"; g.fillText("INTERNET >>", WORLD_W - 10, H - 50); g.textAlign = "left";
  for (const host of hosts) {
    const R = roomRect(host), D = doorOf(host), P = postOf(host);
    g.fillStyle = "#a6aa9d"; g.fillRect(D.x - 36, D.y, 72, H - 62 - D.y);
    g.fillStyle = "#8f948a"; g.fillRect(D.x - 36, D.y, 2, H - 62 - D.y); g.fillRect(D.x + 34, D.y, 2, H - 62 - D.y);
    g.fillStyle = "rgba(0,0,0,.18)"; g.fillRect(R.x + 6, R.y + 6, R.w, R.h);
    g.fillStyle = "#d9caa4"; g.fillRect(R.x, R.y, R.w, R.h);
    for (let y = R.y + 8; y < R.y + R.h - 8; y += 27) for (let x = R.x + 8; x < R.x + R.w - 8; x += 27) {
      g.fillStyle = ((x + y) / 27) % 2 ? "#ddcea8" : "#e7d9b6"; g.fillRect(x, y, 25, 25);
    }
    g.fillStyle = "#2b3f4c";
    g.fillRect(R.x, R.y, R.w, 8); g.fillRect(R.x, R.y, 8, R.h); g.fillRect(R.x + R.w - 8, R.y, 8, R.h);
    g.fillRect(R.x, R.y + R.h - 8, R.w / 2 - 34, 8); g.fillRect(D.x + 34, R.y + R.h - 8, R.w / 2 - 34, 8);
    g.fillStyle = "#4a6677"; g.fillRect(R.x + 8, R.y + 8, R.w - 16, 2); g.fillRect(R.x + 8, R.y + 8, 2, R.h - 16); g.fillRect(R.x + R.w - 10, R.y + 8, 2, R.h - 16);
    g.fillStyle = "#223845"; g.fillRect(R.x + 8, R.y + 10, R.w - 16, 32);
    g.fillStyle = "#f6f0df"; g.font = "bold 13px ui-monospace, Menlo, monospace"; g.fillText(`${HOST_LABEL[host].toUpperCase()} · /data`, R.x + 20, R.y + 31);
    g.fillStyle = "#9a9d92"; g.fillRect(D.x - 34, D.y - 8, 68, 8);
    g.fillStyle = "#d9caa4"; g.fillRect(D.x - 32, D.y - 7, 64, 6);
    g.fillStyle = "#c8c2ad"; g.fillRect(D.x - 32, D.y - 1, 64, 1);
    // guard booth
    g.fillStyle = "rgba(0,0,0,.2)"; g.fillRect(P.x - 62, P.y - 22, 44, 34);
    g.fillStyle = "#d8d2c0"; g.fillRect(P.x - 64, P.y - 26, 42, 32);
    g.fillStyle = "#7fb7d6"; g.fillRect(P.x - 58, P.y - 16, 14, 11); g.fillRect(P.x - 40, P.y - 16, 14, 11);
    g.fillStyle = "#b8503f"; g.fillRect(P.x - 68, P.y - 34, 50, 10);
    g.fillStyle = "#8c3a2e"; g.fillRect(P.x - 68, P.y - 26, 50, 2);
    g.fillStyle = "#f6f0df"; g.font = "bold 7px ui-monospace, monospace"; g.fillText("POS SATPAM", P.x - 65, P.y - 27);
    // bushes
    for (const [bx, by] of [[R.x - 10, R.y + R.h + 4], [R.x + R.w + 10, R.y + R.h + 4], [D.x - 52, D.y + 6], [D.x + 52, D.y + 6]]) {
      g.fillStyle = "#4f7c58"; g.beginPath(); g.arc(bx, by, 9, 0, 6.283); g.fill();
      g.fillStyle = "#639a6c"; g.beginPath(); g.arc(bx - 2, by - 2, 5, 0, 6.283); g.fill();
    }
  }
}
function ensureBackground(rectW, rectH) {
  const key = `${canvas.width}x${canvas.height}:${worldHeight()}`;
  if (bg.key === key) return;
  bg.key = key; bg.canvas.width = canvas.width; bg.canvas.height = canvas.height;
  const g = bg.canvas.getContext("2d");
  g.imageSmoothingEnabled = false;
  g.setTransform(view.dpr * view.scale, 0, 0, view.dpr * view.scale, view.dpr * view.ox, view.dpr * view.oy);
  paintStatic(g);
}

/* ── network cables + load balancer hub ── */
function cableAt(host, s) {
  const D = doorOf(host), R = roomRect(host), startX = hubPos.x + (host === "server-a" ? -52 : 52);
  const l1 = Math.abs(D.x - startX), l2 = R.y - 30;
  if (s <= l1) return { x: startX + Math.sign(D.x - startX) * s, y: 30 };
  return { x: D.x, y: 30 + Math.min(l2, s - l1), tail: true };
}
function drawNetwork() {
  const t = sim.t, g = ctx;
  const lbDown = hosts.some((host) => lbStatus(host)[0] !== "UP");
  const blink = lbDown && Math.floor(t / 260) % 2;
  pill(g, hubPos.x - 52, hubPos.y - 17, 104, 34, "#223845", blink ? "#ff6b5c" : "#10202b");
  g.fillStyle = "#f6f0df"; g.font = "bold 9px ui-monospace, Menlo, monospace"; g.textAlign = "center"; g.fillText("HAPROXY LB", hubPos.x, hubPos.y - 4);
  for (const host of hosts) {
    const [text, color] = lbStatus(host), side = host === "server-a" ? -1 : 1;
    g.fillStyle = color; g.fillText(`${host.at(-1).toUpperCase()} ${text}`, hubPos.x + side * 25, hubPos.y + 10);
  }
  g.textAlign = "left";
  for (const host of hosts) {
    const sc = scene[host], D = doorOf(host), R = roomRect(host), side = host === "server-a" ? -1 : 1;
    const startX = hubPos.x + side * 52, gap = sc.cut * 18, cutY = 46;
    const upperEnd = cutY - gap / 2, lowerStart = cutY + gap / 2;
    const line = (x1, y1, x2, y2, core) => {
      g.lineCap = "butt"; g.strokeStyle = "#16242d"; g.lineWidth = 7; g.beginPath(); g.moveTo(x1, y1); g.lineTo(x2, y2); g.stroke();
      g.strokeStyle = core; g.lineWidth = 3.4; g.stroke();
    };
    const live = sc.cut > 0.5 ? "#6a7478" : "#6ee3b0";
    line(startX, 30, D.x, 30, live);
    line(D.x, 30, D.x, upperEnd, live);
    line(D.x, lowerStart, D.x, R.y, sc.cut > 0.5 ? "#6a7478" : "#6ee3b0");
    for (const [py, dir] of [[upperEnd, 1], [lowerStart, -1]]) {
      if (sc.cut < 0.05) break;
      g.fillStyle = "#d4d9dc"; g.fillRect(D.x - 5, py - (dir > 0 ? 0 : 0) - (dir > 0 ? 6 : 0), 10, 6);
      g.fillStyle = "#6a7478"; g.fillRect(D.x - 3, py - (dir > 0 ? 8 : -6), 6, 2);
    }
    if (sc.cut > 0.9 && Math.sin(t / 90 + (host === "server-a" ? 0 : 2)) > 0.4) {
      g.fillStyle = "#ffe27a"; g.fillRect(D.x - 2 + Math.sin(t / 37) * 6, cutY - 2 + Math.cos(t / 51) * 5, 3, 3);
    }
    if (sc.cut > 0.5) {
      g.font = "bold 8px ui-monospace, Menlo, monospace"; g.fillStyle = "#b8352a"; g.fillText("PUTUS", D.x + 10, cutY + 3);
    }
    const l1 = Math.abs(D.x - startX), total = l1 + (R.y - 30);
    const partnerCut = scene[host === "server-a" ? "server-b" : "server-a"].cut > 0.5;
    const packets = sc.cut > 0.5 ? 0 : partnerCut ? 13 : 7;
    for (let k = 0; k < packets; k++) {
      const s = ((t * (partnerCut ? 0.12 : 0.075) + k * total / packets) % total);
      const p = cableAt(host, s);
      if (sc.cut > 0.2 && p.tail && p.y > upperEnd) continue;
      g.fillStyle = "#e9fff4"; g.fillRect(p.x - 2, p.y - 2, 4, 4);
    }
  }
}

/* ── room dynamics ── */
const STATUS = {
  DETECTED: ["ALERT", "#e0584a"], ISOLATING: ["ISOLASI", "#e68a2e"], ISOLATED: ["TERISOLASI", "#e0584a"], REPAIRING: ["MAINTENANCE", "#d9a42b"],
  VERIFYING: ["VERIFIKASI", "#4f9fdc"], REJOINING: ["REJOIN", "#2fa593"], REPAIRED: ["ONLINE ✓", "#2f9f6d"], FAILED: ["GAGAL", "#e0584a"],
};
function hostStatus(host) {
  const sc = scene[host];
  if (sc.vis && STATUS[sc.vis]) return STATUS[sc.vis];
  if (sc.sealed) return ["TERISOLASI · MAINT", "#e0584a"];
  if (alarmOn(host)) return ["ALERT", "#e68a2e"];
  return ["ONLINE", "#2f9f6d"];
}
function drawRoomDynamic(host) {
  const g = ctx, R = roomRect(host), D = doorOf(host), sc = scene[host], t = sim.t;
  const [label, color] = hostStatus(host);
  g.font = "bold 10px ui-monospace, Menlo, monospace";
  const w = g.measureText(label).width + 22;
  pill(g, R.x + R.w - 20 - w, R.y + 17, w, 18, color);
  g.fillStyle = "#fff"; g.beginPath(); g.arc(R.x + R.w - 20 - w + 9, R.y + 26, 3, 0, 6.283); g.fill();
  g.fillText(label, R.x + R.w - 20 - w + 16, R.y + 30);
  // racks
  for (let i = 0; i < 5; i++) {
    const rx = R.x + 26 + i * 72, ry = R.y + 52;
    g.fillStyle = OUT; g.fillRect(rx - 1, ry - 1, 56, 52); g.fillStyle = "#33444f"; g.fillRect(rx, ry, 54, 50);
    for (let s = 0; s < 4; s++) {
      g.fillStyle = "#1f2c35"; g.fillRect(rx + 4, ry + 4 + s * 11, 46, 8);
      const blink = Math.sin(t / (300 + i * 40 + s * 70) + i * 2 + s) > 0.1;
      const c = sc.alarmStage ? (Math.floor(t / 220 + s) % 2 ? "#ff5d4d" : "#5a1f1b") : sc.cut > 0.5 ? (blink ? "#ff8a3d" : "#4a2a1c") : (blink ? "#59e0a3" : "#1e5c44");
      g.fillStyle = c; g.fillRect(rx + 8, ry + 6 + s * 11, 4, 4);
      g.fillStyle = "#4b5d69"; g.fillRect(rx + 20, ry + 7 + s * 11, 24, 2);
    }
  }
  // door leaves + shutter
  const open = sc.door, x0 = D.x - 32, lw = 32 * (1 - open * 0.88);
  g.fillStyle = OUT; g.fillRect(x0 - 1, D.y - 11, 66, 14);
  g.fillStyle = "#58707f"; g.fillRect(x0, D.y - 10, lw, 12); g.fillRect(D.x + 32 - lw, D.y - 10, lw, 12);
  g.fillStyle = "#9ed3e8"; if (lw > 12) { g.fillRect(x0 + 4, D.y - 7, lw - 8, 4); g.fillRect(D.x + 36 - lw, D.y - 7, lw - 8, 4); }
  const sh = sc.shutter;
  if (sh > 0.01) {
    const hgt = 20 * sh, sy = D.y - 12;
    g.fillStyle = "rgba(20,20,20,.28)"; g.fillRect(x0 - 3, sy + hgt, 70, 8 * sh);
    g.fillStyle = OUT; g.fillRect(x0 - 5, sy - 1, 74, hgt + 2);
    g.fillStyle = "#8b949a"; g.fillRect(x0 - 4, sy, 72, hgt);
    g.fillStyle = "#6b757b"; for (let yy = sy + 3; yy < sy + hgt; yy += 4) g.fillRect(x0 - 4, yy, 72, 1);
    if (hgt > 6) hazard(g, x0 - 4, sy + hgt - 5, 72, 5, 1);
    if (sh > 0.9) { g.fillStyle = Math.floor(t / 300) % 2 ? "#ff4d3d" : "#7a2a24"; g.fillRect(x0 - 2, sy + 2, 4, 4); g.fillRect(x0 + 62, sy + 2, 4, 4); }
  }
}
function drawLockdown(host) {
  const g = ctx, R = roomRect(host), D = doorOf(host), sc = scene[host], lock = clamp(Math.max(sc.shutter, sc.cut * 0.8), 0, 1), t = sim.t;
  if (lock > 0.02) {
    g.fillStyle = `rgba(150,30,28,${(0.1 + (sc.alarmStage ? 0.05 * (1 + Math.sin(t / 180)) : 0)) * lock})`;
    g.fillRect(R.x + 8, R.y + 42, R.w - 16, R.h - 50);
    hazard(g, R.x + 8, R.y + 44, R.w - 16, 7, lock * 0.95);
    hazard(g, R.x + 8, R.y + R.h - 22, R.w - 16, 7, lock * 0.95);
    if (sc.shutter > 0.6) {
      pill(g, D.x - 62, D.y - 56, 124, 22, "#2a1614", "#e0584a");
      g.fillStyle = "#ff8a7a"; g.font = "bold 10px ui-monospace, Menlo, monospace"; g.textAlign = "center";
      g.fillText("AKSES DIKUNCI", D.x + 6, D.y - 41);
      g.fillStyle = "#ff8a7a"; g.fillRect(D.x - 50, D.y - 49, 8, 6); g.strokeStyle = "#ff8a7a"; g.lineWidth = 1.6; g.beginPath(); g.arc(D.x - 46, D.y - 50, 3, Math.PI, 0); g.stroke();
      g.textAlign = "left";
    }
  }
  // roof beacons
  const alarm = alarmOn(host);
  for (const bx of [R.x + 14, R.x + R.w - 14]) {
    const by = R.y - 8;
    g.fillStyle = "#2b3f4c"; g.fillRect(bx - 6, by, 12, 6);
    g.fillStyle = alarm ? (Math.floor(t / 180 + bx) % 2 ? "#ff5d4d" : "#4aa3ff") : "#5b6b73"; g.beginPath(); g.arc(bx, by - 1, 5, Math.PI, 0); g.fill();
    if (alarm && !reduceMotion.matches) {
      g.save(); g.globalAlpha = 0.16; g.fillStyle = Math.floor(t / 180 + bx) % 2 ? "#ff5d4d" : "#4aa3ff";
      g.beginPath(); g.moveTo(bx, by - 1); g.arc(bx, by - 1, 46, t / 260 % 6.283, t / 260 % 6.283 + 0.9); g.closePath(); g.fill(); g.restore();
    }
  }
}
function drawBanner(host) {
  const sc = scene[host], b = sc.banner;
  if (!b || sim.t > b.until) return;
  const R = roomRect(host), g = ctx, age = sim.t - b.at, left = b.until - sim.t;
  const k = clamp(age / 240, 0, 1), alpha = clamp(left / 450, 0, 1);
  g.save(); g.globalAlpha = alpha;
  g.font = "bold 15px ui-monospace, Menlo, monospace";
  const w = g.measureText(b.text).width + 40, h = 34, cx = R.x + R.w / 2, cy = R.y + 78 + (1 - k) * -14;
  g.translate(cx, cy); g.scale(0.7 + 0.3 * k, 0.7 + 0.3 * k);
  pill(g, -w / 2, -h / 2, w, h, "rgba(18,28,36,.93)", b.color);
  g.fillStyle = b.color; g.fillRect(-w / 2 + 8, -4, 8, 8);
  g.fillStyle = "#fff"; g.textAlign = "center"; g.fillText(b.text, 6, 5); g.textAlign = "left";
  g.restore();
}

/* ── files (loot) ── */
function box(g, x, y, w, h, c) { g.fillStyle = OUT; g.fillRect(x - 1, y - 1, w + 2, h + 2); g.fillStyle = c; g.fillRect(x, y, w, h); }
function drawFile(f) {
  const g = ctx, t = sim.t, st = fileState(f);
  if (st === "pending") return;
  const sev = safeSeverity(severityForFile(f)), cat = fileCategory(f.path), x = f.x, y = f.y;
  const key = fkey(f.host_id, f.path), flashAt = scanFlash.get(key);
  if (flashAt !== undefined && t - flashAt < 1100) {
    const k = (t - flashAt) / 1100;
    g.strokeStyle = `rgba(90,170,230,${1 - k})`; g.lineWidth = 2; g.beginPath(); g.arc(x, y, 18 + k * 16, 0, 6.283); g.stroke();
  }
  const label = baseName(f.path).slice(0, 13);
  g.textAlign = "center"; g.font = "9px ui-monospace, Menlo, monospace";
  if (st === "stolen" || st === "deleted") {
    const c = st === "stolen" ? "#d98324" : "#c7483b";
    g.setLineDash([4, 3]); g.strokeStyle = c; g.lineWidth = 2; g.strokeRect(x - 17, y - 16, 34, 31); g.setLineDash([]);
    g.fillStyle = c; g.font = "bold 8px ui-monospace, Menlo, monospace"; g.fillText(st === "stolen" ? "STOLEN" : "REMOVED", x, y + 3);
    g.fillStyle = "#283f4b"; g.font = "9px ui-monospace, Menlo, monospace"; g.fillText(label, x, y + 25);
    g.textAlign = "left"; return;
  }
  const bob = st === "ok" ? Math.sin(t / 650 + x) * 0.8 : 0;
  const yy = y + bob;
  if (["safe", "key", "gold", "document"].includes(cat)) {
    g.save(); g.shadowColor = sev === "safe" ? "#dfb84d" : "#f5c34d"; g.shadowBlur = 12;
    pill(g, x - 17, yy - 16, 34, 31, cat === "safe" ? "#788597" : "#936a28", "#493b2b"); g.restore();
  }
  if (cat === "safe") {
    box(g, x - 11, yy - 10, 22, 19, "#b7c0c6"); g.fillStyle = "#263d4b"; g.fillRect(x - 5, yy - 4, 10, 7); g.fillStyle = "#f2cb56"; g.fillRect(x + 2, yy - 2, 3, 3);
  } else if (cat === "key") {
    box(g, x - 4, yy - 11, 8, 20, "#efc34e"); box(g, x - 10, yy - 12, 20, 5, "#efc34e"); box(g, x + 3, yy + 1, 9, 4, "#efc34e");
  } else if (cat === "gold") {
    box(g, x - 13, yy + 3, 26, 8, "#e9b93e"); box(g, x - 9, yy - 4, 21, 8, "#f0c74d"); box(g, x - 5, yy - 10, 14, 7, "#f7d96b");
  } else if (cat === "document") {
    box(g, x - 11, yy - 13, 22, 27, "#f7f2df"); g.fillStyle = "#60756e"; g.fillRect(x - 7, yy - 7, 14, 2); g.fillRect(x - 7, yy - 1, 12, 2); g.fillRect(x - 7, yy + 5, 9, 2);
  } else {
    box(g, x - 12, yy - 11, 24, 21, "#a87442"); g.fillStyle = "#d7ac6a"; g.fillRect(x - 8, yy - 7, 16, 13); g.fillStyle = "#855a35"; g.fillRect(x - 3, yy - 3, 6, 6);
  }
  if (st === "tampered") {
    g.fillStyle = "rgba(200,60,48,.5)"; g.fillRect(x - 13, yy - 14, 26, 28);
    g.strokeStyle = "#7d1f19"; g.lineWidth = 1.6; g.beginPath(); g.moveTo(x - 6, yy - 13); g.lineTo(x - 1, yy - 4); g.lineTo(x - 7, yy + 2); g.lineTo(x + 2, yy + 13); g.stroke();
    if (Math.floor(t / 140) % 3 === 0) { g.fillStyle = "rgba(255,255,255,.55)"; g.fillRect(x - 13, yy - 5 + Math.floor(Math.sin(t / 50) * 4), 26, 2); }
  }
  if (st === "infected") {
    g.save(); g.globalAlpha = 0.35 + 0.25 * Math.sin(t / 160); g.fillStyle = "#e0584a"; g.beginPath(); g.arc(x, yy, 22, 0, 6.283); g.fill(); g.restore();
    box(g, x + 6, yy - 20, 12, 12, "#2a1614"); g.fillStyle = "#f4efe6"; g.fillRect(x + 8, yy - 18, 8, 6); g.fillRect(x + 9, yy - 13, 6, 3);
    g.fillStyle = "#2a1614"; g.fillRect(x + 9, yy - 17, 2, 2); g.fillRect(x + 13, yy - 17, 2, 2);
  }
  if (st === "ok" && sev !== "safe" && (sev === "compromised" || Math.floor(t / 500) % 2 === 0)) {
    g.fillStyle = sev === "compromised" ? "#b34236" : "#cb7a23"; g.font = "bold 17px ui-monospace, Menlo, monospace"; g.fillText("!", x + 16, yy - 10);
  }
  g.fillStyle = "#283f4b"; g.font = "9px ui-monospace, Menlo, monospace"; g.fillText(label, x, y + 25); g.textAlign = "left";
}

/* ── characters ── */
function drawPerson(a) {
  const g = ctx, U = 2.6, t = sim.t, pose = a.pose, C = COLORS[a.role];
  const flash = a.hit > 0 && Math.floor(a.hit / 70) % 2 === 0;
  g.save();
  g.translate(Math.round(a.x), Math.round(a.y));
  g.globalAlpha = a.alpha;
  g.fillStyle = "rgba(14,24,18,.30)"; g.beginPath(); g.ellipse(0, 1, pose === "ko" ? 19 : 10.5, pose === "ko" ? 5 : 3.8, 0, 0, 6.283); g.fill();
  g.scale(a.dir, 1);
  const P = (x, y, w, h, c) => { g.fillStyle = OUT; g.fillRect(x * U - 1, y * U - 1, w * U + 2, h * U + 2); g.fillStyle = flash ? "#ffffff" : c; g.fillRect(x * U, y * U, w * U, h * U); };
  const F = (x, y, w, h, c) => { g.fillStyle = c; g.fillRect(x * U, y * U, w * U, h * U); };
  const run = pose === "run" || pose === "carry", moving = a.moving;
  const sw = moving ? Math.sin(a.phase) * (run ? 1.35 : 1) : 0;
  const crouch = pose === "sneak" ? 1.7 : 0;
  const bob = moving ? Math.abs(Math.sin(a.phase)) * (run ? 1.5 : 0.9) : Math.sin(t / 430 + a.x * 0.1) * 0.35;
  if (pose === "ko") { g.translate(14, -3); g.rotate(-Math.PI / 2); } else if (run) g.rotate(0.08);
  // legs
  const legH = 5 - crouch;
  for (const side of [-1, 1]) {
    const s = pose === "ko" ? side * 0.4 : side * sw, lift = Math.max(0, s) * 1.1;
    P((side < 0 ? -2.4 : 0.4) + s * 0.6, -legH - lift, 2, legH, C.pants);
    F((side < 0 ? -2.6 : 0.2) + s * 0.6, -lift - 1, 2.6, 1, C.shoe);
  }
  g.translate(0, (crouch - bob) * U);
  const arm = (sx, ang, len, col, item) => {
    g.save(); g.translate(sx * U, -10.6 * U); g.rotate(ang); P(-1, 0, 2, len, col); F(-0.9, len - 0.8, 1.8, 1.3, SKIN);
    if (item) item(len);
    g.restore();
  };
  let fa = sw * 0.7, ba = -sw * 0.7, frontItem = null;
  const L = 4.8;
  switch (pose) {
    case "aim":
      fa = -Math.PI / 2; ba = -Math.PI / 2 + 0.28;
      frontItem = (len) => {
        P(-0.8, len - 0.6, 1.6, 3.6, "#262b33");
        if (t < a.flashUntil) { F(-2.2, len + 3.2, 4.4, 3.4, "#fff3a8"); F(-1, len + 2.6, 2, 5, "#ffd24a"); }
      };
      break;
    case "repair": fa = -1.7 + Math.sin(t / 90) * 0.85; ba = 0.25; frontItem = (len) => { P(-0.5, len - 0.5, 1.1, 4.2, "#9aa4ad"); P(-1.3, len + 3.4, 2.7, 1.5, "#b7c0c8"); }; break;
    case "hammer": fa = -1.7 + Math.sin(t / 90) * 0.85; ba = 0.25; frontItem = (len) => { P(-0.5, len - 0.5, 1.1, 4, "#7a5a34"); P(-1.6, len + 3.2, 3.2, 1.8, "#6d7782"); }; break;
    case "panic": fa = -2.7 + Math.sin(t / 55) * 0.3; ba = 2.7 - Math.sin(t / 55 + 1) * 0.3; break;
    case "peek": fa = -1.35; ba = 0.15; frontItem = (len) => { P(-0.8, len - 0.5, 1.6, 3, "#3a4350"); F(-0.7, len + 2.4, 1.4, 0.8, "#fff1a6"); }; break;
    case "scan": fa = -1.25; ba = 0.1; frontItem = (len) => { P(-1, len - 0.5, 2, 3.2, "#1f2a33"); F(-0.6, len + 2, 1.2, 0.9, "#6fd3ff"); }; break;
    case "grab": fa = -0.95 - Math.sin(t / 160) * 0.15; ba = 0.2; break;
    case "plant": fa = -0.6 + Math.sin(t / 140) * 0.3; ba = 0.2; frontItem = (len) => { P(-1.5, len - 0.3, 3, 2.6, "#3a2f2a"); F(-0.5, len + 0.4, 1, 1, "#fff"); }; break;
    case "badge": fa = -1.5; ba = 0.1; frontItem = (len) => { P(-1.2, len - 0.2, 2.4, 1.8, "#f4f4f0"); F(-0.6, len + 0.3, 1.2, 0.5, "#3fbf86"); }; break;
    case "clip": fa = -1.0; ba = -0.9 + Math.sin(t / 130) * 0.3; frontItem = (len) => { P(-1.8, len - 1.2, 3.6, 4.8, "#c9a36a"); F(-1.3, len - 0.6, 2.6, 3.6, "#fafaf5"); F(-1, len + 0.2, 2, 0.4, "#6a7a82"); F(-1, len + 1.2, 2, 0.4, "#6a7a82"); }; break;
    case "ko": fa = 0.5; ba = -0.4; break;
    default: break;
  }
  if (t < a.aimUntil && pose !== "ko") {
    fa = -Math.PI / 2; ba = -Math.PI / 2 + 0.28;
    frontItem = (len) => { P(-0.8, len - 0.6, 1.6, 3.6, "#262b33"); if (t < a.flashUntil) { F(-2.2, len + 3.2, 4.4, 3.4, "#fff3a8"); F(-1, len + 2.6, 2, 5, "#ffd24a"); } };
  }
  if (a.carry) { P(-6.6, -11.4, 4.6, 5.4, "#7a5a34"); P(-5.4, -12.7, 1.8, 1.4, "#5a4026"); F(-4.8, -9.8, 1, 2.6, "#f1e0a0"); }
  arm(-2.4, ba, L, C.shirt, null);
  // torso
  P(-3, -11, 6, 6, C.shirt);
  if (a.role === "police") { F(-1, -11, 2, 1, "#cfe3f2"); F(1, -9.6, 1.2, 1.2, C.accent); F(-3, -6.1, 6, 1, "#101820"); F(-0.5, -6.1, 1, 1, C.accent); }
  if (a.role === "thief") for (let k = 0; k < 3; k++) F(-3, -10.4 + k * 1.9, 6, 0.8, C.stripe);
  if (a.role === "guard") { F(-3, -11, 2, 6, C.vest); F(1, -11, 2, 6, C.vest); F(-3, -8.2, 6, 0.8, C.accent); }
  // head
  P(-2.5, -16, 5, 5, SKIN);
  if (pose === "ko") { g.strokeStyle = "#18222b"; g.lineWidth = 1.2; for (const ex of [0.4, 1.7]) { g.beginPath(); g.moveTo(ex * U, -14.8 * U); g.lineTo((ex + 0.9) * U, -13.9 * U); g.moveTo((ex + 0.9) * U, -14.8 * U); g.lineTo(ex * U, -13.9 * U); g.stroke(); } }
  else { F(0.5, -14.4, 0.9, 1, "#18222b"); F(1.8, -14.4, 0.9, 1, "#18222b"); }
  if (a.role === "thief") {
    F(-2.5, -14.9, 5, 1.8, "#0f0f14"); if (pose !== "ko") { F(0.4, -14.5, 1.1, 1, "#ffffff"); F(1.8, -14.5, 1.1, 1, "#ffffff"); }
    P(-2.8, -18.2, 5.6, 2.5, C.hat); F(-2.8, -17.3, 5.6, 0.7, "#d9d9df");
  } else if (a.role === "police") {
    P(-3, -18.2, 6, 2.4, C.hat); F(-3, -16.6, 6, 0.6, C.accent); P(2.4, -16.8, 2.8, 0.9, "#101820"); F(-0.4, -17.8, 1.4, 1, C.accent);
  } else {
    P(-3, -18.8, 6, 2.9, C.hat); P(-3.7, -16.4, 7.4, 0.9, C.hat); F(-0.6, -18.4, 1.2, 1.2, "#fff3b0");
  }
  arm(2.4, fa, L, C.shirt, frontItem);
  g.restore();
  if (pose === "ko") {
    for (let i = 0; i < 3; i++) {
      const ang = t / 260 + i * 2.1, sx = a.x - a.dir * 27 + Math.cos(ang) * 11, sy = a.y - 22 + Math.sin(ang) * 4;
      g.fillStyle = "#ffd24a"; g.fillRect(Math.round(sx) - 2, Math.round(sy) - 2, 4, 4);
    }
  }
}
function drawBubble(x, y, text, tone) {
  const g = ctx;
  g.font = "bold 10px ui-monospace, Menlo, monospace";
  const w = g.measureText(text).width + 14, h = 18, bx = clamp(x - w / 2, 4, WORLD_W - w - 4), by = y - h;
  const [bgc, border, ink] = tone === "bad" ? ["#ffe3de", "#b34236", "#5e1710"] : tone === "good" ? ["#e3f8ec", "#2f8f66", "#12452f"] : ["#fffdf5", "#3c514f", "#253d4a"];
  pill(g, bx, by, w, h, bgc, border);
  g.fillStyle = bgc; g.beginPath(); g.moveTo(clamp(x, bx + 6, bx + w - 6) - 4, by + h - 0.5); g.lineTo(clamp(x, bx + 6, bx + w - 6) + 4, by + h - 0.5); g.lineTo(clamp(x, bx + 6, bx + w - 6), by + h + 5); g.fill();
  g.fillStyle = ink; g.fillText(text, bx + 7, by + 12.5);
}
function drawActors() {
  const g = ctx, list = [...hosts.map((h) => guards[h]), ...hosts.map((h) => police[h]), ...thiefList()].sort((a, b) => a.y - b.y);
  for (const a of list) {   // beams under characters
    if (!a.beam || a.ko) continue;
    const hx = a.x + a.dir * 18, hy = a.y - 24, tx = a.beam.x, ty = a.beam.y;
    const police_ = a.role === "police";
    g.save(); g.globalAlpha = police_ ? 0.28 : 0.3; g.fillStyle = police_ ? "#6fd3ff" : "#fff1a6";
    const ang = Math.atan2(ty - hy, tx - hx), d = Math.hypot(tx - hx, ty - hy);
    g.beginPath(); g.moveTo(hx, hy); g.lineTo(hx + Math.cos(ang - 0.18) * d, hy + Math.sin(ang - 0.18) * d); g.lineTo(hx + Math.cos(ang + 0.18) * d, hy + Math.sin(ang + 0.18) * d); g.closePath(); g.fill(); g.restore();
  }
  for (const a of list) {
    if (a.role === "police" && alarmOn(a.host) && !reduceMotion.matches) {
      g.fillStyle = Math.floor(sim.t / 170) % 2 ? "rgba(224,88,74,.2)" : "rgba(74,163,255,.2)"; g.beginPath(); g.arc(a.x, a.y - 16, 30, 0, 6.283); g.fill();
    }
    drawPerson(a);
    if (a.pose === "repair" || a.pose === "hammer") {
      if (sim.t > a.nextSpark) { a.nextSpark = sim.t + 230; sparks(a.x + a.dir * 24, a.y - 12, 4); }
    }
  }
  for (const a of list) {
    const tagColor = a.role === "police" ? "#2f5575" : a.role === "guard" ? "#d9791d" : (a.sev === "compromised" ? "#b83a2e" : "#3b3b46");
    if (a.tag && !a.ko) {
      g.font = "bold 8px ui-monospace, Menlo, monospace";
      const w = g.measureText(a.tag).width + 10;
      pill(g, a.x - w / 2, a.y - 54, w, 12, tagColor); g.fillStyle = "#fff"; g.fillText(a.tag, a.x - w / 2 + 5, a.y - 45);
    }
    if (a.bubble) drawBubble(a.x, a.y - 58, a.bubble.text, a.bubble.tone);
  }
  for (const host of hosts) {   // repair progress bar over the guard
    const sc = scene[host], prog = repairProgress(sc), gd = guards[host];
    if (!prog || gd.pose !== "repair") continue;
    const w = 86, x = gd.x - w / 2, y = gd.y - 84;
    pill(g, x - 3, y - 3, w + 6, 26, "rgba(18,28,36,.92)", "#d9a42b");
    g.fillStyle = "#34444e"; g.fillRect(x, y + 12, w, 6);
    if (prog.pct === null) { g.fillStyle = "#ffd24a"; const o = (sim.t / 12) % (w + 20) - 20; g.save(); g.beginPath(); g.rect(x, y + 12, w, 6); g.clip(); g.fillRect(x + o, y + 12, 20, 6); g.restore(); }
    else { g.fillStyle = "#ffd24a"; g.fillRect(x, y + 12, w * prog.pct, 6); }
    g.fillStyle = "#fff"; g.font = "bold 8px ui-monospace, Menlo, monospace"; g.fillText(prog.label, x + 1, y + 8);
  }
}
function drawFx() {
  const g = ctx;
  for (const b of bullets) {
    b.trail.forEach((p, i) => { g.fillStyle = `rgba(255,226,122,${(i + 1) / (b.trail.length + 2) * 0.6})`; g.fillRect(p.x - 1.5, p.y - 1.5, 3, 3); });
    g.fillStyle = "#fff8d0"; g.fillRect(b.x - 2.5, b.y - 2.5, 5, 5);
  }
  for (const p of parts) {
    const k = p.life / p.max, alpha = clamp(1 - k, 0, 1);
    g.globalAlpha = alpha;
    if (p.k === "sq") { g.fillStyle = p.c; g.fillRect(Math.round(p.x), Math.round(p.y), p.size, p.size); }
    else if (p.k === "ring") { g.strokeStyle = p.c; g.lineWidth = 3; g.beginPath(); g.arc(p.x, p.y, 6 + k * p.r, 0, 6.283); g.stroke(); }
    else if (p.k === "tx") {
      g.font = `bold ${p.size}px ui-monospace, Menlo, monospace`; g.textAlign = "center"; g.lineWidth = 3; g.strokeStyle = "rgba(14,22,28,.85)"; g.strokeText(p.text, p.x, p.y);
      g.fillStyle = p.c; g.fillText(p.text, p.x, p.y); g.textAlign = "left";
    }
    g.globalAlpha = 1;
  }
}

/* ───────────────────────── update + render loop ───────────────────────── */
let fstateSweep = 0;
function update(dt) {
  sim.t += dt;
  runTasks();
  const allActors = [];
  for (const host of hosts) {
    const sc = scene[host], D = doorOf(host);
    sc.shutter += clamp(sc.shutTarget - sc.shutter, -dt * 0.0011, dt * 0.0011);
    sc.cut += clamp(sc.cutTarget - sc.cut, -dt * 0.0022, dt * 0.0022);
    const c = cableCut(host);
    if (sc.cut > 0.97 && !sc.cutFx) { sc.cutFx = true; sparks(c.x, c.y, 20); ring(c.x, c.y, "#ff8a3d", 650, 26); shake(240); popup(c.x + 40, c.y - 10, "KONEKSI PUTUS", "#ff8a6b", 10); }
    if (sc.cut < 0.03 && sc.cutFx) { sc.cutFx = false; greenSparks(c.x, c.y, 20); ring(c.x, c.y, "#7be3b0", 650, 26); popup(c.x + 40, c.y - 10, "TERSAMBUNG", "#7be3b0", 10); }
    const near = [police[host], guards[host], ...thiefList().filter((t) => t.host === host)].some((a) => Math.hypot(a.x - D.x, a.y - D.y) < 54 && !a.ko) && sc.shutter < 0.2;
    sc.door += clamp((near ? 1 : 0) - sc.door, -dt * 0.004, dt * 0.004);
    advanceScene(sc);
    updatePolice(host); updateGuard(host);
    allActors.push(police[host], guards[host]);
  }
  for (const th of thieves.values()) {
    if (th.dead) { for (const sc of Object.values(scene)) if (sc.thief === th) sc.thief = null; thieves.delete(th.uid); continue; }
    allActors.push(th);
  }
  for (const a of allActors) updateActor(a, dt);
  updateBullets(dt); updateParts(dt);
  if (sim.t > fstateSweep) {
    fstateSweep = sim.t + 1000;
    let changed = false;
    for (const [k, v] of fstate) if (!incidentActive(k.split(":")[0]) && sim.t - v.at > 45000) { fstate.delete(k); changed = true; }
    if (changed) layoutFiles();
  }
}
function draw() {
  const rect = canvas.getBoundingClientRect();
  if (!rect.width || !rect.height) return;
  const H = worldHeight(), want = clamp(rect.width * H / WORLD_W, 360, 1000);
  if (Math.abs(parseFloat(canvas.style.height || "0") - want) > 1) { canvas.style.height = `${want}px`; return; }
  const dpr = Math.min(window.devicePixelRatio || 1, 2), pw = Math.round(rect.width * dpr), ph = Math.round(rect.height * dpr);
  const scale = Math.min(rect.width / WORLD_W, rect.height / H);
  view = { scale, ox: (rect.width - WORLD_W * scale) / 2, oy: (rect.height - H * scale) / 2, dpr };
  if (canvas.width !== pw || canvas.height !== ph) { canvas.width = pw; canvas.height = ph; bg.key = ""; }
  ensureBackground();
  const k = sim.shake > 0 ? Math.min(1, sim.shake / 160) : 0, sx = (Math.random() - 0.5) * 5 * k, sy = (Math.random() - 0.5) * 5 * k;
  ctx.setTransform(1, 0, 0, 1, 0, 0); ctx.imageSmoothingEnabled = false;
  ctx.fillStyle = "#8fab8b"; ctx.fillRect(0, 0, pw, ph);
  ctx.drawImage(bg.canvas, Math.round(sx * dpr), Math.round(sy * dpr));
  ctx.setTransform(dpr * scale, 0, 0, dpr * scale, dpr * (view.ox + sx), dpr * (view.oy + sy));
  drawNetwork();
  for (const host of hosts) drawRoomDynamic(host);
  for (const f of patrol.layout) drawFile(f);
  drawActors();
  for (const host of hosts) drawLockdown(host);
  drawFx();
  for (const host of hosts) drawBanner(host);
  ctx.setTransform(1, 0, 0, 1, 0, 0);
}
function frame(now) {
  const real = Math.min(50, now - (sim.last || now));
  sim.last = now;
  if (!patrol.paused && real > 0) update(real * patrol.speed);
  draw();
  window.requestAnimationFrame(frame);
}

/* ───────────────────────── data loading ───────────────────────── */
async function loadState() {
  try {
    const response = await fetch("/api/patrol/state", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const state = await response.json();
    patrol.files = Array.isArray(state.files) ? state.files : [];
    const events = Array.isArray(state.events) ? state.events : [];
    patrol.events = events;
    if (!patrol.primed) { events.forEach((e) => patrol.seen.add(e.id)); patrol.primed = true; }
    else events.forEach(ingestLive);
    refreshPatrol();
    connectEvents(events.at(-1)?.id || 0);
  } catch (error) {
    $("#patrol-source-status").textContent = "Collector terputus";
  }
}
/* ───────────────────────── file system browser ───────────────────────── */
const fsBrowser = { host: "server-a", path: "/", request: 0 };
const FS_LABEL = { dir: "Folder", file: "File", link: "Tautan", other: "Khusus", virtual: "Virtual, tidak dipindai" };
function formatBytes(value) {
  if (!Number.isFinite(value)) return "";
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let size = value / 1024, unit = 0;
  while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit += 1; }
  return `${size.toFixed(size < 10 ? 1 : 0)} ${units[unit]}`;
}
function formatFsTime(seconds) {
  return Number.isFinite(seconds) ? new Date(seconds * 1000).toLocaleString("id-ID", { dateStyle: "medium", timeStyle: "short" }) : "-";
}
const fsChild = (name) => `${fsBrowser.path === "/" ? "" : fsBrowser.path}/${name}`;
function renderFsBreadcrumb() {
  const node = $("#fs-breadcrumb");
  node.replaceChildren();
  const addCrumb = (label, path) => {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = label;
    button.addEventListener("click", () => loadFsListing(path));
    node.append(button);
  };
  addCrumb("/", "/");
  let current = "";
  for (const part of fsBrowser.path.split("/").filter(Boolean)) {
    current += `/${part}`;
    addCrumb(cleanText(part, 60), current);
  }
}
function renderFsEntries(listing) {
  const node = $("#fs-list");
  node.replaceChildren();
  for (const entry of listing.entries) {
    const row = document.createElement("li");
    const button = document.createElement("button");
    button.type = "button";
    button.className = `fs-row fs-${entry.type}`;
    const path = fsChild(entry.name);
    const name = document.createElement("span");
    name.className = "fs-name";
    name.textContent = cleanText(path, 1024);
    const meta = document.createElement("small");
    meta.textContent = entry.type === "file" ? formatBytes(entry.size) : FS_LABEL[entry.type] || "";
    button.append(name, meta);
    button.addEventListener("click", () => {
      if (entry.type === "dir") { loadFsListing(path); return; }
      showDetail(`${HOST_LABEL[listing.host_id]} · ${cleanText(path, 512)} · ${FS_LABEL[entry.type] || "-"} · ${formatBytes(entry.size) || "-"} · ${formatFsTime(entry.mtime)}`);
    });
    row.append(button);
    node.append(row);
  }
}
function fsStatusText(listing) {
  if (!listing.scanned_at) return "Menunggu inventaris pertama dari agent.";
  if (!listing.found) return "Folder ini tidak ada di inventaris terakhir.";
  const scanned = new Date(listing.scanned_at).toLocaleTimeString("id-ID", { hour: "2-digit", minute: "2-digit" });
  const shown = listing.entries.length < listing.total ? `${listing.entries.length} dari ${listing.total}` : `${listing.total}`;
  const denied = listing.denied ? " · Akses ditolak saat scan" : "";
  return `${shown} item · ${listing.entry_count.toLocaleString("id-ID")} total · Scan ${scanned}${denied}`;
}
async function loadFsListing(path = fsBrowser.path) {
  const request = ++fsBrowser.request;
  fsBrowser.host = $("#fs-host").value;
  fsBrowser.path = path;
  renderFsBreadcrumb();
  $("#fs-status").textContent = "Memuat…";
  try {
    const query = new URLSearchParams({ host: fsBrowser.host, path });
    const response = await fetch(`/api/patrol/fs?${query}`, { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const listing = await response.json();
    if (request !== fsBrowser.request) return;
    renderFsEntries(listing);
    $("#fs-status").textContent = fsStatusText(listing);
  } catch (error) {
    if (request !== fsBrowser.request) return;
    $("#fs-list").replaceChildren();
    $("#fs-status").textContent = "Inventaris tidak dapat dimuat.";
  }
}
function initFsBrowser() {
  document.querySelector('.s-tab[data-target="s-files"]').addEventListener("click", () => loadFsListing());
  $("#fs-refresh").addEventListener("click", () => loadFsListing());
  $("#fs-host").addEventListener("change", () => loadFsListing("/"));
}

function connectEvents(after) {
  if (patrol.source) return;
  patrol.source = new EventSource(`/api/patrol/stream?after=${encodeURIComponent(after)}`);
  patrol.source.addEventListener("patrol", (message) => {
    try {
      const event = JSON.parse(message.data);
      if (!patrol.events.some((e) => e.id === event.id)) patrol.events.unshift(event);
      patrol.events = patrol.events.slice(0, 100);
      ingestLive(event);
      refreshPatrol();
    } catch (error) {
      $("#patrol-source-status").textContent = "Payload rusak";
    }
  });
  patrol.source.onerror = () => { $("#patrol-source-status").textContent = "Menyambung ulang…"; };
}
/* Polling dipercepat selama serangan agar status HAProxy yang berubah cepat terlihat. */
function schedulePoll() {
  const busy = Date.now() < (patrol.fastUntil || 0) || hosts.some((host) => incidentActive(host));
  window.setTimeout(async () => { await pollDashboard(); schedulePoll(); }, busy ? 1000 : 2500);
}
async function pollDashboard() {
  if (document.hidden) return;
  try {
    const response = await fetch("/v1/dashboard", { cache: "no-store" });
    if (!response.ok) return;
    const data = await response.json();
    patrol.analysis = data.analysis || {};
    const latest = {};
    for (const run of Array.isArray(data.remediations) ? data.remediations : []) if (!latest[run.host_id]) latest[run.host_id] = run;
    for (const host of hosts) {
      if (latest[host]) applyRemediation(latest[host]);
      applyBackend(host, data.backends?.[host]);
    }
  } catch (error) { /* collector offline: overview tab already reports it */ }
}

/* ───────────────────────── incident strip (DOM) ───────────────────────── */
function updateAttackButton() {
  const sc = scene[$("#patrol-incident-host").value];
  $("#patrol-incident-demo").disabled = Boolean(sc.attackPending || sc.queue.length || incidentActive(sc.host) || !sc.backend.startsWith("UP"));
}
function updateIncidentUI() {
  updateAttackButton();
  const node = $("#patrol-incident");
  if (!node) return;
  const sc = hosts.map((h) => scene[h]).filter((s) => s.vis).sort((a, b) => b.visSince - a.visSince)[0];
  if (!sc) { node.hidden = true; return; }
  node.hidden = false;
  node.style.setProperty("--incident-color", STAGE_TEXT[sc.vis]?.[1] || "#e0584a");
  $("#incident-title").textContent = `${HOST_LABEL[sc.host]} · ${STAGE_TEXT[sc.vis]?.[0] || sc.vis}`;
  $("#incident-lb").textContent = `LB  ${hosts.map((host) => `${host.at(-1).toUpperCase()} ${lbStatus(host)[0]}`).join("  ·  ")}`;
  const idx = STAGES.indexOf(sc.vis), prog = repairProgress(sc);
  $("#incident-timer").textContent = prog ? prog.label : "";
  node.querySelectorAll("[data-stage]").forEach((li) => {
    const i = STAGES.indexOf(li.dataset.stage);
    li.className = sc.vis === "FAILED" ? (i <= STAGES.indexOf("ISOLATING") && sc.seen.has(li.dataset.stage) ? "done" : "") : i < idx ? "done" : i === idx ? "current" : "";
  });
}

/* ───────────────────────── interaction ───────────────────────── */
function actorDetail(a) {
  if (a.role === "police") return `Polisi AI · ${HOST_LABEL[a.host]} · patroli ${filesOf(a.host).length} file (SHA-256)`;
  if (a.role === "guard") return `Satpam · ${HOST_LABEL[a.host]} · perbaikan + verifikasi`;
  return `${a.ko ? "Intruder dilumpuhkan" : "Intruder"} · ${a.tag || a.id} · ${HOST_LABEL[a.host]} · severity ${a.sev || "safe"}`;
}
canvas.addEventListener("click", (event) => {
  const rect = canvas.getBoundingClientRect();
  const x = (event.clientX - rect.left - view.ox) / view.scale, y = (event.clientY - rect.top - view.oy) / view.scale;
  const actors = [...hosts.map((h) => police[h]), ...hosts.map((h) => guards[h]), ...thiefList()];
  const hitActor = actors.map((a) => ({ a, d: Math.hypot(a.x - x, a.y - 20 - y) })).filter((o) => o.d < 28).sort((p, q) => p.d - q.d)[0];
  if (hitActor) return showDetail(actorDetail(hitActor.a));
  const file = patrol.layout.map((f) => ({ f, d: Math.hypot(f.x - x, f.y - y) })).filter((o) => o.d < 30).sort((p, q) => p.d - q.d)[0]?.f;
  if (file) showDetail({ ts: file.checked_at, actor: "police", action: "read", host_id: file.host_id, path: file.path, hash_new: file.sha256, severity: severityForFile(file) });
});
function selectTab(name) {
  const isPatrol = name === "patrol";
  const patrolView = $("#patrol-view");
  const overviewView = $("#overview-view");

  if (isPatrol) {
    overviewView.style.opacity = "0";
    setTimeout(() => {
      overviewView.hidden = true;
      patrolView.hidden = false;
      patrolView.style.opacity = "0";
      setTimeout(() => { patrolView.style.opacity = "1"; }, 20);
    }, 150);
  } else {
    patrolView.style.opacity = "0";
    setTimeout(() => {
      patrolView.hidden = true;
      overviewView.hidden = false;
      overviewView.style.opacity = "0";
      setTimeout(() => { overviewView.style.opacity = "1"; }, 20);
    }, 150);
  }

  $("#tab-patrol").setAttribute("aria-selected", String(isPatrol));
  $("#tab-overview").setAttribute("aria-selected", String(!isPatrol));
  if (isPatrol) layoutFiles();
}
function scheduleDemo(chain) {
  later(4200, () => { if (patrol.demo && patrol.demoChain === chain) { addDemoPair(); scheduleDemo(chain); } });
}
function toggleDemo() {
  patrol.demo = !patrol.demo;
  const button = $("#patrol-demo-toggle");
  button.setAttribute("aria-pressed", String(patrol.demo));
  button.textContent = patrol.demo ? "Hentikan demo" : "Mulai demo";
  patrol.demoChain = (patrol.demoChain || 0) + 1;
  if (patrol.demo) { addDemoPair(); scheduleDemo(patrol.demoChain); }
  else { patrol.demoEvents = []; refreshPatrol(); }
}
$("#tab-patrol").addEventListener("click", () => selectTab("patrol"));
$("#tab-overview").addEventListener("click", () => selectTab("overview"));
$("#patrol-demo-toggle").addEventListener("click", toggleDemo);
$("#patrol-incident-demo")?.addEventListener("click", () => {
  patrol.incidentHost = $("#patrol-incident-host")?.value === "server-b" ? "server-b" : "server-a";
  launchAttack(patrol.incidentHost);
});
$("#patrol-incident-host").addEventListener("change", updateAttackButton);
$("#patrol-pause").addEventListener("click", (event) => {
  patrol.paused = !patrol.paused;
  event.currentTarget.setAttribute("aria-pressed", String(patrol.paused));
  event.currentTarget.textContent = patrol.paused ? "Lanjutkan" : "Jeda";
});
$("#patrol-speed").addEventListener("change", (event) => { patrol.speed = Number(event.target.value) || 1; });
$("#patrol-filter").addEventListener("change", (event) => { patrol.filter = event.target.value; renderPatrolEvents(); });
$(".dashboard-tabs").addEventListener("keydown", (event) => {
  const tabs = [$("#tab-overview"), $("#tab-patrol")], current = tabs.indexOf(document.activeElement);
  if (event.key === "ArrowRight" || event.key === "ArrowLeft") {
    event.preventDefault();
    const next = tabs[(current + (event.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
    next.click(); next.focus();
  }
});

/* ───────────────────────── boot ───────────────────────── */
initActors();
initFsBrowser();
loadState();
pollDashboard();
window.setInterval(loadState, 4000);
schedulePoll();
window.setInterval(updateIncidentUI, 250);
window.requestAnimationFrame(frame);
window.__patrol = { patrol, sim, scene, police, guards, thieves, fstate, launchAttack, ingestLive, applyRemediation, applyBackend, enterStage, roomRect, doorOf, worldHeight };
})();
