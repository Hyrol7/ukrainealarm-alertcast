// alertcast — адмінка. Без бібліотек; DOM будується через h(), тож дані ніколи не потрапляють
// у розмітку як HTML (крім QR — це SVG, згенерований сервером).
"use strict";

// ---------- утиліти ----------

const $root = document.getElementById("root");
let ME = null; // {ip, version, publicURL, csrf}
let REGIONS = null; // [{regionId, regionName, regionType, parentId, depth}]
let cleanup = []; // що закрити при переході (EventSource, таймери)

function h(tag, attrs, ...kids) {
  const svg = ["svg", "path", "line", "polyline", "rect", "text", "g", "circle"].includes(tag);
  const el = svg ? document.createElementNS("http://www.w3.org/2000/svg", tag) : document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "cls") el.setAttribute("class", v);
    else if (k === "html") el.innerHTML = v; // лише для SVG від сервера
    else el.setAttribute(k, v === true ? "" : v);
  }
  add(el, kids);
  return el;
}
function fill(el, ...kids) { el.replaceChildren(); return add(el, kids); }
function add(el, kids) {
  for (const c of kids.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
const ICON = {
  mon: "M3 12h4l3-8 4 16 3-8h4",
  tok: "M8 11a4 4 0 1 0 0 8a4 4 0 1 0 0-8M11 12l9-9M17 6l3 3",
  test: "M9 3h6M10 3v6l-5 9a2 2 0 0 0 2 3h10a2 2 0 0 0 2-3l-5-9V3",
  log: "M4 6h16M4 12h16M4 18h10",
};
const icon = (d) => h("svg", { width: 18, height: 18, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": 2, "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true" }, h("path", { d }));

const nf = new Intl.NumberFormat("uk-UA");
const num = (v) => nf.format(v || 0);
const pad = (n) => String(n).padStart(2, "0");
const tz = { timeZone: "Europe/Kyiv" };
function hm(t) { return new Date(t).toLocaleTimeString("uk-UA", { ...tz, hour: "2-digit", minute: "2-digit" }); }
function hms(t) { return new Date(t).toLocaleTimeString("uk-UA", { ...tz, hour: "2-digit", minute: "2-digit", second: "2-digit" }); }
function dt(t) { return new Date(t).toLocaleString("uk-UA", { ...tz, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }); }
function day(t) { return new Date(t).toLocaleDateString("sv-SE", tz); } // 2026-11-08
function dur(sec) {
  sec = Math.max(0, Math.round(sec));
  if (sec < 60) return sec + " с";
  if (sec < 3600) return Math.round(sec / 60) + " хв";
  if (sec < 86400) return Math.floor(sec / 3600) + " год " + Math.round((sec % 3600) / 60) + " хв";
  return Math.floor(sec / 86400) + " д " + Math.floor((sec % 86400) / 3600) + " год";
}
function ago(t) {
  if (!t) return "ніколи";
  const s = (Date.now() - new Date(t)) / 1000;
  if (s < 60) return "щойно";
  if (s > 7 * 86400) return day(t);
  return dur(s) + " тому";
}
const zeroTime = (t) => !t || t.startsWith("0001-");

class HttpError extends Error { constructor(code, msg, body) { super(msg); this.code = code; this.body = body; } }

// bg — фонове оновлення: не продовжує сесію (простій 30 хв рахується від дій людини)
async function api(method, path, body, bg) {
  const opt = { method, headers: bg ? { "X-Background": "1" } : {}, credentials: "same-origin", cache: "no-store" };
  if (method !== "GET") {
    opt.headers["Content-Type"] = "application/json";
    if (ME && ME.csrf) opt.headers["X-CSRF"] = ME.csrf;
    opt.body = JSON.stringify(body || {});
  }
  const r = await fetch("/api" + path, opt);
  let data = null;
  try { data = await r.json(); } catch (e) { /* порожньо */ }
  if (r.status === 401 && path !== "/login") { toLogin(); throw new HttpError(401, "потрібен вхід"); }
  if (!r.ok) throw new HttpError(r.status, (data && data.error) || "HTTP " + r.status, data);
  return data;
}

function toLogin() {
  if (ME) ME.csrf = null;
  if (location.pathname !== "/login") history.replaceState(null, "", "/login?next=" + encodeURIComponent(location.pathname));
  route();
}

// кнопка з підтвердженням без діалогів браузера: перше натискання питає, друге — виконує
function confirmBtn(label, ask, cls, action) {
  const b = h("button", { type: "button", cls: "btn " + (cls || "") }, label);
  let armed = null;
  b.addEventListener("click", async () => {
    if (!armed) {
      b.textContent = ask;
      armed = setTimeout(() => { b.textContent = label; armed = null; }, 4000);
      return;
    }
    clearTimeout(armed); armed = null; b.disabled = true;
    try { await action(); } catch (e) { alertBox(e); } finally { b.disabled = false; b.textContent = label; }
  });
  return b;
}

let errHost = null;
function alertBox(e) {
  if (e instanceof HttpError && e.code === 401) return;
  const m = h("div", { cls: "err", role: "alert" }, String(e.message || e));
  (errHost || document.querySelector("main") || $root).prepend(m);
  setTimeout(() => m.remove(), 6000);
}

async function regions() {
  if (!REGIONS) REGIONS = await api("GET", "/regions");
  return REGIONS;
}
function regionName(id) {
  const r = REGIONS && REGIONS.find((x) => x.regionId === id);
  return r ? r.regionName : "регіон " + id;
}
function regionsText(ids) {
  if (!ids || !ids.length) return "усі регіони";
  if (ids.length <= 2) return ids.map(regionName).join(" + ");
  return ids.length + " регіонів: " + ids.slice(0, 2).map(regionName).join(", ") + "…";
}

// ---------- каркас ----------

function shell(active, ...content) {
  const link = (href, key, label, ic) => h("a", { href, cls: "nav" + (active === key ? " on" : ""), "aria-current": active === key ? "page" : null, onclick: nav }, icon(ic), label);
  const main = h("main", {}, ...content);
  errHost = main;
  fill($root, h("div", { cls: "app" },
    h("nav", { cls: "side", "aria-label": "Розділи" },
      h("span", { cls: "brand mono" }, "alertcast · адмінка"),
      link("/", "mon", "Моніторинг", ICON.mon),
      link("/tokens", "tok", "Токени", ICON.tok),
      link("/test", "test", "Тестова область", ICON.test),
      link("/journal", "log", "Журнал", ICON.log),
      h("span", { cls: "grow" }),
      h("span", { cls: "who" }, "admin · з ", h("span", { cls: "mono" }, ME.ip)),
      h("button", { type: "button", cls: "nav", onclick: logout }, "Вийти")),
    main));
  return main;
}

function nav(ev) {
  if (ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.button) return;
  ev.preventDefault();
  go(ev.currentTarget.getAttribute("href"));
}
function go(path) { history.pushState(null, "", path); route(); }
window.addEventListener("popstate", route);

async function logout() {
  try { await api("POST", "/logout"); } catch (e) { /* все одно на вхід */ }
  ME.csrf = null;
  history.replaceState(null, "", "/login");
  route();
}

async function route() {
  for (const f of cleanup) f();
  cleanup = [];
  window.scrollTo(0, 0);
  const p = location.pathname;
  try {
    if (!ME || !ME.csrf) {
      ME = await api("GET", "/me");
      if (!ME.authed) return pageLogin();
    }
    if (p === "/login") { history.replaceState(null, "", "/"); return route(); }
    await regions();
    if (p === "/") return await pageMonitoring();
    if (p === "/tokens") return await pageTokens();
    if (p === "/tokens/new") return pageTokenForm(null);
    if (p.startsWith("/tokens/")) return await pageToken(decodeURIComponent(p.slice(8)));
    if (p === "/test") return await pageTest();
    if (p === "/journal") return await pageJournal();
    shell("", h("h1", {}, "Тут нічого немає"), h("a", { href: "/", onclick: nav }, "На моніторинг"));
  } catch (e) {
    if (e instanceof HttpError && e.code === 401) return;
    fill($root, h("main", {}, h("div", { cls: "err", role: "alert" }, "Помилка: " + e.message),
      h("button", { cls: "btn", type: "button", onclick: route }, "Спробувати ще")));
  }
}

// ---------- вхід ----------

function pageLogin() {
  const pw = h("input", { id: "pw", type: "password", autocomplete: "current-password", cls: "in", required: true });
  const otp = h("input", { id: "otp", inputmode: "numeric", autocomplete: "one-time-code", maxlength: 7, placeholder: "000 000", cls: "in otp", required: true });
  const msg = h("div", { role: "alert" });
  const btn = h("button", { type: "submit", cls: "btn dark", disabled: !ME.configured }, "Увійти");
  let timer = null;
  const countdown = (sec, text) => {
    clearInterval(timer);
    btn.disabled = true;
    const tick = () => {
      if (sec <= 0) { clearInterval(timer); btn.disabled = false; fill(msg, h("div", { cls: "err" }, text)); return; }
      fill(msg, h("div", { cls: "err" }, text + " Наступна спроба — через ", h("span", { cls: "mono" }, sec + " с"), "."));
      sec--;
    };
    tick();
    timer = setInterval(tick, 1000);
  };
  cleanup.push(() => clearInterval(timer));
  const form = h("form", {
    onsubmit: async (ev) => {
      ev.preventDefault();
      btn.disabled = true;
      fill(msg);
      try {
        const r = await api("POST", "/login", { password: pw.value, code: otp.value.replace(/\s/g, "") });
        void r;
        ME = null; // перечитати /api/me: після входу там є csrf, адреса, версія
        const next = location.pathname === "/login" ? new URLSearchParams(location.search).get("next") : location.pathname + location.search;
        history.replaceState(null, "", next && next.startsWith("/") && !next.startsWith("//") && !next.startsWith("/login") ? next : "/");
        route();
      } catch (e) {
        otp.value = "";
        const retry = (e.body && e.body.retry) || 0;
        const text = e.code === 429 ? "Забагато невдалих спроб." : e.message.charAt(0).toUpperCase() + e.message.slice(1) + ".";
        if (retry > 0) countdown(retry, text);
        else { btn.disabled = false; fill(msg, h("div", { cls: "err" }, text)); }
        (e.code === 401 ? pw : otp).focus();
      }
    },
  },
    h("span", { cls: "mono k" }, "alertcast · адмінка"),
    h("h1", {}, "Вхід"),
    !ME.configured && h("div", { cls: "err" }, "Вхід ще не налаштовано. На сервері: ", h("span", { cls: "mono" }, "sudo alertcast admin setup")),
    h("label", { cls: "f" }, "Пароль", pw),
    h("label", { cls: "f" }, "Код із застосунку 2FA", otp),
    msg, btn,
    h("p", { cls: "k" }, "Доступно лише через VPN. Загубили телефон з 2FA — ", h("span", { cls: "mono" }, "sudo alertcast admin setup"), " на сервері."));
  fill($root, h("div", { cls: "login" }, form));
  pw.focus();
}

// ---------- графіки (SVG) ----------

function tooltip() {
  let t = document.querySelector(".tip");
  if (!t) { t = h("div", { cls: "tip hidden" }); document.body.append(t); }
  return t;
}

// lineChart: series=[{values:[...|null], color, dash, label, fmt}], xs — unix-секунди слотів
function lineChart(xs, series, { width = 960, height = 200, yfmt = (v) => v, ymin = 0, label = "" } = {}) {
  const W = width, H = height, L = 52, B = 22, T = 10;
  let ymax = 0;
  for (const s of series) for (const v of s.values) if (v != null && v > ymax) ymax = v;
  ymax = niceMax(ymax || 1);
  const x = (i) => L + (i / Math.max(1, xs.length - 1)) * (W - L);
  const y = (v) => T + (1 - (v - ymin) / (ymax - ymin)) * (H - T - B);
  const svg = h("svg", { cls: "chart", viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": label });
  const g = h("g", { stroke: "#EEECE6" });
  for (let k = 0; k <= 3; k++) {
    const v = ymin + ((ymax - ymin) * k) / 3;
    g.append(h("line", { x1: L, x2: W, y1: y(v), y2: y(v) }));
    svg.append(h("text", { x: 0, y: y(v) + 4 }, yfmt(v)));
  }
  svg.prepend(g);
  for (const i of xTicks(xs)) svg.append(h("text", { x: Math.min(x(i), W - 40), y: H - 4 }, hm(xs[i] * 1000)));
  for (const s of series) {
    let d = "", pen = false;
    s.values.forEach((v, i) => {
      if (v == null) { pen = false; return; }
      d += (pen ? "L" : "M") + x(i).toFixed(1) + " " + y(v).toFixed(1);
      pen = true;
    });
    svg.append(h("path", { d, fill: "none", stroke: s.color, "stroke-width": 2.5, "stroke-dasharray": s.dash || null, "stroke-linejoin": "round", "stroke-linecap": "round" }));
  }
  hover(svg, xs, (i) => hm(xs[i] * 1000) + "\n" + series.map((s) => s.label + ": " + (s.values[i] == null ? "—" : s.fmt(s.values[i]))).join("\n"), x, L, W);
  return svg;
}

// barChart: стовпці з шарами; groups=[{t, parts:[v...]}], colors для шарів
function barChart(groups, colors, labels, { width = 480, height = 160, label = "", per = "" } = {}) {
  const W = width, H = height, L = 36, B = 20, T = 8;
  let ymax = 0;
  for (const g of groups) ymax = Math.max(ymax, g.parts.reduce((a, b) => a + b, 0));
  ymax = niceMax(ymax || 1);
  const bw = (W - L) / groups.length;
  const y = (v) => T + (1 - v / ymax) * (H - T - B);
  const svg = h("svg", { cls: "chart", viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": label });
  for (let k = 0; k <= 2; k++) {
    const v = (ymax * k) / 2;
    svg.append(h("line", { x1: L, x2: W, y1: y(v), y2: y(v), stroke: "#EEECE6" }));
    svg.append(h("text", { x: 0, y: y(v) + 4 }, fmtShort(v)));
  }
  groups.forEach((g, i) => {
    let acc = 0;
    g.parts.forEach((v, k) => {
      if (v <= 0) return;
      svg.append(h("rect", { x: L + i * bw + 1, width: Math.max(1, bw - 2), y: y(acc + v), height: y(acc) - y(acc + v), fill: colors[k] }));
      acc += v;
    });
  });
  const xs = groups.map((g) => g.t);
  for (const i of xTicks(xs, 2)) svg.append(h("text", { x: Math.min(L + i * bw, W - 40), y: H - 4 }, hm(xs[i] * 1000)));
  hover(svg, xs, (i) => hm(xs[i] * 1000) + "–" + hm((xs[i] + 3600) * 1000) + per + "\n" + labels.map((l, k) => l + ": " + fmtShort(groups[i].parts[k])).join("\n"),
    (i) => L + (i + 0.5) * bw, L, W, true);
  return svg;
}

function hover(svg, xs, text, x, L, W, bars) {
  const tip = tooltip();
  const ln = h("line", { y1: 0, y2: 1000, stroke: "#1B1B19", "stroke-opacity": 0.25, cls: "hidden" });
  svg.append(ln);
  svg.addEventListener("mousemove", (ev) => {
    const r = svg.getBoundingClientRect();
    const px = ((ev.clientX - r.left) / r.width) * W;
    if (px < L) { tip.classList.add("hidden"); ln.classList.add("hidden"); return; }
    const n = xs.length;
    let i = bars ? Math.floor(((px - L) / (W - L)) * n) : Math.round(((px - L) / (W - L)) * (n - 1));
    i = Math.max(0, Math.min(n - 1, i));
    ln.setAttribute("x1", x(i)); ln.setAttribute("x2", x(i)); ln.classList.remove("hidden");
    tip.textContent = text(i);
    tip.classList.remove("hidden");
    tip.style.left = Math.min(ev.clientX + 14, innerWidth - tip.offsetWidth - 8) + "px";
    tip.style.top = ev.clientY + 14 + "px";
  });
  svg.addEventListener("mouseleave", () => { tip.classList.add("hidden"); ln.classList.add("hidden"); });
}

function xTicks(xs, every = 6) {
  const out = [];
  for (let i = 0; i < xs.length; i++) {
    const d = new Date(xs[i] * 1000);
    const hr = Number(d.toLocaleString("en-GB", { ...tz, hour: "2-digit", hourCycle: "h23" }));
    const mn = Number(d.toLocaleString("en-GB", { ...tz, minute: "2-digit" }));
    if (mn === 0 && hr % every === 0) out.push(i);
  }
  return out;
}
function niceMax(v) {
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 1.5, 2, 3, 5, 7.5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}
function fmtShort(v) { return v >= 1000 ? (v / 1000).toFixed(v >= 10000 ? 0 : 1) + "k" : String(Math.round(v * 10) / 10); }
const fmtSec = (ms) => (ms >= 10000 ? Math.round(ms / 1000) : (ms / 1000).toFixed(1)) + " с";
const fmtMs = (ms) => (ms >= 1000 ? fmtSec(ms) : (ms < 10 ? ms.toFixed(1) : Math.round(ms)) + " мс");

// 1440 хвилинних слотів за 24 год; відсутні хвилини (служба не працювала) — null
function minuteSlots(minutes, now) {
  const end = Math.floor(now / 60) * 60, start = end - 1440 * 60;
  const by = new Map(minutes.map((m) => [m.t, m]));
  const xs = [], ms = [];
  for (let t = start; t < end; t += 60) { xs.push(t); ms.push(by.get(t) || null); }
  return { xs, ms };
}
function quant(vals, q) {
  const v = vals.filter((x) => x != null && x >= 0).sort((a, b) => a - b);
  return v.length ? v[Math.floor(q * (v.length - 1))] : null;
}
// buckets — звести хвилини до відрізків по n хвилин: f(значення відрізка) або null, якщо даних немає
function buckets(xs, vals, n, f) {
  const bx = [], bv = [];
  for (let i = 0; i < xs.length; i += n) {
    const part = vals.slice(i, i + n).filter((v) => v != null);
    bx.push(xs[i]);
    bv.push(part.length ? f(part) : null);
  }
  return { bx, bv };
}
const median = (a) => quant(a, 0.5);
const maxOf = (a) => Math.max(...a);

function hourly(xs, ms, parts) {
  const out = [];
  for (let i = 0; i < xs.length; i += 60) {
    const sum = parts.map(() => 0);
    for (let k = i; k < i + 60 && k < xs.length; k++) if (ms[k]) parts.forEach((f, j) => (sum[j] += f(ms[k])));
    out.push({ t: xs[i], parts: sum });
  }
  return out;
}

// ---------- моніторинг ----------

async function pageMonitoring() {
  const [ov, met, jr, bans] = await Promise.all([api("GET", "/overview"), api("GET", "/metrics"), api("GET", "/journal?limit=8"), api("GET", "/bans")]);
  met.minutes = met.minutes || [];
  const live = h("span", { cls: "k mono" });
  const liveDot = h("span", { cls: "dot" });
  const tiles = h("section", { cls: "grid4", "aria-label": "Стан" });
  const cards = h("div", { cls: "row" });
  const latency = h("section", { cls: "card" });
  const charts = h("div", { cls: "row" });
  const jcard = h("section", { cls: "card" });
  const bcard = h("section", { cls: "card" });
  shell("mon",
    h("div", { cls: "head" }, h("h1", {}, "Моніторинг"), h("span", { cls: "lg" }, liveDot, "наживо · ", live)),
    tiles, cards, latency, charts, h("div", { cls: "row" }, jcard, bcard));

  const drawOverview = (o) => {
    live.textContent = hms(o.now * 1000);
    const src = o.source, ad = o.alertd || {};
    const tile = (k, dot, v, sub) => h("div", { cls: "card tile" }, h("span", { cls: "k" }, k), h("span", { cls: "v" }, dot && h("span", { cls: "dot " + dot }), v), h("span", { cls: "k" }, sub));
    fill(tiles, 
      tile("alertcast", "ok", "online", h("span", { cls: "mono" }, o.version + " · працює " + dur(o.now - o.started))),
      tile("Зв'язок з alertd", src.connected ? "ok" : "bad", src.connected ? "потік відкритий" : "немає зв'язку",
        src.connected ? ["перепідключень: ", h("span", { cls: "mono" }, src.reconnects), " · resync: ", h("span", { cls: "mono" }, src.resyncs)] : (src.lastError || "")),
      tile("Дані", src.stale ? "warn" : "ok", src.stale ? "застарілі" : "свіжі",
        src.verifiedAt > 0 ? ["звірка з API ", h("span", { cls: "mono" }, dur(o.now - src.verifiedAt)), " тому"] : "звірки ще не було"),
      h("div", { cls: "card tile" }, h("span", { cls: "k" }, "Потоки"), h("span", { cls: "big" }, num(o.streams.total), " ", h("small", {}, "/ " + num(o.streams.max))),
        h("span", { cls: "k" }, "токенів на зв'язку: ", h("span", { cls: "mono" }, o.streams.tokens))));
    const kv = (k, v) => h("div", { cls: "kv" }, h("span", {}, k), h("span", { cls: "mono" }, v));
    const wh = ad.webhooks || {};
    const t = (s) => (s ? hms(s) + " · " + ago(s) : "—");
    const paused = ad.apiPausedUntil && new Date(ad.apiPausedUntil) > new Date() ? "до " + hms(ad.apiPausedUntil) : "ні";
    fill(cards, 
      h("section", { cls: "card" }, h("h2", { cls: "h2" }, "alertd (збирач)"),
        o.alertdError ? h("div", { cls: "err" }, "Немає відповіді: " + o.alertdError) : h("div", {},
          kv("Останній webhook", t(ad.lastWebhook)),
          kv("Остання звірка з API", t(ad.lastSync)),
          kv("Webhook прийнято / дублі / відхилено", num(wh.accepted) + " / " + num(wh.duplicates) + " / " + num((wh.rejected || 0) + (wh.badJSON || 0))),
          kv("Справжні пропуски webhook", num(ad.webhookMisses)),
          kv("Звірка виправила стан", num(ad.reconcileFixes)),
          kv("Пауза API (429)", paused),
          kv("Записів БД не вдалося", num(ad.db && ad.db.dropped)),
          kv("Працює", (ad.version || "?") + " · " + (ad.uptime || "?"))),
        h("span", { cls: "k" }, "Лічильники alertd — з його запуску.")),
      h("section", { cls: "card" }, h("h2", { cls: "h2" }, "alertcast (розсилач)"), h("div", {},
        kv("Запитів за останню хвилину", num(o.lastMinute.ok + o.lastMinute.unauth + o.lastMinute.forbid + o.lastMinute.limited)),
        kv("Успішних за 24 год", num(o.requests24.ok)),
        kv("401 / 403 за 24 год", num(o.requests24.unauth) + " / " + num(o.requests24.forbid)),
        kv("429 за 24 год", num(o.requests24.limited)),
        kv("Токенів / сесій браузера", num(o.tokens) + " / " + num(o.sessions)),
        kv("Заблоковано адрес зараз", num(o.bans)),
        kv("Активних тривог у стані", num(o.activeAlerts) + (o.test ? " + тестових " + o.test : "")),
        kv("Сторожовий таймер systemd", !o.watchdog.enabled ? "вимкнено" : o.now - o.watchdog.lastOK < 60 ? "ok" : "немає сигналу"))));
  };
  drawOverview(ov);

  const drawMetrics = (m) => {
    const { xs, ms } = minuteSlots(m.minutes, m.now);
    const pick = (f) => ms.map((x) => (x && f(x) >= 0 ? f(x) : null));
    const full = pick((x) => x.full[0]), web = pick((x) => x.webhook[0]), del = pick((x) => x.delivery[0]);
    const fullP = pick((x) => x.full[1]), webP = pick((x) => x.webhook[1]), delP = pick((x) => x.delivery[1]);
    const stat = (k, a, b, f) => h("div", { cls: "tile card" }, h("span", { cls: "k" }, k),
      h("span", { cls: "big" }, a == null ? "—" : f(a), " ", h("small", {}, "/ " + (b == null ? "—" : f(b)))));
    const lg = (color, dash, text) => h("span", { cls: "lg" }, h("svg", { width: 22, height: 6, "aria-hidden": "true" }, h("line", { x1: 0, y1: 3, x2: 22, y2: 3, stroke: color, "stroke-width": 3, "stroke-dasharray": dash })), text);
    const hasData = full.some((v) => v != null) || del.some((v) => v != null);
    fill(latency, 
      h("div", { cls: "head" }, h("h2", { cls: "h2" }, "Затримка за 24 год ", h("span", { cls: "k" }, "· медіана за 10 хв")),
        h("div", { cls: "legend" }, lg("#1B1B19", null, "повний шлях: подія ukrainealarm → пристрій"), lg("#D9822B", "5 3", "ukrainealarm → alertd (webhook)"), lg("#2B6CB0", null, "alertd → пристрій (наша доставка)"))),
      h("div", { cls: "grid3" },
        stat("Повний шлях, медіана / p90", quant(full, 0.5), quant(fullP, 0.9), fmtSec),
        stat("Webhook, медіана / p90", quant(web, 0.5), quant(webP, 0.9), fmtSec),
        stat("Доставка, медіана / p90", quant(del, 0.5), quant(delP, 0.9), fmtMs)),
      hasData ? (() => {
        const b = (v) => buckets(xs, v, 10, median); // медіана за 10 хв — події бувають не щохвилини
        const W = b(web), F = b(full), Dl = b(del);
        return lineChart(W.bx, [
          { values: W.bv, color: "#D9822B", dash: "6 4", label: "webhook", fmt: fmtSec },
          { values: F.bv, color: "#1B1B19", label: "повний шлях", fmt: fmtSec },
          { values: Dl.bv, color: "#2B6CB0", label: "доставка", fmt: fmtMs },
        ], { height: 240, yfmt: (v) => (v === 0 ? "0" : fmtSec(v)), label: "Затримка доставки за 24 години, медіана за 10 хвилин" });
      })()
        : h("p", { cls: "k" }, "Ще немає подій за 24 год — графік з'явиться після першої зміни тривог."),
      h("span", { cls: "k" }, "Повний шлях і webhook рахуються лише для подій, що прийшли через webhook; доставка — для кожної події, надісланої в потік."));
    const S = buckets(xs, ms.map((x) => (x ? x.streams : null)), 10, maxOf);
    const req = hourly(xs, ms, [(x) => x.ok / 60, (x) => (x.unauth + x.forbid) / 60, (x) => x.limited / 60]);
    const sq = (c, t) => h("span", { cls: "lg" }, h("span", { cls: "sq", "data-c": c }), t);
    const legendReq = h("div", { cls: "legend" }, sq("#1B1B19", "успішні"), sq("#2B6CB0", "401/403"), sq("#D9822B", "429"));
    for (const s of legendReq.querySelectorAll(".sq")) s.style.background = s.dataset.c;
    fill(charts, 
      h("section", { cls: "card" }, h("h2", { cls: "h2" }, "Потоки за 24 год"),
        lineChart(S.bx, [{ values: S.bv, color: "#1B1B19", label: "відкрито (макс. за 10 хв)", fmt: (v) => num(v) }], { width: 480, height: 170, yfmt: (v) => fmtShort(v), label: "Кількість відкритих потоків за 24 години" })),
      h("section", { cls: "card" }, h("div", { cls: "head" }, h("h2", { cls: "h2" }, "Запити за 24 год ", h("span", { cls: "k" }, "· за хвилину, середнє по годинах")), legendReq),
        barChart(req, ["#1B1B19", "#2B6CB0", "#D9822B"], ["успішні", "401/403", "429"], { label: "Запити за хвилину по годинах", per: " · за хв" })));
  };
  drawMetrics(met);

  const drawJournal = (items) => {
    items = items || [];
    fill(jcard, h("h2", { cls: "h2" }, "Журнал подій"),
      items.length ? h("div", {}, items.map(evRow)) : h("p", { cls: "k" }, "Поки порожньо."),
      h("a", { href: "/journal", onclick: nav, cls: "k" }, "Увесь журнал →"));
  };
  drawJournal(jr);
  const drawBans = (list) => {
    list = list || [];
    fill(bcard, h("h2", { cls: "h2" }, "Заблоковані адреси"),
      list.length ? h("div", {}, list.map((b) => h("div", { cls: "kv" },
        h("div", {}, h("div", { cls: "mono" }, b.ip), h("div", { cls: "k" }, "ще " + dur((new Date(b.until) - Date.now()) / 1000) + " · невдалі спроби")),
        h("button", {
          type: "button", cls: "btn small", onclick: async () => {
            try { await api("POST", "/unban", { ip: b.ip }); drawBans(await api("GET", "/bans")); } catch (e) { alertBox(e); }
          },
        }, "Розблокувати")))) : h("p", { cls: "k" }, "Немає."));
  };
  drawBans(bans);

  // наживо: огляд щоразу, решта — раз на хвилину
  const es = new EventSource("/api/live");
  es.addEventListener("overview", (e) => { liveDot.className = "dot ok"; drawOverview(JSON.parse(e.data)); });
  es.addEventListener("logout", () => { es.close(); toLogin(); });
  es.onerror = () => { liveDot.className = "dot warn"; };
  const slow = setInterval(async () => {
    try {
      const [m, j, b] = await Promise.all([api("GET", "/metrics", null, true), api("GET", "/journal?limit=8", null, true), api("GET", "/bans", null, true)]);
      m.minutes = m.minutes || [];
      drawMetrics(m); drawJournal(j); drawBans(b);
    } catch (e) { /* наступного разу */ }
  }, 60000);
  cleanup.push(() => es.close(), () => clearInterval(slow));
}

const KIND = { login: ["вхід", ""], token: ["токен", ""], ban: ["блокування", "ban"], service: ["служба", "service"], data: ["дані", "data"], test: ["тест", "test"] };
function evRow(e) {
  const [label, cls] = KIND[e.kind] || [e.kind, ""];
  return h("div", { cls: "ev" }, h("span", { cls: "mono k", title: dt(e.t) }, Date.now() - new Date(e.t) > 86400000 ? day(e.t).slice(5) + " " + hm(e.t) : hm(e.t)),
    h("span", { cls: "tag " + cls }, label),
    h("span", {}, e.text, e.ip ? [" · ", h("span", { cls: "mono k" }, e.ip)] : null));
}

async function pageJournal() {
  const kind = new URLSearchParams(location.search).get("kind") || "";
  const items = await api("GET", "/journal?limit=500&kind=" + encodeURIComponent(kind));
  const f = (k, label) => h("a", { href: "/journal" + (k ? "?kind=" + k : ""), onclick: nav, cls: "btn small" + (kind === k ? " on" : "") }, label);
  shell("log", h("div", { cls: "head" }, h("h1", {}, "Журнал")),
    h("div", { cls: "filters" }, f("", "Усі"), Object.entries(KIND).map(([k, [l]]) => f(k, l))),
    h("section", { cls: "card" }, items.length ? h("div", {}, items.map(evRow)) : h("p", { cls: "k" }, "Записів немає."),
      h("span", { cls: "k" }, "Зберігається 30 днів; тут — останні 500.")));
}

// ---------- токени ----------

async function pageTokens() {
  const list = await api("GET", "/tokens");
  const params = new URLSearchParams(location.search);
  let filter = params.get("f") || "all";
  const q = h("input", { id: "q", type: "search", cls: "in", placeholder: "Пошук: назва, регіон, ID, адреса" });
  const idle = (t) => !t.lastSeen || Date.now() - new Date(t.lastSeen) > 7 * 86400000;
  const F = {
    all: ["Усі", () => true],
    active: ["Активні", (t) => t.status === "active"],
    expired: ["Прострочені", (t) => t.status === "expired"],
    idle: ["Не використовувались 7+ днів", (t) => t.status === "active" && idle(t)],
  };
  const fbar = h("div", { cls: "filters" });
  const body = h("tbody");
  const open = list.reduce((a, t) => a + t.open, 0);
  const draw = () => {
    fill(fbar, ...Object.entries(F).map(([k, [l, fn]]) => h("button", {
      type: "button", cls: "btn small" + (filter === k ? " on" : ""), onclick: () => { filter = k; draw(); },
    }, l + " · " + list.filter(fn).length)));
    const s = q.value.trim().toLowerCase();
    const rows = list.filter(F[filter][1]).filter((t) => !s || [t.name, t.id, t.lastIp, ...(t.nets || []), ...(t.regions || []).map(regionName), ...(t.regions || [])]
      .some((x) => x && String(x).toLowerCase().includes(s)));
    fill(body, ...rows.map((t) => h("tr", { cls: "link", onclick: () => go("/tokens/" + t.id) },
      h("td", {}, h("a", { href: "/tokens/" + t.id, onclick: nav }, t.name || "без назви"), h("span", { cls: "sub mono" }, t.id)),
      h("td", {}, regionsText(t.regions)),
      h("td", { cls: "mono nw" }, t.rpm + "/хв · " + t.streams),
      h("td", { cls: "nw" }, t.status === "expired" ? h("span", { cls: "tag exp" }, "прострочено " + day(t.expires)) : zeroTime(t.expires) ? "безстроково" : day(t.expires)),
      h("td", {}, t.nets && t.nets.length ? h("span", { cls: "mono" }, t.nets.join(", ")) : "будь-які"),
      h("td", { cls: "nw" }, t.open ? [h("span", { cls: "mono" }, t.open), " відкрито"] : "—"),
      h("td", { cls: "mono" }, num(t.day.req), h("span", { cls: "sub" }, "відмов " + num(t.day.unauth + t.day.forbid + t.day.limited))),
      h("td", {}, ago(t.lastSeen), t.lastIp && h("span", { cls: "sub mono" }, t.lastIp)))));
    if (!rows.length) fill(body, h("tr", {}, h("td", { colspan: 8, cls: "k" }, list.length ? "Нічого не знайдено." : "Токенів ще немає.")));
  };
  q.addEventListener("input", draw);
  shell("tok",
    h("div", { cls: "head" }, h("div", {}, h("h1", {}, "Токени"), h("span", { cls: "k" }, num(list.length) + " токенів · відкрито потоків: " + num(open))),
      h("a", { href: "/tokens/new", onclick: nav, cls: "btn dark" }, "+ Новий токен")),
    h("label", { cls: "f" }, h("span", { cls: "hidden" }, "Пошук"), q), fbar,
    h("section", { cls: "card scroll" }, h("table", { cls: "tbl" },
      h("thead", {}, h("tr", {}, ["Токен", "Регіони", "Ліміти", "Діє до", "Адреси", "Потоки", "За 24 год", "Востаннє"].map((x) => h("th", {}, x)))), body)));
  draw();
}

function regionPicker(selected) {
  const sel = new Set(selected || []);
  const chips = h("div", { cls: "chips" });
  const search = h("input", { type: "search", cls: "in", placeholder: "Пошук регіону за назвою або ID" });
  const listEl = h("div", { cls: "rlist" });
  const byId = new Map(REGIONS.map((r) => [r.regionId, r]));
  const covered = (r) => { // уже входить у вибраний предок
    for (let p = r.parentId, i = 0; p && i < 8; i++) {
      if (sel.has(p)) return true;
      const pr = byId.get(p);
      p = pr && pr.parentId;
    }
    return false;
  };
  const draw = () => {
    fill(chips, ...[...sel].map((id) => h("span", { cls: "chipx" }, regionName(id),
      h("button", { type: "button", "aria-label": "Прибрати " + regionName(id), onclick: () => { sel.delete(id); draw(); } }, "×"))));
    if (!sel.size) chips.append(h("span", { cls: "k" }, "Нічого не вибрано — усі регіони (крім тестової області)."));
    const s = search.value.trim().toLowerCase();
    let rows = REGIONS;
    if (s) {
      const hit = new Set(REGIONS.filter((r) => r.regionName.toLowerCase().includes(s) || r.regionId === s).map((r) => r.regionId));
      const keep = new Set(hit);
      for (const id of hit) { // разом з предками, щоб було видно, де це
        for (let r = byId.get(id), i = 0; r && r.parentId && i < 8; i++) { keep.add(r.parentId); r = byId.get(r.parentId); }
      }
      rows = REGIONS.filter((r) => keep.has(r.regionId));
    } else rows = REGIONS.filter((r) => r.depth <= 1);
    const shown = rows.slice(0, 300);
    fill(listEl, ...shown.map((r) => {
      const cb = h("input", { type: "checkbox", checked: sel.has(r.regionId), disabled: covered(r) });
      cb.addEventListener("change", () => { cb.checked ? sel.add(r.regionId) : sel.delete(r.regionId); draw(); });
      return h("label", { cls: "d" + Math.min(r.depth, 2) }, cb, r.regionName, h("span", { cls: "k mono" }, " " + r.regionId), covered(r) && h("span", { cls: "k" }, " · входить у вибраний"));
    }), rows.length > shown.length ? h("p", { cls: "k" }, "…ще " + (rows.length - shown.length) + " — уточніть пошук") : null);
  };
  search.addEventListener("input", draw);
  draw();
  return {
    el: h("div", { cls: "card" }, h("h2", { cls: "h2" }, "Регіони"),
      h("span", { cls: "hint" }, "Дозвіл на область відкриває всі її райони й громади. Без пошуку видно області й райони; громади — через пошук."),
      chips, h("label", { cls: "f" }, h("span", { cls: "hidden" }, "Пошук регіону"), search), listEl),
    value: () => [...sel],
  };
}

function pageTokenForm(tok) {
  const edit = !!tok;
  const name = h("input", { cls: "in", value: tok ? tok.name : "", maxlength: 64, required: true });
  const rp = regionPicker(tok ? tok.regions : []);
  const rpm = h("input", { cls: "in mono", type: "number", min: 1, max: 6000, value: tok ? tok.rpm : 30 });
  const st = h("input", { cls: "in mono", type: "number", min: 0, max: 100, value: tok ? tok.streams : 1 });
  let exp = tok ? (zeroTime(tok.expires) ? "" : "keep") : "";
  const date = h("input", { cls: "in hidden", type: "date", min: day(Date.now() + 86400000) });
  const expBtns = h("div", { cls: "btns" });
  const drawExp = () => {
    const b = (k, l) => h("button", { type: "button", cls: "btn small" + (exp === k ? " on" : ""), onclick: () => { exp = k; drawExp(); } }, l);
    fill(expBtns, b("", "Безстроково"), tok && exp === "keep" ? b("keep", "до " + day(tok.expires)) : null, b("7d", "7 днів"), b("30d", "30 днів"), b("date", "До дати…"));
    date.classList.toggle("hidden", exp !== "date");
  };
  drawExp();
  const nets = h("textarea", { cls: "in mono", rows: 2, placeholder: "порожньо — будь-які; напр. 10.77.0.12, 176.122.0.0/16" });
  nets.value = tok && tok.nets ? tok.nets.join(", ") : "";
  const aq = h("input", { type: "checkbox", checked: tok ? tok.allowQuery : false });
  const msg = h("div", { role: "alert" });
  const submit = h("button", { type: "submit", cls: "btn dark" }, edit ? "Зберегти" : "Створити токен");
  const result = h("div");
  const form = h("form", {
    cls: "row",
    onsubmit: async (ev) => {
      ev.preventDefault();
      fill(msg);
      const spec = {
        name: name.value.trim(), rpm: Number(rpm.value), streams: Number(st.value), regions: rp.value(),
        nets: nets.value.split(/[\s,]+/).filter(Boolean), allowQuery: aq.checked,
      };
      if (exp === "date") {
        if (!date.value) { fill(msg, h("div", { cls: "err" }, "Вкажіть дату.")); return; }
        // до кінця дня за київським часом
        spec.expires = date.value + "T23:59:59" + kyivOffset(date.value);
      } else if (exp !== "keep") spec.expires = exp;
      submit.disabled = true;
      try {
        if (edit) {
          await api("PATCH", "/tokens/" + tok.id, spec);
          go("/tokens/" + tok.id);
        } else {
          const r = await api("POST", "/tokens", spec);
          form.remove();
          fill(result, secretCard(r.token, r.secret, r.qr, "створено щойно"));
        }
      } catch (e) {
        fill(msg, h("div", { cls: "err" }, e.message));
      } finally { submit.disabled = false; }
    },
  },
    h("div", { cls: "col" },
      h("section", { cls: "card" }, h("label", { cls: "f" }, "Назва", name, h("span", { cls: "hint" }, "Для себе: хто чи що користуватиметься токеном."))),
      rp.el),
    h("div", { cls: "col" },
      h("section", { cls: "card" }, h("h2", { cls: "h2" }, "Ліміти"),
        h("div", { cls: "grid2" }, h("label", { cls: "f" }, "Запитів на хвилину", rpm), h("label", { cls: "f" }, "Одночасних потоків", st)),
        h("span", { cls: "hint" }, "Пристрою (ESP8266, ESP32) і телефону вистачає одного потоку; 0 — лише запити стану.")),
      h("section", { cls: "card" }, h("h2", { cls: "h2" }, "Термін дії"), expBtns, date,
        edit && h("span", { cls: "hint" }, "Зміна налаштувань закриває відкриті потоки — пристрій перепідключиться.")),
      h("section", { cls: "card" }, h("label", { cls: "f" }, "Дозволені адреси", nets),
        h("label", { cls: "chk" }, aq, h("span", {}, "Дозволити токен у адресі (?token=…)", h("span", { cls: "hint", }, " Лише для прошивок, що не вміють заголовків. Адреси потрапляють у журнали; на VPN-вході не діє.")))),
      msg,
      h("div", { cls: "btns" }, submit, h("a", { href: edit ? "/tokens/" + tok.id : "/tokens", onclick: nav, cls: "btn" }, "Скасувати"))));
  shell("tok", h("a", { href: edit ? "/tokens/" + tok.id : "/tokens", onclick: nav, cls: "back" }, "← " + (edit ? tok.name : "Токени")),
    h("h1", {}, edit ? "Редагувати токен" : "Новий токен"), form, result);
  name.focus();
}

function kyivOffset(dateStr) {
  // зсув Києва на цю дату (+02:00 / +03:00)
  const d = new Date(dateStr + "T12:00:00Z");
  const p = new Intl.DateTimeFormat("en-US", { ...tz, timeZoneName: "longOffset" }).formatToParts(d).find((x) => x.type === "timeZoneName");
  const m = p && p.value.match(/GMT([+-]\d\d:\d\d)/);
  return m ? m[1] : "+02:00";
}

function secretCard(tok, secret, qr, when) {
  const code = h("code", { cls: "mono" }, "ac_" + "•".repeat(43));
  let shown = false;
  const base = ME.publicURL || "https://ваш-сайт";
  return h("section", { cls: "card" },
    h("div", {}, h("h2", { cls: "h2" }, tok.name), h("span", { cls: "k" }, "ID ", h("span", { cls: "mono" }, tok.id), " · " + when)),
    h("div", { cls: "okmsg" }, "Токен показується лише зараз. Збережіть його — потім лишиться тільки rotate (новий секрет)."),
    h("div", { cls: "secret" }, code,
      h("button", { type: "button", cls: "btn small", onclick: (e) => { navigator.clipboard.writeText(secret).then(() => (e.target.textContent = "Скопійовано"), () => alertBox("Не вдалося скопіювати")); } }, "Копіювати"),
      h("button", { type: "button", cls: "btn small", onclick: (e) => { shown = !shown; code.textContent = shown ? secret : "ac_" + "•".repeat(43); e.target.textContent = shown ? "Сховати" : "Показати"; } }, "Показати")),
    qr && h("div", { cls: "row" }, h("div", { cls: "qr", html: qr }),
      h("div", { cls: "col" }, h("h2", { cls: "h2" }, "QR-код токена"), h("span", { cls: "k" }, ME.publicURL ? "Містить JSON з адресою сервера й токеном: {\"url\":…, \"token\":…}." : "Містить лише токен (PUBLIC_URL не задано)."))),
    h("div", { cls: "col" }, h("span", { cls: "k" }, "Перевірка"), h("pre", { cls: "code" }, `curl -H "Authorization: Bearer ${secret.slice(0, 6)}…" ${base}/api/v1/me`)),
    h("div", { cls: "btns" }, h("a", { href: "/tokens/" + tok.id, onclick: nav, cls: "btn dark" }, "До токена"), h("a", { href: "/tokens", onclick: nav, cls: "btn" }, "Усі токени")));
}

async function pageToken(id) {
  if (location.search === "?edit") { const d = await api("GET", "/tokens/" + id); return pageTokenForm(d.token); }
  const d = await api("GET", "/tokens/" + id);
  const t = d.token;
  const hist = d.history || [];
  const peak = hist.reduce((m, x) => Math.max(m, x.req + x.limited), 0);
  const deny = t.day.unauth + t.day.forbid + t.day.limited;
  const nowS = Math.floor(Date.now() / 1000);
  const { xs, ms } = minuteSlots(hist, nowS);
  const groups = hourly(xs, ms, [(x) => x.req, (x) => x.unauth + x.forbid + x.limited]);
  const stat = (k, v, sub) => h("div", { cls: "card tile" }, h("span", { cls: "k" }, k), h("span", { cls: "big" }, v), sub && h("span", { cls: "k mono" }, sub));
  const kv = (k, v) => h("div", { cls: "kv" }, h("span", {}, k), h("span", {}, v));
  const top = h("div", {});
  const actions = h("div", { cls: "btns" },
    h("a", { href: "/tokens/" + id + "?edit", onclick: nav, cls: "btn" }, "Редагувати"),
    confirmBtn("Rotate — новий секрет", "Старий перестане діяти. Точно?", "", async () => {
      const r = await api("POST", "/tokens/" + id + "/rotate");
      fill(top, secretCard(r.token, r.secret, r.qr, "новий секрет щойно"));
    }),
    confirmBtn("Відкликати", "Назавжди. Точно?", "danger", async () => { await api("DELETE", "/tokens/" + id); go("/tokens"); }));
  shell("tok",
    h("a", { href: "/tokens", onclick: nav, cls: "back" }, "← Токени"),
    h("div", { cls: "head" },
      h("div", { cls: "col" }, h("div", { cls: "btns" }, h("h1", {}, t.name || "без назви"),
        h("span", { cls: "tag " + (t.status === "active" ? "ok" : "exp") }, t.status === "active" ? "активний" : "прострочено"),
        t.open ? h("span", { cls: "k" }, t.open + " потік(и) відкрито") : null),
        h("span", { cls: "k" }, "ID ", h("span", { cls: "mono" }, t.id), " · створено " + dt(t.created))),
      actions),
    top,
    h("section", { cls: "grid4" },
      stat("Запитів за 24 год", num(t.day.req)),
      stat("Відмов за 24 год", num(deny)),
      stat("Востаннє", ago(t.lastSeen), t.lastIp || ""),
      stat("Ліміт використано (пік)", h("span", {}, num(peak), " ", h("small", {}, "/ " + t.rpm + " за хв")))),
    h("section", { cls: "card" },
      h("div", { cls: "head" }, h("h2", { cls: "h2" }, "Запити за 24 години"), h("div", { cls: "legend" }, h("span", { cls: "lg" }, "чорне — успішні, помаранчеве — відмови й 429"))),
      hist.length ? barChart(groups, ["#1B1B19", "#D9822B"], ["успішні", "відмови"], { width: 960, height: 200, label: "Запити токена по годинах" })
        : h("p", { cls: "k" }, "За 24 год запитів не було.")),
    h("div", { cls: "row" },
      h("section", { cls: "card" }, h("h2", { cls: "h2" }, "Налаштування"), h("div", {},
        kv("Регіони", t.regions && t.regions.length ? t.regions.map(regionName).join(", ") : "усі (крім тестової області)"),
        kv("Діє до", zeroTime(t.expires) ? "безстроково" : dt(t.expires)),
        kv("Ліміти", t.rpm + "/хв · " + t.streams + " пот."),
        kv("Адреси", t.nets && t.nets.length ? t.nets.join(", ") : "будь-які"),
        kv("Токен у адресі", t.allowQuery ? "дозволено" : "заборонено"),
        kv("Сесії браузера", num(d.sessions)),
        kv("Усього запитів / відмов", num(t.requests) + " / " + num(t.denied)))),
      h("section", { cls: "card" }, h("h2", { cls: "h2" }, "Відмови за 24 год"), h("div", {},
        kv("Ліміт запитів або потоків (429)", num(t.day.limited)),
        kv("Регіон поза дозволеними (403)", num(t.day.forbid)),
        kv("Недозволена адреса / прострочено (401)", num(t.day.unauth))),
        h("span", { cls: "k" }, "Причини відмов видно лише тут: ззовні всім відповідає однакова 401."))),
    h("section", { cls: "card scroll" }, h("h2", { cls: "h2" }, "Відкриті потоки"),
      d.streams.length ? [h("table", { cls: "tbl" },
        h("thead", {}, h("tr", {}, ["Адреса", "Вхід", "Регіони", "Відкрито", "Подій надіслано"].map((x) => h("th", {}, x)))),
        h("tbody", {}, d.streams.map((s) => h("tr", {},
          h("td", { cls: "mono" }, s.ip), h("td", {}, s.listener === "vpn" ? "VPN" : "публічний"),
          h("td", { cls: "mono" }, s.regions.join(", ")),
          h("td", {}, hms(s.opened), h("span", { cls: "sub" }, dur((Date.now() - new Date(s.opened)) / 1000))),
          h("td", { cls: "mono" }, num(s.sent)))))),
      h("div", { cls: "btns" }, confirmBtn("Закрити потоки (пристрій перепідключиться)", "Закрити всі потоки токена?", "", async () => {
        await api("POST", "/tokens/" + id + "/kick"); route();
      }))] : h("p", { cls: "k" }, "Немає відкритих потоків.")));
}

// ---------- тестова область ----------

const LEVELS = [["none", "Спокій"], ["yellow", "БпЛА"], ["red", "Ракети"], ["unknown", "Не вказано"]];
const TYPES = { AIR: "Повітряна (AIR)", ARTILLERY: "Артобстріл", URBAN_FIGHTS: "Вуличні бої", CHEMICAL: "Хімічна", NUCLEAR: "Ядерна" };
const LEVEL_TEXT = { red: "Ракети", yellow: "БпЛА", unknown: "Не вказано" };

async function pageTest() {
  let data = await api("GET", "/test");
  let type = "AIR";
  try { type = sessionStorage.getItem("testType") || "AIR"; } catch (e) { /* без збереження */ }
  const typeSel = h("select", { cls: "in" }, (data.types || Object.keys(TYPES)).map((k) => h("option", { value: k, selected: k === type }, TYPES[k] || k)));
  typeSel.addEventListener("change", () => { type = typeSel.value; try { sessionStorage.setItem("testType", type); } catch (e) { /* без збереження */ } draw(); });
  const regionsCard = h("section", { cls: "card" });
  const side = h("div", { cls: "col" });
  const reset = h("span", { cls: "k" });
  const clearBtn = confirmBtn("Зняти все", "Зняти всі тестові тривоги?", "", async () => { data = await api("DELETE", "/test"); draw(); });
  const depth = { "990000": 0, "990100": 1, "990200": 1, "990101": 2, "990102": 2 };
  const set = async (region, level, btn) => {
    btn.disabled = true;
    try { data = await api("POST", "/test", { region, type, level }); draw(); } catch (e) { alertBox(e); btn.disabled = false; }
  };
  const draw = () => {
    if (!data.enabled) {
      fill(regionsCard, h("div", { cls: "err" }, "Тестова область вимкнена: справжнє дерево регіонів зайняло зарезервовані ID 99xxxx."));
      return;
    }
    reset.textContent = data.resetAt ? "автоскидання через " + dur(data.resetAt - Date.now() / 1000) : "тривог немає";
    const own = (id) => (data.alerts || []).find((a) => a.region === id && a.type === type);
    fill(regionsCard, h("div", { cls: "head" }, h("h2", { cls: "h2" }, "Регіони"), h("label", { cls: "f" }, "Тип тривоги", typeSel)),
      h("div", {}, data.regions.map((r) => {
        const a = own(r.id);
        const ts = r.types && r.types[type];
        let state;
        if (a) state = LEVEL_TEXT[a.level] + " з " + hm(a.since) + " · змінено " + ago(a.changed);
        else if (ts && ts.state === "active") state = "діє тривога " + (ts.from || []).filter((x) => x !== r.id).map(regionName).join(", ");
        else if (ts && ts.state === "partial") state = "частково · " + (ts.partial || []).length + " вкладених";
        else state = "спокій";
        const cur = a ? a.level : "none";
        return h("div", { cls: "treg d" + (depth[r.id] || 0) },
          h("div", { cls: "nm" }, h("span", {}, r.name, " ", h("span", { cls: "k mono" }, r.id)), h("span", { cls: "k" }, state)),
          h("div", { cls: "btns" }, LEVELS.map(([lv, label]) => {
            const b = h("button", { type: "button", cls: "btn small lvl " + lv + (cur === lv ? " on" : ""), "aria-pressed": cur === lv ? "true" : "false" }, label);
            b.addEventListener("click", () => set(r.id, lv, b));
            return b;
          })));
      })));
    fill(side, 
      h("section", { cls: "card" }, h("h2", { cls: "h2" }, "Хто дивиться"),
        data.viewers.length ? h("div", {}, data.viewers.map((v) => h("div", { cls: "kv" }, h("a", { href: "/tokens/" + v.id, onclick: nav }, v.name), h("span", { cls: "k" }, v.open ? v.open + " потік" : "не підписаний")))) : h("p", { cls: "k" }, "Жоден токен не має доступу."),
        h("span", { cls: "k" }, "Додати токену тестову область — у його налаштуваннях регіонів (пошук «тест»).")),
      h("section", { cls: "card" }, h("h2", { cls: "h2" }, "Що побачать пристрої"),
        h("pre", { cls: "code" }, 'event: update\ndata: {"version":…,"region":{"id":"990101",\n "name":"Тестова громада 1.1","test":true,\n "state":"active","level":"red","types":{"AIR":{…}}}}')));
  };
  shell("test",
    h("div", { cls: "head" }, h("div", { cls: "col" }, h("h1", {}, "Тестова область"), h("span", { cls: "k" }, "Вигадані регіони для перевірки пристроїв, ботів і сторінок")),
      h("div", { cls: "btns" }, reset, clearBtn)),
    h("div", { cls: "okmsg" }, "Бачать лише токени, яким тестову область дозволено явно. Кожна відповідь має \"test\": true. У сумісному v3, на публічній головній і в alertd її немає. Тривоги знімаються самі через 1 год без змін."),
    h("div", { cls: "row" }, regionsCard, side));
  draw();
  const t = setInterval(async () => { try { data = await api("GET", "/test", null, true); draw(); } catch (e) { /* далі */ } }, 15000);
  cleanup.push(() => clearInterval(t));
}

route();
