// Документація API: розгортання операцій, «Виконати» з токеном, приклади. Токен — лише в
// пам'яті вкладки; дані відповіді показуються як текст (без HTML).
"use strict";
(() => {
  const d = document;
  d.documentElement.classList.add("js");
  const $ = (s, el = d) => el.querySelector(s);
  const $$ = (s, el = d) => [...el.querySelectorAll(s)];
  const base = location.origin;
  for (const el of $$(".base, .base-t")) el.textContent = base;

  // ---------- токен ----------
  let token = "";
  const tokRe = /^ac_[A-Za-z0-9_-]{43}$/;
  const state = $("#authstate");
  const setState = () => {
    state.textContent = token ? "Токен застосовано: " + token.slice(0, 6) + "…" + token.slice(-4) + ". Запити йдуть від вашого імені й рахуються в його ліміт." : "Токен не задано.";
    state.classList.toggle("ok", !!token);
  };
  $("#authform").addEventListener("submit", (e) => {
    e.preventDefault();
    const v = $("#tok").value.trim();
    if (!tokRe.test(v)) { state.textContent = "Це не схоже на токен: ac_ і 43 символи."; state.classList.remove("ok"); return; }
    token = v; $("#tok").value = ""; setState();
  });
  $("#tokclear").addEventListener("click", () => { token = ""; $("#tok").value = ""; setState(); });

  // ---------- операції ----------
  const open = (op, on) => op.classList.toggle("open", on ?? !op.classList.contains("open"));
  for (const op of $$(".op")) {
    $(".op-h", op).addEventListener("click", () => {
      open(op);
      if (op.classList.contains("open")) history.replaceState(null, "", "#" + op.id);
    });
    $(".op-h", op).setAttribute("tabindex", "0");
    $(".op-h", op).setAttribute("role", "button");
    $(".op-h", op).addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(op); } });
  }
  const openHash = () => {
    const el = location.hash && d.getElementById(decodeURIComponent(location.hash.slice(1)));
    if (el && el.classList.contains("op")) open(el, true);
  };
  window.addEventListener("hashchange", openHash);
  openHash();
  if (!location.hash) { const s = $("#op-status"), st = $("#op-stream"); open(s, true); open(st, true); }

  // підсвітка поточного розділу в змісті
  const links = new Map($$(".toc a").map((a) => [a.getAttribute("href").slice(1), a]));
  const io = new IntersectionObserver((ents) => {
    for (const e of ents) if (e.isIntersecting && links.has(e.target.id)) {
      for (const a of links.values()) a.classList.remove("on");
      links.get(e.target.id).classList.add("on");
    }
  }, { rootMargin: "-80px 0px -70% 0px" });
  for (const id of links.keys()) { const el = d.getElementById(id); if (el) io.observe(el); }

  // ---------- вкладки прикладів ----------
  for (const b of $$(".tabs button")) {
    b.addEventListener("click", () => {
      for (const x of $$(".tabs button")) x.setAttribute("aria-selected", String(x === b));
      for (const p of $$("pre.tab")) p.hidden = p.dataset.tab !== b.dataset.tab;
    });
  }

  // ---------- консоль ----------
  const con = $("#console"), body = $("#con-body"), meta = $("#con-meta");
  let abort = null, lastCurl = "";
  const stopStream = () => { if (abort) { abort.abort(); abort = null; } for (const b of $$(".try .stop")) b.hidden = true; };
  $("#con-close").addEventListener("click", () => { stopStream(); con.hidden = true; });
  $("#con-copy").addEventListener("click", (e) => {
    navigator.clipboard.writeText(lastCurl).then(() => { e.target.textContent = "Скопійовано"; setTimeout(() => (e.target.textContent = "Копіювати curl"), 1500); }, () => {});
  });
  const show = (title, url, stream) => {
    con.hidden = false;
    $("#con-title").textContent = title;
    $("#con-url").textContent = "GET " + url;
    lastCurl = `curl ${stream ? "-N " : ""}-H "Authorization: Bearer $TOKEN" "${base}${url}"`;
    meta.textContent = "";
    body.textContent = stream ? "Підключення…" : "Запит…";
  };
  const status = (code, text, extra) => {
    meta.replaceChildren();
    const st = d.createElement("span");
    st.className = "st " + (code >= 200 && code < 300 || code === 304 ? "ok" : "err");
    st.textContent = code + " " + text;
    meta.append(st, extra ? "  ·  " + extra : "");
  };
  const pretty = (txt) => { try { return JSON.stringify(JSON.parse(txt), null, 2); } catch (e) { return txt; } };

  for (const f of $$("form.try")) {
    const stopBtn = $(".stop", f);
    if (stopBtn) stopBtn.addEventListener("click", stopStream);
    f.addEventListener("submit", async (e) => {
      e.preventDefault();
      stopStream();
      let path = f.dataset.path;
      const q = new URLSearchParams();
      for (const inp of $$("input", f)) {
        const v = inp.value.trim().replace(/\s+/g, "");
        if (path.includes("{" + inp.name + "}")) {
          if (!/^\d+$/.test(v)) { inp.focus(); return; }
          path = path.replace("{" + inp.name + "}", v);
        } else if (v) q.set(inp.name, v);
      }
      const url = path + (q.size ? "?" + q.toString().replace(/%2C/g, ",") : "");
      const stream = !!f.dataset.stream;
      const title = $(".path", f.closest(".op")).textContent;
      show(title, url, stream);
      if (!token) { status(0, "немає токена", "задайте його вище, у розділі «Токен»"); body.textContent = "Без токена сервер відповість 401."; }
      const ctl = new AbortController();
      if (stream) { abort = ctl; if (stopBtn) stopBtn.hidden = false; }
      const t0 = performance.now();
      try {
        const r = await fetch(url, { headers: token ? { Authorization: "Bearer " + token } : {}, cache: "no-store", signal: ctl.signal, credentials: "omit" });
        const ms = Math.round(performance.now() - t0);
        const hdr = ["Content-Type", "Retry-After", "X-Data-Stale", "ETag"].map((h) => r.headers.get(h) && h + ": " + r.headers.get(h)).filter(Boolean).join("  ·  ");
        status(r.status, r.statusText, ms + " мс" + (hdr ? "  ·  " + hdr : ""));
        if (!stream || !r.ok || !r.body) { body.textContent = pretty(await r.text()); stopStream(); return; }
        // потік: показуємо події, як вони приходять (не більше 200 останніх рядків)
        body.textContent = "";
        const reader = r.body.pipeThrough(new TextDecoderStream()).getReader();
        let buf = "", lines = [];
        for (;;) {
          const { value, done } = await reader.read();
          if (done) { lines.push("— з'єднання закрито —"); body.textContent = lines.join("\n"); break; }
          buf += value;
          let i;
          while ((i = buf.indexOf("\n\n")) >= 0) {
            const block = buf.slice(0, i); buf = buf.slice(i + 2);
            const time = new Date().toLocaleTimeString("uk-UA");
            const ev = /^event: (.*)$/m.exec(block), data = /^data: (.*)$/m.exec(block);
            if (ev) lines.push(`[${time}] ${ev[1]}\n${data ? pretty(data[1]) : ""}`);
            else if (block.startsWith(": ping")) lines.push(`[${time}] : ping`);
            else if (block.startsWith("retry:")) lines.push(block);
          }
          if (lines.length > 200) lines = lines.slice(-200);
          body.textContent = lines.join("\n\n");
          body.scrollTop = body.scrollHeight;
        }
      } catch (err) {
        if (err.name !== "AbortError") { status(0, "помилка мережі", String(err.message || err)); body.textContent = ""; }
        else meta.append("  ·  зупинено");
      } finally {
        if (abort === ctl) { abort = null; if (stopBtn) stopBtn.hidden = true; }
      }
    });
  }
  setState();
})();
