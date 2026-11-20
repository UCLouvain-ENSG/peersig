// PeerSig window. All data is inserted with textContent, never as HTML:
// application names come from executables on this computer. The Android
// app shows it too, in a WebView (android/app/src/main/ui/android.js
// stands in for Tauri): `state.os` is then "android".
"use strict";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

let state = null;
let tab = "overview";
let itemsCurrent = false;
let items = null;
let autostartOn = null;

// ------------------------------------------------------------ helpers

function el(tag, attrs, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (v === true) e.setAttribute(k, "");
    else e.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return e;
}

const day = (t) => new Date(t * 1000).toLocaleDateString(undefined, { weekday: "short", day: "numeric", month: "short" });
const when = (t) => new Date(t * 1000).toLocaleString(undefined, { weekday: "short", day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
const iso = (s) => (s ? new Date(s).toLocaleString() : "never");
const weekRange = (from, to) => `${day(from)} – ${day(to - 1)}`;
// An observer reports days (UTC), a participant weeks.
const unit = () => (state.observer ? "day" : "week");
const utcDay = (t) => new Date(t * 1000).toLocaleDateString(undefined, { weekday: "short", day: "numeric", month: "short", timeZone: "UTC" });
const period = (from, to) => (state.observer ? `Day of ${utcDay(from)} (UTC)` : `Week of ${weekRange(from, to)}`);
// A dedicated observer's code: OBS-XXXX-XXXX-XXXX (crates/proto/src/code.rs).
function isObserverCode(s) {
  const n = s.toUpperCase().replace(/[^A-Z0-9]/g, "").replace(/O/g, "0").replace(/[IL]/g, "1");
  return n.length === 15 && n.startsWith("0BS");
}
// The Android app: a phone, its own VPN for a capture, packages for apps.
const android = () => !!state && state.os === "android";
const device = () => (android() ? "phone" : "computer");
// What an item names of an application (Android has no signing team or engine).
const appFields = () => (android() ? "name, package name, version, kind" : "name, bundle id, version, signing team, kind, engine");
function hours(sec) {
  if (sec <= 0) return "now";
  const h = Math.floor(sec / 3600), m = Math.round((sec % 3600) / 60);
  return h > 0 ? `${h} h ${m} min` : `${m} min`;
}

async function call(cmd, args) {
  try {
    return await invoke(cmd, args || {});
  } catch (e) {
    alert(String(e));
    throw e;
  }
}

async function refresh() {
  state = await invoke("get_state");
  render();
}

function setTab(t) {
  tab = t;
  if (t === "items") loadItems();
  render();
}

async function loadItems() {
  items = await invoke("get_items", { current: itemsCurrent });
  render();
}

// ------------------------------------------------------------ header

function renderPill() {
  const p = document.getElementById("pill");
  let text = "…", cls = "pill";
  if (!state.enrolled) [text, cls] = ["Not enrolled", "pill warn"];
  else if (state.paused) [text, cls] = ["Capture paused", "pill warn"];
  else if (!state.probe.running) [text, cls] = ["Capture not running", "pill bad"];
  else if (state.reports.some((r) => r.state === "sending")) [text, cls] = ["Sending report…", "pill ok"];
  else [text, cls] = ["Capturing", "pill ok"];
  p.textContent = text;
  p.className = cls;
  for (const b of document.querySelectorAll("#tabs button")) {
    b.setAttribute("aria-selected", String(b.dataset.tab === tab));
    b.disabled = !state.enrolled && b.dataset.tab !== "privacy";
  }
}

// ------------------------------------------------------------ enroll

function renderEnroll() {
  const server = el("input", { type: "url", placeholder: "https://peersig.example.org", value: state.settings.server || "" });
  const relay = el("input", { type: "url", placeholder: "https://relay.example.net", value: state.settings.relay || "" });
  const code = el("input", { type: "text", placeholder: "XXXX-XXXX-XXXX", autocomplete: "off" });
  const observerNote = el("div", { class: "notice", hidden: true },
    el("strong", {}, "Dedicated observer code. "),
    `This ${device()} will report every day, in one report the server knows comes from this observer, and each day's items are published as they are, without waiting for other participants. Use it only on a machine set up for the study, whose traffic may be published.`);
  code.addEventListener("input", () => (observerNote.hidden = !isObserverCode(code.value)));
  const getCode = el("button", { class: "btn", type: "button" }, "Get a code…");
  getCode.addEventListener("click", () => call("open_url", { url: server.value.trim() }));
  const domains = el("input", { type: "checkbox" });
  const agree = el("input", { type: "checkbox" });
  const go = el("button", { class: "btn primary", disabled: true }, "Join the study");
  agree.addEventListener("change", () => (go.disabled = !agree.checked));
  go.addEventListener("click", async () => {
    go.disabled = true;
    go.textContent = "Checking the server…";
    try {
      await call("enroll", { server: server.value, relay: relay.value, code: code.value, shareDomains: domains.checked });
      try { autostartOn = await invoke("autostart", { enabled: true }); } catch (_) {}
      await refresh();
    } finally {
      go.disabled = false;
      go.textContent = "Join the study";
    }
  });
  return el("div", { class: "card" },
    el("h2", {}, "Join the study"),
    el("p", {}, `PeerSig watches the start of the encrypted connections this ${device()} makes (the TLS “ClientHello”), notes which application made each one, and once a week contributes that list to a research study.`),
    android() ? el("p", {}, "On a phone, PeerSig sees other apps' connections through a VPN of its own. That VPN stays on the phone: it forwards every connection, unchanged, to where it was going, and only looks at the start of encrypted connections. No VPN server is involved, and PeerSig's own traffic does not go through it.") : null,
    el("p", {}, `What it sends: the applications (${android() ? appFields() : "name, bundle id, version, signing team, kind, browser engine"}), the fingerprint (JA4) of their handshakes, and the system with its major version (${android() ? "Android 15" : "macOS 27, Ubuntu 24"}); if you choose, the server names non-browser applications connect to. Builds of one version line are merged first (2.1.322 and 2.1.326 go as 2.1.*). Never: addresses, the sites you visit, times, file paths or your name. Each item travels as a separate anonymous ballot that the server cannot tie to you or to your other items. Each week you get a day to look at the list and remove anything before it is sent.`),
    el("label", { class: "field" }, el("span", {}, "Collection server"), server),
    el("label", { class: "field" }, el("span", {}, "Relay (hides your address from the server)"), relay),
    el("label", { class: "field" }, el("span", {}, "Enrollment code"), code),
    observerNote,
    el("p", { class: "muted small" }, `The study's web page gives you a code: in one click from the university's network, or by e-mail, or with a GitHub account. The code only lets this ${device()} send a limited number of anonymous ballots each week, so that nobody else can flood the study; it does not identify your ballots.`),
    el("div", { class: "row" }, getCode),
    el("label", { class: "check" }, domains,
      el("span", {}, "Also share the server names (SNI) that non-browser applications connect to, each with its fingerprint (e.g. Teams connecting to teams.microsoft.com). Browsers' names are never collected: no browsing history. You can change this later.")),
    el("label", { class: "check" }, agree, el("span", {}, "I have read the study information and agree to take part. I can leave at any time from Settings.")),
    el("div", { class: "row" }, go),
  );
}

// ------------------------------------------------------------ overview

// Android: the capture is PeerSig's own VPN (CaptureService), not a service
// to install.
function androidCaptureCard() {
  const p = state.probe;
  const body = [];
  const start = (label) => el("button", { class: "btn primary", onclick: async () => { await call("install_probe"); refresh(); } }, label);
  if (!state.probe_installed) {
    body.push(el("div", { class: "big bad" }, "Not started"));
    body.push(el("p", { class: "muted" }, "PeerSig sees other apps' connections through a VPN of its own, which stays on this phone and forwards everything unchanged. Android asks once for your permission."));
    body.push(el("div", { class: "row" }, start("Allow and start")));
    return el("div", { class: "card" }, el("h2", {}, "Capture"), ...body);
  }
  if (state.paused) body.push(el("div", { class: "big warn" }, "Paused"), el("p", { class: "muted" }, "PeerSig's VPN is off: nothing is being looked at."), p.error ? el("p", { class: "muted small" }, p.error) : null);
  else if (p.running) body.push(el("div", { class: "big ok" }, "Capturing"), el("p", { class: "muted small" }, "Through PeerSig's VPN, on this phone only."));
  else if (p.error) body.push(el("div", { class: "big bad" }, "Cannot capture"), el("p", { class: "muted" }, p.error), el("div", { class: "row" }, start("Start capture")));
  else body.push(el("div", { class: "big bad" }, "Not running"), el("p", { class: "muted" }, "PeerSig's VPN is not on."), el("div", { class: "row" }, start("Start capture")));
  body.push(el("p", {}, `${p.hellos.toLocaleString()} handshakes seen since ${iso(p.started)}`, el("br"), el("span", { class: "muted small" }, `Last: ${iso(p.last_hello)}`)));
  body.push(el("div", { class: "row" },
    el("button", { class: "btn", onclick: () => call("set_paused", { paused: !state.paused }).then(refresh) }, state.paused ? "Resume capture" : "Pause capture"),
    el("button", { class: "btn", onclick: () => call("open_logs") }, "Export local logs"),
  ));
  return el("div", { class: "card" }, el("h2", {}, "Capture"), ...body);
}

function captureCard() {
  if (android()) return androidCaptureCard();
  const p = state.probe;
  const body = [];
  if (!state.probe_installed) {
    body.push(el("div", { class: "big bad" }, "Not installed"));
    body.push(el("p", { class: "muted" }, state.os === "windows"
      ? "The capture service needs to be installed once. Windows will ask for an administrator's permission."
      : "The capture service needs to be installed once. Your computer will ask for an administrator password."));
    body.push(el("div", { class: "row" }, el("button", { class: "btn primary", onclick: async () => { await call("install_probe"); refresh(); } }, "Install capture service")));
    return el("div", { class: "card" }, el("h2", {}, "Capture"), ...body);
  }
  if (state.probe_outdated) {
    body.push(el("div", { class: "notice" }, `The capture service still runs ${p.tool}, not the probe that came with this version of PeerSig: installing PeerSig does not update the service. Update it to get this version's fixes. `,
      state.os === "windows" ? "Windows will ask for an administrator's permission." : "Your computer will ask for an administrator password."));
    body.push(el("div", { class: "row" }, el("button", { class: "btn primary", onclick: async () => { await call("install_probe"); refresh(); } }, "Update capture service")));
  }
  if (state.paused) body.push(el("div", { class: "big warn" }, "Paused"), el("p", { class: "muted" }, "The capture device is closed: nothing is being looked at."));
  else if (p.running) body.push(el("div", { class: "big ok" }, "Capturing"));
  else if (p.error) body.push(el("div", { class: "big bad" }, "Cannot capture"), el("p", { class: "muted" }, p.error, el("br"), "The service tries again every 30 seconds."));
  else body.push(el("div", { class: "big bad" }, "Not running"), el("p", { class: "muted" }, "The service is installed but has not reported in the last 30 seconds."));
  body.push(el("p", {}, `${p.hellos.toLocaleString()} handshakes seen since ${iso(p.started)}`, el("br"), el("span", { class: "muted small" }, `Last: ${iso(p.last_hello)}`)));
  if (p.running && !p.pktap && state.os === "macos")
    body.push(el("div", { class: "notice" }, "No per-packet process data: applications are identified less reliably."));
  body.push(el("div", { class: "row" },
    el("button", { class: "btn", onclick: () => call("set_paused", { paused: !state.paused }).then(refresh) }, state.paused ? "Resume capture" : "Pause capture"),
    el("button", { class: "btn", onclick: () => call("open_logs") }, "Open local logs"),
  ));
  return el("div", { class: "card" }, el("h2", {}, "Capture"), ...body);
}

function reportCard() {
  const r = state.current;
  const body = [];
  if (!state.config) {
    body.push(el("p", { class: "muted" }, "Waiting for the server's configuration."));
  } else if (!r) {
    const cy = state.cycle;
    const from = cy.spec.origin + cy.current * cy.spec.length, to = from + cy.spec.length;
    body.push(el("div", { class: "big" }, "Collecting"));
    body.push(el("p", { class: "muted" }, state.observer
      ? `Today (${utcDay(from)}, UTC) will be reported tomorrow${state.settings.review_hours ? `, after ${state.settings.review_hours} hours for you to review it` : ", shortly after midnight UTC"}.`
      : `This week (${weekRange(from, to)}) will be reported next week, after a day for you to review it.`));
  } else {
    body.push(el("div", { class: "muted small" }, period(r.from, r.to)));
    if (r.state === "review") {
      body.push(el("div", { class: "big" }, `Sends in ${hours(r.review_until - state.now)}`));
      body.push(el("p", { class: "muted" }, "Look at the items and untick anything you do not want to send."));
      body.push(el("div", { class: "row" },
        el("button", { class: "btn primary", onclick: () => setTab("items") }, "Review items"),
        el("button", { class: "btn", onclick: () => call("send_now").then(refresh) }, "Send now")));
    } else if (r.state === "sending") {
      body.push(el("div", { class: "big ok" }, `Sending: ${r.sent} / ${r.total}`));
      body.push(el("progress", { max: r.total, value: r.sent }));
      body.push(el("p", { class: "muted small" }, `${r.real.length} items, one anonymous ballot each, at random times.`));
    } else if (r.state === "sent") {
      body.push(el("div", { class: "big ok" }, "Sent"), el("p", { class: "muted" }, state.observer ? `${r.real.length} items in one report, on ${when(r.finished)}.` : `${r.total} ballots on ${when(r.finished)}.`));
    } else {
      body.push(el("div", { class: "big bad" }, "Not sent"), el("p", { class: "muted" }, r.error || ""));
    }
    if (r.error && r.state !== "failed") body.push(el("div", { class: "notice error small" }, r.error));
  }
  return el("div", { class: "card" }, el("h2", {}, state.observer ? "Daily report" : "This week's report"), ...body);
}

function connectionCard() {
  const s = state.settings;
  return el("div", { class: "card" },
    el("h2", {}, "Connection"),
    el("p", {}, "Server: ", el("span", { class: "mono" }, s.server)),
    state.observer
      ? el("div", { class: "notice" }, `Dedicated observer: this ${device()} reports every day, and its items are published daily, without threshold.`)
      : s.relay
        ? el("p", {}, "Relay: ", el("span", { class: "mono" }, s.relay))
        : el("div", { class: "notice" }, `No relay: the server sees this ${device()}'s address when ballots arrive (not what they contain to whom).`),
    el("p", { class: "muted small" }, `Enrollment code ${s.code}`),
    state.last_error ? el("div", { class: "notice error small" }, state.last_error) : null,
  );
}

function renderOverview() {
  return el("div", { class: "grid" }, captureCard(), reportCard(), connectionCard());
}

// ------------------------------------------------------------ items

function describe(item) {
  if (item.type === "hello") return [`${item.transport.toUpperCase()} handshake`, el("div", { class: "mono" }, item.ja4)];
  if (item.type === "domain") return [`${item.ja4.startsWith("q") ? "QUIC" : "TCP"} connection to`, el("div", { class: "mono" }, item.domain), el("div", { class: "mono muted small" }, item.ja4)];
  return [item.type];
}

function renderItems() {
  const head = el("div", { class: "row" },
    el("div", { class: "segmented" },
      el("button", { class: "btn", "aria-pressed": String(!itemsCurrent), onclick: () => { itemsCurrent = false; loadItems(); } }, `${state.observer ? "Day" : "Week"} being reported`),
      el("button", { class: "btn", "aria-pressed": String(itemsCurrent), onclick: () => { itemsCurrent = true; loadItems(); } }, state.observer ? "Today so far" : "This week so far")),
    el("button", { class: "btn", onclick: loadItems }, "Refresh"));
  if (!items) return el("div", {}, head, el("p", { class: "muted" }, "Loading…"));
  const rows = items.items.map((o) => {
    const it = o.item;
    const box = el("input", { type: "checkbox", checked: !o.excluded, title: "Send this item" });
    box.addEventListener("change", async () => {
      await call("set_excluded", { key: o.key, excluded: !box.checked });
      o.excluded = !box.checked;
      tr.className = o.excluded ? "excluded" : "";
    });
    const app = it.app || {};
    const tr = el("tr", { class: o.excluded ? "excluded" : "" },
      el("td", {}, box),
      el("td", {}, el("div", {}, app.name, app.version ? el("span", { class: "muted" }, " " + app.version) : null,
          o.merged ? el("span", { class: "muted small", title: o.merged.join("\n") }, ` · ${o.merged.length} merged`) : null),
        el("span", { class: "chip" }, app.kind || ""), app.engine ? el("span", { class: "muted small" }, " " + app.engine) : null,
        app.id || app.team_id ? el("div", { class: "mono muted small" }, [app.id, app.team_id ? `team ${app.team_id}` : null].filter(Boolean).join(" · ")) : null),
      el("td", {}, ...describe(it)),
      el("td", { class: "muted" }, o.count.toLocaleString()),
      el("td", { class: "muted small" }, [...o.procs].join(", ")));
    return tr;
  });
  const sk = items.skipped;
  const os = items.items.map((o) => o.item.os).find(Boolean);
  const what = state.observer
    ? (items.current ? `Today so far: ${utcDay(items.from)} (UTC)` : `Day being reported: ${utcDay(items.from)} (UTC)`)
    : `${items.current ? "This week so far" : "Week being reported"}: ${weekRange(items.from, items.to)}`;
  return el("div", {},
    head,
    el("p", { class: "muted" }, `${what}. ${items.items.length} items.`),
    el("div", { class: "scroll" }, el("table", {},
      el("thead", {}, el("tr", {}, el("th", {}, "Send"), el("th", {}, "Application"), el("th", {}, "What"), el("th", {}, "Seen ¹"), el("th", {}, "Processes ¹"))),
      el("tbody", {}, rows.length ? rows : el("tr", {}, el("td", { colspan: 5, class: "muted" }, "Nothing yet."))))),
    el("p", { class: "muted small" }, `¹ Stays on this ${device()}: how often, and which ${android() ? "apps" : "processes"}. Everything else in a ticked row is sent, as shown: the application (${android() ? appFields() : "name, version, kind, engine, bundle id, signing team"}), the transport and fingerprint, and the server name of a “connection to” row (those carry no version). Each item also gives the system and its major version${os ? ` (${os})` : ""}. Once per ${unit()}, however often it was seen.`),
    el("p", { class: "muted small" },
      `Not collected: ${sk.unattributed} handshakes with no known application; ${sk.browser_domains} names contacted by browsers (browsing history is never collected)` +
      (state.settings.share_domains ? `; ${sk.private_domains} local or private names; ${sk.not_sni} names seen only in DNS or plain HTTP.` : `; ${sk.domains_off} server names (sharing is off).`)),
    el("p", { class: "muted small" }, state.observer
      ? "Ticked items go in one report that the server knows comes from this observer, and are published with the day, as they are: no threshold."
      : "Each ticked item goes as a separate anonymous ballot: the server cannot tell which items come from the same person. An item is published only once enough participants reported it."),
  );
}

// ------------------------------------------------------------ history

function renderHistory() {
  if (!state.reports.length) return el("p", { class: "muted" }, "No report yet.");
  return el("div", {}, ...state.reports.map((r) =>
    el("div", { class: "card stacked" },
      el("div", { class: "row flush" },
        el("strong", {}, period(r.from, r.to)),
        el("span", { class: "chip" }, r.state)),
      r.total && state.observer ? el("p", { class: "muted" }, `${r.real.length} items in one report.`) : null,
      r.total && !state.observer ? el("p", { class: "muted" }, `${r.sent}/${r.total} ballots: ${r.real.length} items and one "took part" ballot${r.dropped ? `; ${r.dropped} items over the token budget were left out` : ""}.`) : null,
      r.error ? el("p", { class: "small bad" }, r.error) : null,
      r.real.length ? el("details", {}, el("summary", {}, "Real items sent"),
        el("ul", { class: "plain small" }, ...r.real.map((i) => el("li", {}, i.app ? `${i.app.name} ${i.app.version || ""} — ${i.type === "hello" ? i.ja4 : `${i.domain} (${i.ja4})`}` : i.type)))) : null,
      r.key_id ? el("p", { class: "muted small" }, `Token key ${r.key_id}`) : null,
    )));
}

// ------------------------------------------------------------ privacy

function renderObserverPrivacy() {
  return el("div", { class: "card" },
    el("h2", {}, `This ${device()} is a dedicated observer`),
    el("ul", { class: "plain" },
      el("li", {}, el("strong", {}, "What is sent. "), `Each day (UTC): which applications (${appFields()}) sent which handshake fingerprint, on which system and major version; if sharing is on, the server names non-browser applications connected to. No addresses, times, counts, file paths, user or host names.`),
      el("li", {}, el("strong", {}, "Not anonymous. "), `The day's items go in one report with this ${device()}'s observer code: the server knows they come from this observer. It keeps a count per item and day, and which observers reported which day.`),
      el("li", {}, el("strong", {}, "Published daily. "), "Each day's items are published with the number of observers that reported them, without waiting for other participants."),
      el("li", {}, el("strong", {}, "Review. "), state.settings.review_hours ? `Each day's list waits ${state.settings.review_hours} hours before it is sent; untick anything.` : "No review: each day's list is sent shortly after midnight UTC. Settings can add one."),
      el("li", {}, el("strong", {}, "Apart from participants. "), "Observers' items never count towards the participants' table."),
      el("li", {}, el("strong", {}, "Local logs. "), `The capture logs stay on this ${device()} and are deleted after two weeks.`),
      android() ? vpnPrivacy() : null,
    ),
    el("div", { class: "row" }, el("button", { class: "btn", onclick: () => call("open_url", { url: "https://github.com/UCLouvain-ENSG/peersig/blob/main/docs/observers.md" }) }, "About observers")),
  );
}

// Android: what the VPN does, and does not.
function vpnPrivacy() {
  return el("li", {}, el("strong", {}, "A VPN that stays on the phone. "), "Android shows other apps' connections only to a VPN, so PeerSig runs one of its own. It forwards every connection, unchanged, to where it was going, and keeps a copy of the start of encrypted connections only, for the local logs. No VPN server is involved: your traffic goes out as it would without PeerSig. Android shows a key icon while it is on.");
}

function renderPrivacy() {
  if (state.enrolled && state.observer) return renderObserverPrivacy();
  const c = state.config;
  return el("div", { class: "card" },
    el("h2", {}, "How your data is protected"),
    el("ul", { class: "plain" },
      el("li", {}, el("strong", {}, `Little leaves your ${device()}. `), `Per week: which applications (${appFields()}) sent which handshake fingerprint, on which system and major version. Optional: the server names (SNI) non-browser applications connect to, with the fingerprint used. No addresses, times, counts, file paths, user or host names.`),
      el("li", {}, el("strong", {}, "Less specific items. "), "Before you review them, items that differ only in a detail are merged: versions after major.minor (2.1.322 and 2.1.326 go as 2.1.*) and numbered server names (p177-fmip.icloud.com and p63-fmip.icloud.com go as p*-fmip.icloud.com). A rare build points to fewer people, and more items fit the weekly budget. An item you remove is never merged into another."),
      el("li", {}, el("strong", {}, "You review it first. "), `Each week's list waits ${state.settings.review_hours} hours before it is sent; untick anything.`),
      el("li", {}, el("strong", {}, "Anonymous ballots. "), "Every item is a separate ballot carrying a token the server signed without seeing it (blind signature, as in anonymous e-voting). The server knows the ballot comes from an enrolled participant, not which one, nor which ballots come from the same person."),
      el("li", {}, el("strong", {}, "Hidden address. "), state.settings.relay ? "Ballots go through a relay: it sees your address but not the content; the server sees the content but not your address. This hides who sends what as long as the relay and the server are run by different parties." : "No relay is configured: the server could see your address when ballots arrive."),
      el("li", {}, el("strong", {}, "Thresholds. "), c ? `The study publishes an item only once at least ${c.k_hello} participants reported it in the same week (${c.k_domain} for server names).` : "Items are published only above a participant threshold."),
      el("li", {}, el("strong", {}, "Counts only. "), "The server keeps one counter per item and week: no individual ballots, no arrival times."),
      el("li", {}, el("strong", {}, "Local logs. "), `The capture logs stay on this ${device()} and are deleted after two weeks.`),
      android() ? vpnPrivacy() : null,
    ),
    c ? el("p", { class: "muted small" }, `Token key for this week: ${c.token_key.key_id}. The app checks that the server signs with the key everyone sees, and that the relay and the server publish the same encryption key.`) : null,
    c && c.about_url ? el("div", { class: "row" }, el("button", { class: "btn", onclick: () => call("open_url", { url: c.about_url }) }, "About this study")) : null,
    el("div", { class: "row" }, el("button", { class: "btn", onclick: () => call("open_url", { url: "https://github.com/UCLouvain-ENSG/peersig" }) }, "Source code")),
  );
}

// ------------------------------------------------------------ settings

function renderSettings() {
  const s = state.settings;
  const relay = el("input", { type: "url", value: s.relay });
  const domains = el("input", { type: "checkbox", checked: s.share_domains });
  const review = el("input", { type: "number", min: 0, max: 96, value: s.review_hours });
  const spread = el("input", { type: "number", min: 5, max: 1440, value: s.spread_minutes });
  const auto = el("input", { type: "checkbox", checked: !!autostartOn });
  auto.addEventListener("change", async () => (autostartOn = await call("autostart", { enabled: auto.checked })));
  const save = el("button", { class: "btn primary" }, "Save");
  save.addEventListener("click", async () => {
    await call("save_settings", { relay: relay.value, shareDomains: domains.checked, reviewHours: Number(review.value), spreadMinutes: Number(spread.value) });
    await refresh();
  });
  const del = el("input", { type: "checkbox" });
  const leave = el("button", { class: "btn" }, "Leave the study");
  leave.addEventListener("click", async () => {
    if (!confirm("Leave the study? Nothing more will be sent. Ballots already sent cannot be withdrawn: they are anonymous, so nobody can find them.")) return;
    await call("leave", { deleteLogs: del.checked });
    await refresh();
  });
  return el("div", { class: "grid" },
    el("div", { class: "card" },
      el("h2", {}, "Sending"),
      el("label", { class: "field" }, el("span", {}, "Relay"), relay),
      el("label", { class: "check" }, domains, el("span", {}, "Share the server names (SNI) non-browser applications connect to")),
      el("label", { class: "field" }, el("span", {}, `Hours to review each ${unit()}'s report before it is sent`), review),
      state.observer ? null : el("label", { class: "field" }, el("span", {}, "Spread the ballots over (minutes)"), spread),
      el("div", { class: "row" }, save)),
    el("div", { class: "card" },
      el("h2", {}, `This ${device()}`),
      el("label", { class: "check" }, auto, el("span", {}, android() ? "Start PeerSig when the phone starts (it sends nothing while it is not running)" : "Start PeerSig when I log in (it sends nothing while it is not running)")),
      el("p", { class: "muted small" }, "Local logs: ", el("span", { class: "mono" }, s.logs_dir)),
      el("div", { class: "row" },
        el("button", { class: "btn", onclick: () => call("open_logs") }, android() ? "Export logs" : "Open logs"),
        (state.os === "macos" || state.os === "windows") && state.probe_installed ? el("button", { class: "btn", onclick: async () => { await call("uninstall_probe"); refresh(); } }, "Remove capture service") : null)),
    el("div", { class: "card" },
      el("h2", {}, "Leave"),
      el("label", { class: "check" }, del, el("span", {}, "Also delete the local logs")),
      el("div", { class: "row" }, leave)),
  );
}

// ------------------------------------------------------------ main

function render() {
  if (!state) return;
  renderPill();
  const main = document.getElementById("main");
  let view;
  if (!state.enrolled && tab !== "privacy") view = renderEnroll();
  else if (tab === "items") view = renderItems();
  else if (tab === "history") view = renderHistory();
  else if (tab === "privacy") view = renderPrivacy();
  else if (tab === "settings") view = renderSettings();
  else view = renderOverview();
  main.replaceChildren(view);
}

for (const b of document.querySelectorAll("#tabs button")) b.addEventListener("click", () => setTab(b.dataset.tab));
listen("state", (e) => {
  state = e.payload;
  // Do not rebuild a form being typed in.
  if (tab === "settings" || (!state.enrolled && tab !== "privacy")) { renderPill(); return; }
  render();
});
invoke("autostart", {}).then((v) => (autostartOn = v)).catch(() => {});
refresh();
