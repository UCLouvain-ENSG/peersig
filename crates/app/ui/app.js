// PeerSig window. All data is inserted with textContent, never as HTML:
// application names come from executables on this computer.
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
  const relay = el("input", { type: "url", placeholder: "https://relay.example.net (given with your code)", value: state.settings.relay || "" });
  const code = el("input", { type: "text", placeholder: "XXXX-XXXX-XXXX", autocomplete: "off" });
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
    el("p", {}, "PeerSig watches the start of the encrypted connections this computer makes (the TLS “ClientHello”), notes which application made each one, and once a week contributes that list to a research study."),
    el("p", {}, "What it sends: application names and versions, the fingerprint (JA4) of their handshakes, and the OS family. Never: addresses, the sites you visit, times, file paths or your name. Each item travels as a separate anonymous ballot that the server cannot tie to you or to your other items. Each week you get a day to look at the list and remove anything before it is sent."),
    el("label", { class: "field" }, el("span", {}, "Collection server"), server),
    el("label", { class: "field" }, el("span", {}, "Relay (hides your address from the server)"), relay),
    el("label", { class: "field" }, el("span", {}, "Enrollment code"), code),
    el("label", { class: "check" }, domains,
      el("span", {}, "Also share the domain names that non-browser applications contact (e.g. Teams contacting teams.microsoft.com). Browsing history is never collected. You can change this later.")),
    el("label", { class: "check" }, agree, el("span", {}, "I have read the study information and agree to take part. I can leave at any time from Settings.")),
    el("div", { class: "row" }, go),
  );
}

// ------------------------------------------------------------ overview

function captureCard() {
  const p = state.probe;
  const body = [];
  if (!state.probe_installed) {
    body.push(el("div", { class: "big bad" }, "Not installed"));
    body.push(el("p", { class: "muted" }, "The capture service needs to be installed once. Your computer will ask for an administrator password."));
    body.push(el("div", { class: "row" }, el("button", { class: "btn primary", onclick: async () => { await call("install_probe"); refresh(); } }, "Install capture service")));
    return el("div", { class: "card" }, el("h2", {}, "Capture"), ...body);
  }
  if (state.paused) body.push(el("div", { class: "big warn" }, "Paused"), el("p", { class: "muted" }, "The capture device is closed: nothing is being looked at."));
  else if (p.running) body.push(el("div", { class: "big ok" }, "Capturing"));
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
    const c = state.config;
    body.push(el("div", { class: "big" }, "Collecting"));
    body.push(el("p", { class: "muted" }, `This week (${weekRange(c.epochs.origin + c.current_epoch * c.epochs.length, c.epochs.origin + (c.current_epoch + 1) * c.epochs.length)}) will be reported next week, after a day for you to review it.`));
  } else {
    body.push(el("div", { class: "muted small" }, `Week of ${weekRange(r.from, r.to)}`));
    if (r.state === "review") {
      body.push(el("div", { class: "big" }, `Sends in ${hours(r.review_until - state.now)}`));
      body.push(el("p", { class: "muted" }, "Look at the items and untick anything you do not want to send."));
      body.push(el("div", { class: "row" },
        el("button", { class: "btn primary", onclick: () => setTab("items") }, "Review items"),
        el("button", { class: "btn", onclick: () => call("send_now").then(refresh) }, "Send now")));
    } else if (r.state === "sending") {
      body.push(el("div", { class: "big ok" }, `Sending: ${r.sent} / ${r.total}`));
      body.push(el("progress", { max: r.total, value: r.sent }));
      body.push(el("p", { class: "muted small" }, `${r.real.length} real items and ${r.decoys} decoys, one anonymous ballot each, at random times.`));
    } else if (r.state === "sent") {
      body.push(el("div", { class: "big ok" }, "Sent"), el("p", { class: "muted" }, `${r.total} ballots on ${when(r.finished)}.`));
    } else {
      body.push(el("div", { class: "big bad" }, "Not sent"), el("p", { class: "muted" }, r.error || ""));
    }
    if (r.error && r.state !== "failed") body.push(el("div", { class: "notice error small" }, r.error));
  }
  return el("div", { class: "card" }, el("h2", {}, "This week's report"), ...body);
}

function connectionCard() {
  const s = state.settings;
  return el("div", { class: "card" },
    el("h2", {}, "Connection"),
    el("p", {}, "Server: ", el("span", { class: "mono" }, s.server)),
    s.relay
      ? el("p", {}, "Relay: ", el("span", { class: "mono" }, s.relay))
      : el("div", { class: "notice" }, "No relay: the server sees this computer's address when ballots arrive (not what they contain to whom)."),
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
  if (item.type === "domain") return ["contacted", el("div", { class: "mono" }, item.domain)];
  return [item.type];
}

function renderItems() {
  const head = el("div", { class: "row" },
    el("div", { class: "segmented" },
      el("button", { class: "btn", "aria-pressed": String(!itemsCurrent), onclick: () => { itemsCurrent = false; loadItems(); } }, "Week being reported"),
      el("button", { class: "btn", "aria-pressed": String(itemsCurrent), onclick: () => { itemsCurrent = true; loadItems(); } }, "This week so far")),
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
      el("td", {}, el("div", {}, app.name, app.version ? el("span", { class: "muted" }, " " + app.version) : null),
        el("span", { class: "chip" }, app.kind || ""), app.engine ? el("span", { class: "muted small" }, " " + app.engine) : null),
      el("td", {}, ...describe(it)),
      el("td", { class: "muted" }, o.count.toLocaleString()),
      el("td", { class: "muted small" }, [...o.procs].join(", ")));
    return tr;
  });
  const sk = items.skipped;
  return el("div", {},
    head,
    el("p", { class: "muted" }, `${items.current ? "This week so far" : "Week being reported"}: ${weekRange(items.from, items.to)}. ${items.items.length} items.`),
    el("table", {},
      el("thead", {}, el("tr", {}, el("th", {}, "Send"), el("th", {}, "Application"), el("th", {}, "What"), el("th", {}, "Seen ¹"), el("th", {}, "Processes ¹"))),
      el("tbody", {}, rows.length ? rows : el("tr", {}, el("td", { colspan: 5, class: "muted" }, "Nothing yet.")))),
    el("p", { class: "muted small" }, "¹ Stays on this computer. Only the application, its version, the OS family and the fingerprint (or domain) are sent, once per week, not how often."),
    el("p", { class: "muted small" },
      `Not collected: ${sk.unattributed} handshakes with no known application; ${sk.browser_domains} names contacted by browsers (browsing history is never collected)` +
      (state.settings.share_domains ? `; ${sk.private_domains} local or private names.` : `; ${sk.domains_off} domain names (sharing is off).`)),
    el("p", { class: "muted small" }, "Items the server already knows are sent with randomized response: some of your items are left out and some you did not see are added, so no ballot proves you use an application."),
  );
}

// ------------------------------------------------------------ history

function renderHistory() {
  if (!state.reports.length) return el("p", { class: "muted" }, "No report yet.");
  return el("div", {}, ...state.reports.map((r) =>
    el("div", { class: "card stacked" },
      el("div", { class: "row flush" },
        el("strong", {}, `Week of ${weekRange(r.from, r.to)}`),
        el("span", { class: "chip" }, r.state)),
      r.total ? el("p", { class: "muted" }, `${r.sent}/${r.total} ballots: ${r.real.length} real items, ${r.decoys} decoys, ${r.withheld} left out by randomized response${r.dropped ? `, ${r.dropped} over the token budget` : ""}.`) : null,
      r.error ? el("p", { class: "small bad" }, r.error) : null,
      r.real.length ? el("details", {}, el("summary", {}, "Real items sent"),
        el("ul", { class: "plain small" }, ...r.real.map((i) => el("li", {}, i.app ? `${i.app.name} ${i.app.version || ""} — ${i.type === "hello" ? i.ja4 : i.domain}` : i.type)))) : null,
      r.key_id ? el("p", { class: "muted small" }, `Token key ${r.key_id}`) : null,
    )));
}

// ------------------------------------------------------------ privacy

function renderPrivacy() {
  const c = state.config;
  const eps = state.epsilon_local;
  return el("div", { class: "card" },
    el("h2", {}, "How your data is protected"),
    el("ul", { class: "plain" },
      el("li", {}, el("strong", {}, "Little leaves your computer. "), "Per week: which applications (name, version, kind) sent which handshake fingerprint, on which OS family. Optional: domains contacted by non-browser applications. No addresses, times, counts, file paths, user or host names."),
      el("li", {}, el("strong", {}, "You review it first. "), `Each week's list waits ${state.settings.review_hours} hours before it is sent; untick anything.`),
      el("li", {}, el("strong", {}, "Anonymous ballots. "), "Every item is a separate ballot carrying a token the server signed without seeing it (blind signature, as in anonymous e-voting). The server knows the ballot comes from an enrolled participant, not which one, nor which ballots come from the same person."),
      el("li", {}, el("strong", {}, "Hidden address. "), state.settings.relay ? "Ballots go through a relay run by another party: the relay sees your address but not the content; the server sees the content but not your address." : "No relay is configured: the server could see your address when ballots arrive."),
      el("li", {}, el("strong", {}, "Plausible deniability. "), c ? `Items already known are reported with randomized response (p = ${c.rr_p.toFixed(2)}, ε = ${eps.toFixed(2)} per item and week): some of yours are left out, some you did not have are added.` : "Randomized response on known items."),
      el("li", {}, el("strong", {}, "Thresholds. "), c ? `The study publishes an item only once at least ${c.k_hello} participants reported it (${c.k_domain} for domains), with Laplace noise (ε = ${c.epsilon_central}).` : "Items are published only above a participant threshold."),
      el("li", {}, el("strong", {}, "Counts only. "), "The server keeps one counter per item and week: no individual ballots, no arrival times."),
      el("li", {}, el("strong", {}, "Local logs. "), "The capture logs stay on this computer and are deleted after two weeks."),
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
      el("label", { class: "check" }, domains, el("span", {}, "Share domains contacted by non-browser applications")),
      el("label", { class: "field" }, el("span", {}, "Hours to review each week's report before it is sent"), review),
      el("label", { class: "field" }, el("span", {}, "Spread the ballots over (minutes)"), spread),
      el("div", { class: "row" }, save)),
    el("div", { class: "card" },
      el("h2", {}, "This computer"),
      el("label", { class: "check" }, auto, el("span", {}, "Start PeerSig when I log in (it sends nothing while it is not running)")),
      el("p", { class: "muted small" }, "Local logs: ", el("span", { class: "mono" }, s.logs_dir)),
      el("div", { class: "row" },
        el("button", { class: "btn", onclick: () => call("open_logs") }, "Open logs"),
        state.os === "macos" && state.probe_installed ? el("button", { class: "btn", onclick: async () => { await call("uninstall_probe"); refresh(); } }, "Remove capture service") : null)),
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
