// peersig.org hero: volunteers (left) send (JA4, application) ballots, each
// with its blind token, to the table (middle); on a network (right), flows
// are labelled by looking their JA4 up in that table.
//
// The scene is drawn at once; motion starts when the page is idle, pauses
// when the scene is off screen or the tab hidden, and never starts with
// prefers-reduced-motion. A fixed pool of elements is reused.
(function () {
  "use strict";
  var host = document.getElementById("scene");
  if (!host) return;
  var reduced = window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;
  var NS = "http://www.w3.org/2000/svg";

  // Pairs seen in a test run: JA4, short name (ballots), full name (labels).
  var PAIRS = [
    ["t13d1516h2_8daaf6152771_806a8c22fdea", "Teams", "Microsoft Teams"],
    ["t13d1517h2_8daaf6152771_e6dcd7ae0a9e", "Firefox", "Firefox 160"],
    ["t13d4907h2_0d8feac7bc37_7395dae3b2f3", "git", "git 2.55"],
    ["t13d2013h2_a09f3c656075_7f0f34a4126d", "WhatsApp", "WhatsApp"],
    ["t13d1517h2_8daaf6152771_a87ad97598a9", "VS Code", "Visual Studio Code"],
    ["q13d0311h3_55b375c5d22e_f2a83c8e78ae", "iCloud", "iCloud (cloudd)"],
    ["t13d3012h1_1d37bd780c83_882d495ac381", "Defender", "Microsoft Defender"],
    ["q13d0311h3_55b375c5d22e_653d80c3fe9d", "Teams", "Microsoft Teams (QUIC)"]
  ];
  var PEERS = [72, 152, 232, 312];
  var DB = { x: 600, top: 118, bottom: 246, rx: 80, ry: 18 };
  var TRACK = { x: 770, y: 168, w: 410, h: 44 };
  var LENS = { x: 965, y: 190 };
  var CHIP_W = 168, FLOW_W = 214;

  function el(name, attrs, parent) {
    var e = document.createElementNS(NS, name);
    for (var k in attrs) e.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(e);
    return e;
  }
  function text(parent, x, y, s, cls, anchor) {
    var t = el("text", { x: x, y: y, "class": cls, "text-anchor": anchor || "start" }, parent);
    t.textContent = s;
    return t;
  }
  function short(ja4) { return ja4.slice(0, 10) + "…"; }

  // ---- scene ----------------------------------------------------------------
  var svg = el("svg", { viewBox: "0 0 1200 400", "aria-hidden": "true", focusable: "false" });
  var defs = el("defs", {}, svg);
  var g = el("linearGradient", { id: "dbg", x1: "0", y1: "0", x2: "1", y2: "1" }, defs);
  el("stop", { offset: "0", "class": "db-s1" }, g);
  el("stop", { offset: "1", "class": "db-s2" }, g);
  var clip = el("clipPath", { id: "trackclip" }, defs);
  el("rect", { x: TRACK.x, y: TRACK.y, width: TRACK.w, height: TRACK.h, rx: 22 }, clip);

  text(svg, 120, 44, "VOLUNTEERS", "h-label", "middle");
  text(svg, DB.x, 44, "THE PEERSIG TABLE", "h-label", "middle");
  text(svg, TRACK.x + TRACK.w / 2, 44, "ANY NETWORK", "h-label", "middle");

  // Paths from the peers to the table, and from the table to the lens.
  PEERS.forEach(function (y) {
    el("path", { d: "M170 " + (y + 24) + " Q 360 " + (y + 24) + " " + (DB.x - DB.rx - 6) + " 182", "class": "h-line" }, svg);
  });
  var pingPath = "M" + (DB.x + DB.rx) + " 168 C 760 92, 900 92, " + LENS.x + " " + (LENS.y - 30);
  el("path", { d: pingPath, "class": "h-dash" }, svg);
  var ping = el("path", { d: pingPath, "class": "h-ping" }, svg);

  // Ballots travel beneath the table, so they slide into it.
  var chipG = el("g", {}, svg);

  // Volunteers' laptops.
  PEERS.forEach(function (y) {
    el("rect", { x: 70, y: y, width: 92, height: 54, rx: 7, "class": "h-peer" }, svg);
    el("rect", { x: 77, y: y + 7, width: 78, height: 40, rx: 4, "class": "h-screen" }, svg);
    el("path", { d: "M60 " + (y + 54) + " h112 l-8 9 h-96 z", "class": "h-peer" }, svg);
    el("rect", { x: 86, y: y + 17, width: 40, height: 5, rx: 2.5, "class": "a-soft" }, svg);
    el("rect", { x: 86, y: y + 28, width: 58, height: 5, rx: 2.5, "class": "a-soft" }, svg);
  });

  // The table: a database and its last rows.
  el("path", { d: "M" + (DB.x - DB.rx) + " " + DB.top + " v" + (DB.bottom - DB.top) + " a" + DB.rx + " " + DB.ry + " 0 0 0 " + 2 * DB.rx + " 0 v-" + (DB.bottom - DB.top) + " z", "class": "h-db" }, svg);
  el("ellipse", { cx: DB.x, cy: DB.top, rx: DB.rx, ry: DB.ry, "class": "h-db-top" }, svg);
  text(svg, DB.x, 182, "JA4 → application", "h-title a-white", "middle");
  var counter = text(svg, DB.x, 206, "", "h-mono a-white", "middle");
  var labels = 1204;
  counter.textContent = labels.toLocaleString("en") + " labels";
  var rows = [];
  for (var i = 0; i < 3; i++) {
    var rg = el("g", { "class": "h-row", transform: "translate(452 " + (276 + i * 32) + ")" }, svg);
    el("rect", { width: 296, height: 25, rx: 7 }, rg);
    var rt = text(rg, 12, 17, "", "h-mono");
    var p = PAIRS[i];
    rt.textContent = short(p[0]) + "  →  " + p[2];
    rows.push({ g: rg, t: rt });
  }

  // The network: flows go through a lens that looks them up.
  el("rect", { x: TRACK.x, y: TRACK.y, width: TRACK.w, height: TRACK.h, rx: 22, "class": "h-box" }, svg);
  var flowG = el("g", { "clip-path": "url(#trackclip)" }, svg);
  text(svg, 860, 246, "unknown JA4", "h-mono-m", "middle");
  text(svg, 1090, 246, "labelled", "h-mono-m", "middle");
  el("circle", { cx: LENS.x, cy: LENS.y, r: 30, "class": "h-lens", "fill-opacity": "0.15" }, svg);
  el("path", { d: "M" + (LENS.x + 21) + " " + (LENS.y + 21) + " l18 18", "class": "h-lens", "stroke-linecap": "round", "stroke-width": "5" }, svg);
  text(svg, LENS.x, 300, "classifier", "h-label", "middle");

  host.appendChild(svg);

  // ---- moving parts ---------------------------------------------------------
  var chips = [], flows = [], next = 0;
  function makeChip() {
    var c = el("g", { "class": "h-chip", opacity: 0 }, chipG);
    el("rect", { width: CHIP_W, height: 26, rx: 13 }, c);
    el("circle", { cx: 14, cy: 13, r: 6, "class": "tok" }, c);
    var t = text(c, 27, 17, "", "h-mono");
    return { g: c, t: t, busy: false };
  }
  function makeFlow() {
    var f = el("g", { "class": "h-flow", opacity: 0 }, flowG);
    el("rect", { width: FLOW_W, height: 26, rx: 13 }, f);
    el("circle", { cx: 14, cy: 13, r: 5 }, f);
    var t = text(f, 26, 17, "", "h-mono");
    return { g: f, t: t, busy: false };
  }
  for (i = 0; i < 9; i++) chips.push(makeChip());
  for (i = 0; i < 4; i++) flows.push(makeFlow());

  function ease(x) { return x < 0.5 ? 2 * x * x : 1 - Math.pow(-2 * x + 2, 2) / 2; }
  function pick() { return PAIRS[Math.floor(Math.random() * PAIRS.length)]; }

  function launchChip(now) {
    var c = chips.filter(function (c) { return !c.busy; })[0];
    if (!c) return;
    var y = PEERS[Math.floor(Math.random() * PEERS.length)] + 24;
    var p = pick();
    c.busy = true; c.t0 = now; c.y = y; c.pair = p;
    c.t.textContent = short(p[0]) + " · " + p[1];
  }
  function moveChip(c, now) {
    var k = (now - c.t0) / 2800;
    if (k >= 1) {
      c.busy = false; c.g.setAttribute("opacity", 0);
      arrive(c.pair);
      return;
    }
    var e = ease(k), x0 = 170, y0 = c.y, cx = 360, cy = c.y, x1 = DB.x - DB.rx - 6 - CHIP_W / 2, y1 = 182;
    var x = (1 - e) * (1 - e) * x0 + 2 * (1 - e) * e * cx + e * e * x1;
    var y = (1 - e) * (1 - e) * y0 + 2 * (1 - e) * e * cy + e * e * y1;
    var o = k < 0.1 ? k / 0.1 : k > 0.88 ? (1 - k) / 0.12 : 1;
    c.g.setAttribute("transform", "translate(" + (x - 6).toFixed(1) + " " + (y - 13).toFixed(1) + ")");
    c.g.setAttribute("opacity", o.toFixed(2));
  }
  function arrive(p) {
    var r = rows[next++ % rows.length];
    r.t.textContent = short(p[0]) + "  →  " + p[2];
    r.g.classList.add("flash");
    setTimeout(function () { r.g.classList.remove("flash"); }, 700);
    labels += 1;
    counter.textContent = labels.toLocaleString("en") + " labels";
  }

  function launchFlow(now) {
    var f = flows.filter(function (f) { return !f.busy; })[0];
    if (!f) return;
    var p = pick();
    f.busy = true; f.t0 = now; f.pair = p; f.known = false;
    f.g.classList.remove("known");
    f.t.textContent = p[0].slice(0, 22) + "…";
  }
  function moveFlow(f, now) {
    var k = (now - f.t0) / 6000;
    if (k >= 1) { f.busy = false; f.g.setAttribute("opacity", 0); return; }
    var x = TRACK.x - FLOW_W + k * (TRACK.w + FLOW_W);
    if (!f.known && x + FLOW_W / 2 > LENS.x) {
      f.known = true;
      f.g.classList.add("known");
      f.t.textContent = "✓ " + f.pair[2];
      ping.classList.remove("on");
      void ping.getBoundingClientRect();
      ping.classList.add("on");
    }
    f.g.setAttribute("transform", "translate(" + x.toFixed(1) + " " + (TRACK.y + 9) + ")");
    f.g.setAttribute("opacity", 1);
  }

  // A still frame, from which the animation goes on: some ballots on their
  // way, one flow labelled, one about to be.
  function still() {
    var now = performance.now();
    [[0, 0.35], [2, 0.6], [3, 0.8]].forEach(function (s, j) {
      var c = chips[j];
      c.busy = true; c.t0 = now - s[1] * 2800; c.y = PEERS[s[0]] + 24; c.pair = PAIRS[j];
      c.t.textContent = short(PAIRS[j][0]) + " · " + PAIRS[j][1];
      moveChip(c, now);
    });
    [[0, 0.62], [3, 0.2]].forEach(function (s, j) {
      var f = flows[j];
      f.busy = true; f.pair = PAIRS[s[0]]; f.t0 = now - s[1] * 6000; f.known = false;
      f.g.classList.remove("known");
      f.t.textContent = PAIRS[s[0]][0].slice(0, 22) + "…";
      moveFlow(f, now);
    });
    ping.classList.remove("on");
  }
  still();
  if (reduced) return;

  var running = false, visible = true, lastChip = 0, lastFlow = 0, pausedAt = 0;
  function frame(now) {
    if (!running) return;
    if (now - lastChip > 650) { launchChip(now); lastChip = now; }
    if (now - lastFlow > 1700) { launchFlow(now); lastFlow = now; }
    chips.forEach(function (c) { if (c.busy) moveChip(c, now); });
    flows.forEach(function (f) { if (f.busy) moveFlow(f, now); });
    requestAnimationFrame(frame);
  }
  function update() {
    var go = visible && !document.hidden;
    if (go && !running) {
      running = true;
      // Pick up where things were: shift every start by the time paused.
      var now = performance.now(), gap = now - (pausedAt || now);
      chips.concat(flows).forEach(function (x) { if (x.busy) x.t0 += gap; });
      lastChip = lastChip + gap; lastFlow = lastFlow + gap;
      requestAnimationFrame(frame);
    } else if (!go && running) {
      running = false;
      pausedAt = performance.now();
    }
  }
  function start() {
    if ("IntersectionObserver" in window) {
      new IntersectionObserver(function (es) { visible = es[0].isIntersecting; update(); }).observe(host);
    }
    document.addEventListener("visibilitychange", update);
    update();
  }
  if ("requestIdleCallback" in window) requestIdleCallback(start, { timeout: 1500 });
  else setTimeout(start, 600);
})();
