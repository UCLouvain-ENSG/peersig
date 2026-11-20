// peersig.org: the JA4 walk-through (home page), the download tabs
// (/participate) and the tables (/data). Everything works without this
// script; it only animates, shows one tab at a time, picks the right file
// and filters rows.
(function () {
  "use strict";
  var reduced = window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;

  // ---- JA4, one part at a time ------------------------------------------------
  var demo = document.getElementById("ja4demo");
  if (demo) {
    // Each step lights the ClientHello fields (data-f) and the JA4 parts
    // (data-p) it names.
    var STEPS = [
      ["t", "<b>t</b>: the ClientHello came over TCP (<b>q</b> for QUIC, <b>d</b> for DTLS)."],
      ["v", "<b>13</b>: the highest TLS version offered, here TLS 1.3."],
      ["sni", "<b>d</b>: a server name (SNI) was sent; <b>i</b> when connecting to a bare IP address. The name itself is not in the JA4."],
      ["cs", "<b>15</b>: how many cipher suites are offered (GREASE values left out)."],
      ["ext", "<b>16</b>: how many extensions."],
      ["alpn", "<b>h2</b>: first and last characters of the first application protocol (ALPN)."],
      ["cs b", "<b>8daaf6152771</b>: the cipher suites, sorted, hashed with SHA-256 and cut to 12 hex digits. Their order does not matter."],
      ["ext sig c", "<b>806a8c22fdea</b>: the extensions (sorted, without SNI and ALPN) and the signature algorithms (in order), hashed the same way."],
      ["t v sni cs ext alpn b c", "Same TLS library, same settings: same JA4. It names software, never people. Which software, a JA4 alone does not say: that is what PeerSig adds."]
    ];
    var why = document.getElementById("ja4why"), dots = document.getElementById("ja4steps");
    var step = 0, hover = false, holdUntil = 0;
    // A click (or Enter) shows that step and holds the slideshow a while.
    var pick = function (i) { show(i); holdUntil = Date.now() + 20000; };
    STEPS.forEach(function (s, i) {
      var d = document.createElement("i");
      d.title = "Step " + (i + 1);
      d.addEventListener("click", function () { pick(i); });
      dots.appendChild(d);
    });
    // Every ClientHello field and every part of the JA4 leads to its step.
    demo.querySelectorAll("[data-f],[data-p]").forEach(function (e) {
      var n = e.getAttribute("data-f") || e.getAttribute("data-p");
      var i = STEPS.findIndex(function (s) { return s[0].split(" ").indexOf(n) >= 0; });
      if (i < 0) return;
      e.setAttribute("role", "button");
      e.setAttribute("tabindex", "0");
      e.classList.add("pick");
      e.addEventListener("click", function () { pick(i); });
      e.addEventListener("keydown", function (ev) {
        if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); pick(i); }
      });
    });
    function show(i) {
      step = i;
      var names = STEPS[i][0].split(" ");
      demo.querySelectorAll("[data-f],[data-p]").forEach(function (e) {
        var n = e.getAttribute("data-f") || e.getAttribute("data-p");
        e.classList.toggle("hl", names.indexOf(n) >= 0);
      });
      why.innerHTML = STEPS[i][1];
      Array.prototype.forEach.call(dots.children, function (d, j) { d.classList.toggle("on", j === i); });
    }
    show(0);
    demo.addEventListener("mouseenter", function () { hover = true; });
    demo.addEventListener("mouseleave", function () { hover = false; });
    if (!reduced) {
      setInterval(function () {
        if (!hover && !document.hidden && Date.now() > holdUntil) show((step + 1) % STEPS.length);
      }, 3200);
    }
  }

  // ---- tabs (/participate, /data) ------------------------------------------------
  // Without the script every pane shows, one after the other. A link to
  // #<name> (#server, #observers...) opens tab-<name>.
  var makeTabs = function (tablist) {
    var tabs = Array.prototype.slice.call(tablist.querySelectorAll("[role=tab]"));
    var paneOf = function (t) { return document.getElementById(t.getAttribute("aria-controls")); };
    var select = function (tab, focus) {
      tabs.forEach(function (t) {
        var on = t === tab;
        t.setAttribute("aria-selected", String(on));
        t.tabIndex = on ? 0 : -1;
        paneOf(t).hidden = !on;
      });
      if (focus) tab.focus();
    };
    tabs.forEach(function (t, i) {
      t.addEventListener("click", function () { select(t, false); });
      t.addEventListener("keydown", function (ev) {
        var j = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: tabs.length - 1 }[ev.key];
        if (j === undefined) return;
        ev.preventDefault();
        select(tabs[(j + tabs.length) % tabs.length], true);
      });
    });
    var named = function () {
      var t = document.getElementById("tab-" + location.hash.slice(1));
      return tabs.indexOf(t) >= 0 ? t : null;
    };
    window.addEventListener("hashchange", function () { if (named()) select(named(), false); });
    tablist.hidden = false;
    tablist.parentNode.classList.add("tabbed");
    var asked = named();
    select(asked || tabs[0], false);
    return { select: select, asked: !!asked };
  };
  document.querySelectorAll(".data .tabs[role=tablist]").forEach(makeTabs);

  // ---- /data: filter the rows, pick a day -------------------------------------------
  document.querySelectorAll("input.filter").forEach(function (input) {
    var rows = input.parentNode.querySelectorAll("table.items tbody tr");
    input.hidden = false;
    input.addEventListener("input", function () {
      var q = input.value.trim().toLowerCase();
      rows.forEach(function (r) { r.hidden = q !== "" && r.textContent.toLowerCase().indexOf(q) < 0; });
    });
  });
  document.querySelectorAll("form.day-pick select").forEach(function (sel) {
    sel.addEventListener("change", function () { sel.form.submit(); });
  });

  // ---- /participate: the visitor's system ---------------------------------------------
  // Its tab open; within it, its package first.
  var tablist = document.querySelector("#download .tabs[role=tablist]");
  if (tablist) {
    var dlTabs = makeTabs(tablist);
    var detect = function () {
      var ua = navigator.userAgent;
      var plat = (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || "";
      // Before Linux: Android's user agent names Linux too.
      if (/android/i.test(ua) || /android/i.test(plat)) return Promise.resolve("android");
      if (/iphone|ipad|ipod/i.test(ua) || (/mac/i.test(plat) && navigator.maxTouchPoints > 1)) return Promise.resolve("mobile");
      if (/mac/i.test(plat) || /Mac OS X/.test(ua)) {
        if (navigator.userAgentData && navigator.userAgentData.getHighEntropyValues) {
          return navigator.userAgentData.getHighEntropyValues(["architecture"])
            .then(function (v) { return v.architecture === "x86" ? "macos-x64" : "macos-arm64"; })
            .catch(gpuMac);
        }
        return Promise.resolve(gpuMac());
      }
      // Firefox names the distribution; otherwise the .deb, the common case.
      if (/linux/i.test(plat) || /Linux/.test(ua)) return Promise.resolve(/Fedora|Red Hat|CentOS|SUSE/i.test(ua) ? "linux-rpm" : "linux-deb");
      if (/win/i.test(plat) || /Windows/.test(ua)) return Promise.resolve("windows-x64");
      return Promise.resolve("other");
    };
    // Safari and Firefox do not say which Mac: Intel Macs have Intel or AMD GPUs.
    var gpuMac = function () {
      try {
        var c = document.createElement("canvas").getContext("webgl");
        var ext = c && c.getExtension("WEBGL_debug_renderer_info");
        var r = ext ? String(c.getParameter(ext.UNMASKED_RENDERER_WEBGL)) : "";
        if (/Intel|AMD|Radeon/i.test(r)) return "macos-x64";
      } catch (e) { /* no WebGL: assume the common case */ }
      return "macos-arm64";
    };
    var mb = function (n) { return (n / 1048576).toFixed(1) + " MB"; };
    var tabFor = function (kind) {
      var name = /^macos/.test(kind) ? "macos" : /^windows/.test(kind) ? "windows" : /^linux/.test(kind) ? "linux" : kind === "android" ? "android" : "macos";
      return document.getElementById("tab-" + name);
    };
    var latest = fetch("/download/latest.json", { cache: "no-cache" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .catch(function () { return null; });
    Promise.all([detect(), latest]).then(function (v) {
      var kind = v[0], rel = v[1];
      var file = function (k) { return rel && rel.files && rel.files[k]; };
      // Versioned names when the release list is known; a package that is
      // not in it (not published here yet) is not offered.
      document.querySelectorAll(".pane a[data-kind]").forEach(function (a) {
        var f = file(a.getAttribute("data-kind"));
        if (f) {
          a.href = "/download/" + f.name;
          a.title = f.name + (f.size ? " · " + mb(f.size) : "");
        } else if (rel) {
          a.hidden = true;
        }
      });
      document.querySelectorAll(".pane").forEach(function (pane) {
        var meta = pane.querySelector(".dl .meta"), shown = pane.querySelectorAll(".dl a[data-kind]:not([hidden])");
        if (!meta || !rel) return;
        if (shown.length) {
          meta.textContent = meta.textContent + " · version " + rel.version;
          return;
        }
        // Not mirrored here (yet): the release on GitHub has every package.
        var gh = document.createElement("a");
        gh.href = "https://github.com/UCLouvain-ENSG/peersig/releases/latest";
        gh.textContent = "the latest release on GitHub";
        meta.textContent = "Not on this site yet: download it from ";
        meta.appendChild(gh);
        meta.appendChild(document.createTextNode("."));
      });
      // The visitor's package is the highlighted one in its tab.
      var mine = document.querySelector('.pane a[data-kind="' + kind + '"]:not([hidden])');
      if (mine) {
        mine.parentNode.querySelectorAll("a").forEach(function (a) { a.classList.toggle("grad-bg", a === mine); });
      }
      var note = document.getElementById("dl-note");
      if (kind === "mobile" || kind === "other") {
        note.textContent = kind === "mobile" ? "PeerSig does not run on iPhones and iPads: open this page on a computer or an Android phone." : "Pick your system:";
        note.hidden = false;
      }
      if (!dlTabs.asked) dlTabs.select(tabFor(kind), false);
    });
  }
})();
