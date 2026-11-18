// peersig.org: the JA4 walk-through (home page) and the download button
// (/participate). Everything works without this script; it only animates
// and picks the right file.
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

  // ---- the right download -------------------------------------------------------
  var main = document.getElementById("dl-main"), label = document.getElementById("dl-label");
  if (main && label) {
    var KINDS = {
      "macos-arm64": { label: "Download for macOS", meta: "Apple Silicon (M1 and newer) · macOS 12 or newer", tip: "dl-tip-mac" },
      "macos-x64": { label: "Download for macOS (Intel)", meta: "Intel Macs · macOS 12 or newer", tip: "dl-tip-mac" },
      "windows-x64": { label: "Download for Windows", meta: "Windows 10 and 11 · x64", tip: "dl-tip-windows" },
      "linux-deb": { label: "Download for Linux (.deb)", meta: "Debian, Ubuntu and derivatives · x86_64", tip: "dl-tip-linux" },
      "linux-rpm": { label: "Download for Linux (.rpm)", meta: "Fedora, RHEL, openSUSE · x86_64", tip: "dl-tip-linux" },
      "linux-appimage": { label: "Download for Linux (AppImage)", meta: "x86_64", tip: "dl-tip-linux" }
    };
    var detect = function () {
      var ua = navigator.userAgent;
      var plat = (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || "";
      if (/android|iphone|ipad|ipod/i.test(ua) || (/mac/i.test(plat) && navigator.maxTouchPoints > 1)) return Promise.resolve("mobile");
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
    var latest = fetch("/download/latest.json", { cache: "no-cache" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .catch(function () { return null; });
    Promise.all([detect(), latest]).then(function (v) {
      var kind = v[0], rel = v[1];
      var file = function (k) { return rel && rel.files && rel.files[k]; };
      // Versioned names when the release list is known; a package that is
      // not in it (not published here yet) is not offered.
      document.querySelectorAll("a[data-kind]").forEach(function (a) {
        var f = file(a.getAttribute("data-kind"));
        if (f) a.href = "/download/" + f.name;
        else if (rel) a.hidden = true;
      });
      var meta = document.getElementById("dl-meta");
      var k = KINDS[kind];
      var tips = function (shown) {
        document.querySelectorAll("[id^='dl-tip-']").forEach(function (t) { t.hidden = t.id !== shown; });
      };
      if (!k || (rel && !file(kind))) {
        label.textContent = kind === "mobile" ? "PeerSig runs on a computer" : "PeerSig runs on macOS, Windows and Linux";
        main.removeAttribute("href");
        main.classList.remove("grad-bg");
        var icon = main.querySelector("svg");
        if (icon) icon.remove();
        tips(null);
        meta.textContent = kind === "mobile" ? "Open this page on a Mac or a PC." : k ? "The package for this system is not published yet." : "Pick your system below.";
        return;
      }
      label.textContent = k.label;
      var f = file(kind);
      if (f) main.href = "/download/" + f.name;
      else main.href = document.querySelector('a[data-kind="' + kind + '"]').href;
      meta.textContent = k.meta + (rel ? " · version " + rel.version : "") + (f && f.size ? " · " + mb(f.size) : "");
      tips(k.tip);
    });
  }
})();
