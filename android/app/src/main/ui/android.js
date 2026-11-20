// Stands in for Tauri's API in the Android app (crates/app/ui runs
// unchanged): `invoke` goes to the app's bridge (MainActivity.Bridge),
// which answers through `__peersig.resolve`; the app pushes events
// through `__peersig.emit`. Loaded before app.js.
"use strict";

(() => {
  const pending = new Map();
  const listeners = new Map();
  let next = 1;

  window.__peersig = {
    resolve(id, json) {
      const p = pending.get(id);
      if (!p) return;
      pending.delete(id);
      const r = JSON.parse(json);
      if ("err" in r) p.reject(r.err);
      else p.resolve(r.ok);
    },
    emit(event, json) {
      const payload = JSON.parse(json);
      for (const cb of listeners.get(event) || []) cb({ event, payload });
    },
  };

  window.__TAURI__ = {
    core: {
      invoke(cmd, args) {
        return new Promise((resolve, reject) => {
          const id = next++;
          pending.set(id, { resolve, reject });
          window.PeerSigBridge.invoke(id, cmd, JSON.stringify(args || {}));
        });
      },
    },
    event: {
      listen(event, cb) {
        if (!listeners.has(event)) listeners.set(event, []);
        listeners.get(event).push(cb);
        return Promise.resolve(() => listeners.set(event, listeners.get(event).filter((c) => c !== cb)));
      },
    },
  };
})();
