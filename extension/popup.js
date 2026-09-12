(function (root) {
  "use strict";
  function derivePopupState(tabUrl, policy) {
    const origin = root.SentinelSitePolicy.normalizeOrigin(tabUrl);
    if (!origin) return { state: "unsupported", origin: null };
    if (!policy) return { state: "unavailable", origin };
    const validated = root.SentinelSitePolicy.validatePolicy(policy);
    return { state: validated.pausedOrigins.includes(origin) ? "paused" : "protected", origin, policy: validated };
  }
  function copyFor(state) {
    return {
      protected: ["✓ Protected on this site", "Sentinel pauses supported pastes before this site receives them."],
      paused: ["Ⅱ Protection paused on this site", "Supported pastes proceed after local policy confirmation."],
      unsupported: ["— Unsupported page", "Sentinel cannot inject or manage protection on this page. Password fields are also excluded."],
      unavailable: ["! Protection status unavailable", "Policy could not be read. Supported pastes remain blocked."],
    }[state];
  }
  async function start(api = root.chrome, doc = root.document, confirmReset = root.confirm) {
    const status = doc.querySelector("#status"), title = doc.querySelector("#status-title"), originNode = doc.querySelector("#origin"), copy = doc.querySelector("#status-copy"), primary = doc.querySelector("#primary"), list = doc.querySelector("#paused-list");
    const store = root.SentinelSitePolicy.createStore(api.storage.local, api.storage.onChanged);
    const [tab] = await api.tabs.query({ active: true, currentWindow: true });
    let current;
    async function render() {
      try { current = derivePopupState(tab?.url, await store.read()); }
      catch { current = { state: root.SentinelSitePolicy.normalizeOrigin(tab?.url) ? "unavailable" : "unsupported", origin: root.SentinelSitePolicy.normalizeOrigin(tab?.url) }; }
      const [heading, detail] = copyFor(current.state); status.dataset.state = current.state; title.textContent = heading; copy.textContent = detail; originNode.textContent = current.origin || "";
      primary.hidden = !["protected", "paused"].includes(current.state); primary.textContent = current.state === "paused" ? "Resume protection" : "Pause on this site";
      let policy; try { policy = await store.read(); } catch { policy = null; }
      list.replaceChildren(...(policy?.pausedOrigins || []).map((origin) => { const li = doc.createElement("li"); li.textContent = origin; return li; }));
    }
    primary.addEventListener("click", async () => { if (!current?.origin) return; try { await store.setPaused(current.origin, current.state === "protected"); await render(); } catch { current = { state: "unavailable", origin: current.origin }; await render(); } });
    doc.querySelector("#reset").addEventListener("click", async () => { if (!confirmReset("Clear every paused-site exception?")) return; try { await store.reset(); await render(); } catch { await render(); } });
    store.subscribe(() => render()); await render();
  }
  root.SentinelPopup = Object.freeze({ derivePopupState, start });
  if (root.document && root.chrome) root.document.addEventListener("DOMContentLoaded", () => start());
})(typeof globalThis !== "undefined" ? globalThis : window);
