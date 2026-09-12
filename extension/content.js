(() => {
  "use strict";

  function removeReview() {
    document.querySelector("#sentinel-paste-overlay")?.remove();
    document.querySelector("#sentinel-paste-backdrop")?.remove();
  }

  function button(label, handler, primary = false) {
    const element = document.createElement("button");
    element.type = "button";
    element.textContent = label;
    element.style.cssText = `padding:9px 13px;border-radius:6px;border:1px solid #3b4657;background:${primary ? "#4f6df5" : "#1b2230"};color:#fff;cursor:pointer`;
    element.addEventListener("click", handler);
    return element;
  }

  function renderError(message) {
    removeReview();
    const notice = document.createElement("div");
    notice.id = "sentinel-paste-overlay";
    notice.setAttribute("role", "alert");
    notice.textContent = message;
    notice.style.cssText = "position:fixed;right:20px;bottom:20px;z-index:2147483647;max-width:440px;padding:14px 16px;border:1px solid #ef4444;border-radius:8px;background:#17191f;color:#fca5a5;font:14px system-ui;box-shadow:0 12px 36px #0009";
    document.documentElement.appendChild(notice);
  }

  function renderReview({ findings, actions }) {
    removeReview();
    const backdrop = document.createElement("div");
    backdrop.id = "sentinel-paste-backdrop";
    backdrop.style.cssText = "position:fixed;inset:0;z-index:2147483646;background:#0008";
    const overlay = document.createElement("section");
    overlay.id = "sentinel-paste-overlay";
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");
    overlay.setAttribute("aria-label", "Sentinel paste review");
    overlay.style.cssText = "position:fixed;left:50%;top:50%;transform:translate(-50%,-50%);z-index:2147483647;width:min(520px,92vw);max-height:80vh;overflow:auto;padding:20px;border:1px solid #596579;border-radius:12px;background:#11151d;color:#eef2ff;font:14px system-ui;box-shadow:0 24px 70px #000c";
    const title = document.createElement("h2"); title.textContent = "Sentinel blocked a sensitive paste"; title.style.marginTop = "0";
    const explanation = document.createElement("p"); explanation.textContent = "Analysis ran locally in your browser. The original text has not entered this page.";
    const list = document.createElement("div");
    const checks = findings.map((finding) => {
      const row = document.createElement("label"); row.style.cssText = "display:flex;gap:8px;margin:8px 0;padding:8px;background:#1a202b;border-radius:6px";
      const check = document.createElement("input"); check.type = "checkbox"; check.checked = true; check.value = finding.id;
      const safe = document.createElement("span"); safe.textContent = `${finding.type.replaceAll("_", " ")}: ${finding.safePreview} → ${finding.replacement}`;
      row.append(check, safe); list.append(row); return check;
    });
    const controls = document.createElement("div"); controls.style.cssText = "display:flex;gap:8px;justify-content:flex-end;margin-top:16px";
    controls.append(
      button("Block", () => { actions.block(); removeReview(); }),
      button("Allow once", () => { actions.allowOnce(); removeReview(); }),
      button("Redact and paste", () => { const ids = checks.filter((c) => c.checked).map((c) => c.value); if (!ids.length) return; actions.redact(ids); removeReview(); }, true)
    );
    overlay.append(title, explanation, list, controls);
    document.documentElement.append(backdrop, overlay);
    overlay.querySelector("button")?.focus();
  }

  if (!/^https?:$/.test(location.protocol)) return;
  const engine = globalThis.SentinelEngine;
  const paste = globalThis.SentinelPaste;
  const policyApi = globalThis.SentinelSitePolicy;
  if (!paste || !policyApi) return;
  const pageOrigin = policyApi.normalizeOrigin(location.href);
  const sitePolicy = policyApi.createStore(chrome.storage.local, chrome.storage.onChanged);
  const controller = paste.createController({
    engine: engine || { analyzeText() { throw new Error("Browser engine unavailable"); } },
    sitePolicy,
    pageOrigin,
    renderReview,
    renderError,
  });
  document.addEventListener("paste", (event) => { controller.handlePaste(event); }, true);
})();
