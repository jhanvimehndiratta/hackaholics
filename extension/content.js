(() => {
  const ALLOWED_ACTIONS = new Set(["health", "analyze", "redact", "audit", "getAudit", "exportAudit"]);

  // Message bridge for Sentinel Demo Client
  window.addEventListener("sentinel:request", (event) => {
    const detail = event.detail;
    if (!detail || typeof detail.requestId !== "string" || !ALLOWED_ACTIONS.has(detail.action)) {
      return;
    }

    chrome.runtime.sendMessage(
      {
        source: "sentinel-demo",
        action: detail.action,
        payload: detail.payload || {},
      },
      (response) => {
        const error = chrome.runtime.lastError?.message;
        window.dispatchEvent(
          new CustomEvent("sentinel:response", {
            detail: {
              requestId: detail.requestId,
              payload: response?.payload,
              error: error || response?.error,
            },
          })
        );
      }
    );
  });

  window.addEventListener("sentinel:before-send", (event) => {
    event.preventDefault();
  });

  // Helper to send messages to background script
  function callEngine(action, payload = {}) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(
        {
          source: "sentinel-demo",
          action,
          payload,
        },
        (response) => {
          const error = chrome.runtime.lastError?.message;
          if (error || !response?.ok) {
            reject(new Error(error || response?.error || "Failed to communicate with local engine"));
          } else {
            resolve(response.payload);
          }
        }
      );
    });
  }

  // --- Paste Firewall Implementation ---

  function isSupportedInput(target) {
    if (!target || !(target instanceof HTMLElement)) return false;
    if (target.isContentEditable) return true;
    if (target.tagName === "TEXTAREA") return true;
    if (target.tagName === "INPUT") {
      const type = (target.getAttribute("type") || "text").toLowerCase();
      return type === "text" || type === "search" || type === "url" || type === "email";
    }
    return false;
  }

  function insertTextAtCaret(target, text) {
    if (!target) return;
    target.focus();

    if (target.isContentEditable) {
      const selection = window.getSelection();
      if (selection && selection.rangeCount > 0) {
        const range = selection.getRangeAt(0);
        range.deleteContents();
        const textNode = document.createTextNode(text);
        range.insertNode(textNode);
        range.setStartAfter(textNode);
        range.setEndAfter(textNode);
        selection.removeAllRanges();
        selection.addRange(range);
        target.dispatchEvent(new Event("input", { bubbles: true }));
      }
    } else if (typeof target.selectionStart === "number" && typeof target.selectionEnd === "number") {
      const start = target.selectionStart;
      const end = target.selectionEnd;
      const original = target.value;
      target.value = original.slice(0, start) + text + original.slice(end);
      const newPos = start + text.length;
      target.setSelectionRange(newPos, newPos);
      target.dispatchEvent(new Event("input", { bubbles: true }));
      target.dispatchEvent(new Event("change", { bubbles: true }));
    }
  }

  function removeExistingOverlay() {
    const existing = document.getElementById("sentinel-paste-overlay");
    if (existing) existing.remove();
  }

  function createOverlay(target, originalText, analysis) {
    removeExistingOverlay();

    const overlay = document.createElement("div");
    overlay.id = "sentinel-paste-overlay";
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-label", "Sentinel Paste Firewall Review");

    const findingCount = analysis.findings.length;

    // Apply inline style encapsulation
    overlay.style.cssText = `
      position: fixed;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      z-index: 2147483647;
      width: min(520px, 92vw);
      max-height: 85vh;
      overflow-y: auto;
      background: #11161d;
      border: 1px solid rgba(245, 158, 11, 0.4);
      border-radius: 12px;
      box-shadow: 0 20px 48px rgba(0, 0, 0, 0.7), 0 0 0 1px rgba(255, 255, 255, 0.05);
      color: #e2e8f0;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 16px;
      box-sizing: border-box;
      backdrop-filter: blur(12px);
    `;

    // Header
    const header = document.createElement("div");
    header.style.cssText = "display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid rgba(255, 255, 255, 0.08); padding-bottom: 12px;";

    const titleContainer = document.createElement("div");
    titleContainer.style.cssText = "display: flex; align-items: center; gap: 8px;";

    const badge = document.createElement("span");
    badge.textContent = "FIREWALL";
    badge.style.cssText = "background: rgba(245, 158, 11, 0.2); color: #fbbf24; font-size: 10px; font-weight: 700; padding: 2px 6px; border-radius: 4px; letter-spacing: 0.5px;";

    const title = document.createElement("strong");
    title.textContent = "Paste Review Required";
    title.style.cssText = "font-size: 15px; color: #f8fafc;";

    titleContainer.append(badge, title);

    const countBadge = document.createElement("span");
    countBadge.textContent = `${findingCount} finding${findingCount === 1 ? "" : "s"}`;
    countBadge.style.cssText = "font-size: 12px; color: #94a3b8; font-weight: 500;";

    header.append(titleContainer, countBadge);

    // Description
    const desc = document.createElement("p");
    desc.textContent = "Sentinel detected sensitive credentials or private network identifiers in your clipboard. Choose how to proceed:";
    desc.style.cssText = "margin: 0; font-size: 13px; color: #94a3b8; line-height: 1.5;";

    // Findings List
    const listContainer = document.createElement("div");
    listContainer.style.cssText = "display: flex; flex-direction: column; gap: 8px; max-height: 240px; overflow-y: auto; padding-right: 4px;";

    const checkboxes = [];
    analysis.findings.forEach((finding) => {
      const item = document.createElement("label");
      item.style.cssText = `
        display: flex;
        align-items: flex-start;
        gap: 10px;
        background: rgba(255, 255, 255, 0.03);
        border: 1px solid rgba(255, 255, 255, 0.06);
        border-radius: 8px;
        padding: 10px;
        cursor: pointer;
        font-size: 12px;
      `;

      const chk = document.createElement("input");
      chk.type = "checkbox";
      chk.checked = true;
      chk.value = finding.id;
      chk.style.cssText = "margin-top: 2px; accent-color: #38bdf8;";
      checkboxes.push(chk);

      const info = document.createElement("div");
      info.style.cssText = "display: flex; flex-direction: column; gap: 4px; width: 100%;";

      const top = document.createElement("div");
      top.style.cssText = "display: flex; justify-content: space-between; align-items: center;";

      const typeSpan = document.createElement("span");
      typeSpan.textContent = finding.type.replace(/_/g, " ");
      typeSpan.style.cssText = "font-weight: 600; text-transform: capitalize; color: #f1f5f9;";

      const sevSpan = document.createElement("span");
      sevSpan.textContent = finding.severity;
      sevSpan.style.cssText = "font-size: 10px; color: #fbbf24; text-transform: uppercase; font-weight: 600;";

      top.append(typeSpan, sevSpan);

      const preview = document.createElement("code");
      preview.textContent = `${finding.safePreview} → ${finding.replacement}`;
      preview.style.cssText = "background: rgba(0, 0, 0, 0.3); padding: 3px 6px; border-radius: 4px; color: #38bdf8; font-family: monospace; font-size: 11px; word-break: break-all;";

      info.append(top, preview);
      item.append(chk, info);
      listContainer.append(item);
    });

    // Action Buttons
    const actions = document.createElement("div");
    actions.style.cssText = "display: flex; flex-wrap: wrap; gap: 8px; justify-content: flex-end; border-top: 1px solid rgba(255, 255, 255, 0.08); padding-top: 14px;";

    const blockBtn = document.createElement("button");
    blockBtn.textContent = "Block Paste";
    blockBtn.style.cssText = "padding: 8px 14px; background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 6px; font-weight: 600; font-size: 12px; cursor: pointer;";

    const allowOnceBtn = document.createElement("button");
    allowOnceBtn.textContent = "Paste Once";
    allowOnceBtn.style.cssText = "padding: 8px 14px; background: rgba(255, 255, 255, 0.05); color: #cbd5e1; border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 6px; font-weight: 500; font-size: 12px; cursor: pointer;";

    const redactBtn = document.createElement("button");
    redactBtn.textContent = "Redact & Paste";
    redactBtn.style.cssText = "padding: 8px 16px; background: #0284c7; color: #ffffff; border: none; border-radius: 6px; font-weight: 600; font-size: 12px; cursor: pointer; box-shadow: 0 2px 8px rgba(2, 132, 199, 0.4);";

    // Event Handlers
    blockBtn.addEventListener("click", async () => {
      overlay.remove();
      try {
        const findingTypes = [...new Set(analysis.findings.map((f) => f.type))];
        await callEngine("audit", {
          decision: "block",
          findingTypes,
          sent: false,
        });
      } catch (err) {
        console.warn("Sentinel audit error:", err);
      }
    });

    allowOnceBtn.addEventListener("click", async () => {
      overlay.remove();
      insertTextAtCaret(target, originalText);
      try {
        const findingTypes = [...new Set(analysis.findings.map((f) => f.type))];
        await callEngine("audit", {
          decision: "paste_once",
          findingTypes,
          sent: true,
        });
      } catch (err) {
        console.warn("Sentinel audit error:", err);
      }
    });

    redactBtn.addEventListener("click", async () => {
      const selectedFindingIds = checkboxes.filter((c) => c.checked).map((c) => c.value);
      if (selectedFindingIds.length === 0) {
        alert("Please select at least one finding to redact, or choose 'Paste Once' / 'Block'.");
        return;
      }
      overlay.remove();
      try {
        const redactResult = await callEngine("redact", {
          text: originalText,
          findingIds: selectedFindingIds,
        });
        insertTextAtCaret(target, redactResult.redactedText);
        const redactedFindings = analysis.findings.filter((f) => selectedFindingIds.includes(f.id));
        const findingTypes = [...new Set(redactedFindings.map((f) => f.type))];
        await callEngine("audit", {
          decision: "redact_paste",
          findingTypes,
          sent: true,
        });
      } catch (err) {
        console.error("Sentinel redaction failed:", err);
        alert(`Sentinel redaction failed: ${err.message}`);
      }
    });

    actions.append(blockBtn, allowOnceBtn, redactBtn);
    overlay.append(header, desc, listContainer, actions);

    // Backdrop for click-away blocking
    const backdrop = document.createElement("div");
    backdrop.id = "sentinel-paste-backdrop";
    backdrop.style.cssText = "position: fixed; inset: 0; background: rgba(0, 0, 0, 0.4); z-index: 2147483646;";
    backdrop.addEventListener("click", () => {
      overlay.remove();
      backdrop.remove();
    });

    overlay.appendChild(backdrop);
    document.body.appendChild(overlay);
  }

  // Intercept Paste events
  document.addEventListener(
    "paste",
    async (event) => {
      const target = event.target;
      if (!isSupportedInput(target)) return;

      const clipboardData = event.clipboardData || window.clipboardData;
      if (!clipboardData) return;

      const pastedText = clipboardData.getData("text/plain");
      if (!pastedText || pastedText.trim().length === 0) return;

      // Prevent immediate paste until inspected
      event.preventDefault();
      event.stopImmediatePropagation();

      try {
        const analysis = await callEngine("analyze", { text: pastedText });
        if (!analysis || analysis.decision === "allow" || !analysis.findings || analysis.findings.length === 0) {
          // Safe to insert immediately
          insertTextAtCaret(target, pastedText);
        } else {
          // Trigger interactive decision overlay
          createOverlay(target, pastedText, analysis);
        }
      } catch (error) {
        console.warn("Sentinel Paste Firewall inspection failed, permitting local paste:", error);
        insertTextAtCaret(target, pastedText);
      }
    },
    true
  );
})();

