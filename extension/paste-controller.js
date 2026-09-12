(function (root) {
  "use strict";

  function editableTarget(node) {
    const original = node;
    let current = node?.nodeType === 3 ? node.parentElement || node.parentNode : node;
    while (current) {
      if (current.isContentEditable) return current;
      current = current.parentElement || current.parentNode;
    }
    return original;
  }

  function isSupportedInput(node) {
    const target = editableTarget(node);
    if (!target) return false;
    if (target.isContentEditable) return true;
    const tag = String(target.tagName || "").toUpperCase();
    if (tag === "TEXTAREA") return true;
    if (tag !== "INPUT") return false;
    return ["text", "search", "url", "email"].includes(String(target.type || target.getAttribute?.("type") || "text").toLowerCase());
  }

  function captureSelection(node, selectionProvider) {
    const target = editableTarget(node);
    if (!isSupportedInput(target)) return null;
    if (!target.isContentEditable) return { kind: "control", target, start: target.selectionStart, end: target.selectionEnd };
    const selection = selectionProvider();
    if (!selection || !selection.rangeCount) return null;
    return { kind: "contenteditable", target, range: selection.getRangeAt(0).cloneRange() };
  }

  function setControlValue(target, value) {
    const view = target.ownerDocument?.defaultView;
    const tag = String(target.tagName || "").toUpperCase();
    const prototype = tag === "TEXTAREA" ? view?.HTMLTextAreaElement?.prototype : view?.HTMLInputElement?.prototype;
    const setter = prototype && Object.getOwnPropertyDescriptor(prototype, "value")?.set;
    if (setter) setter.call(target, value);
    else target.value = value;
  }

  function restoreAndInsert(snapshot, text, selectionProvider) {
    if (!snapshot || snapshot.target.isConnected === false) throw new Error("The editable selection is no longer available. Paste was blocked.");
    const target = snapshot.target;
    target.focus?.();
    if (snapshot.kind === "control") {
      if (!Number.isInteger(snapshot.start) || !Number.isInteger(snapshot.end)) throw new Error("The text selection is unavailable. Paste was blocked.");
      const original = String(target.value || "");
      setControlValue(target, original.slice(0, snapshot.start) + text + original.slice(snapshot.end));
      const caret = snapshot.start + text.length;
      target.setSelectionRange?.(caret, caret);
    } else {
      const range = snapshot.range;
      if (!range) throw new Error("The editable selection is unavailable. Paste was blocked.");
      range.deleteContents();
      const textNode = target.ownerDocument.createTextNode(text);
      range.insertNode(textNode);
      range.setStartAfter(textNode); range.collapse(true);
      const selection = selectionProvider();
      selection.removeAllRanges(); selection.addRange(range);
    }
    const EventConstructor = target.ownerDocument?.defaultView?.InputEvent || root.InputEvent || root.Event;
    target.dispatchEvent?.(new EventConstructor("input", { bubbles: true, composed: true, inputType: "insertFromPaste", data: text }));
  }

  function createController({ engine, sitePolicy, pageOrigin, renderReview, renderError, selectionProvider = () => root.getSelection() }) {
    async function handlePaste(event, policy = "balanced") {
      if (!isSupportedInput(event.target)) return { intercepted: false };
      const text = event.clipboardData?.getData("text/plain");
      if (!text) return { intercepted: false };
      event.preventDefault();
      event.stopImmediatePropagation();
      const snapshot = captureSelection(event.target, selectionProvider);
      if (!snapshot) { renderError("Sentinel could not preserve the current selection. Paste remained blocked."); return { intercepted: true, blocked: true }; }
      try {
        if (sitePolicy) {
          if (!pageOrigin) throw new Error("Unsupported page origin");
          const paused = await Promise.resolve(sitePolicy.isPaused(pageOrigin));
          if (typeof paused !== "boolean") throw new Error("Invalid site policy response");
          if (paused) {
            restoreAndInsert(snapshot, text, selectionProvider);
            return { intercepted: true, inserted: true, decision: "site_paused" };
          }
        }
        const analysis = await Promise.resolve(engine.analyzeText(text, policy));
        if (!analysis || !Array.isArray(analysis.findings)) throw new Error("Invalid analysis response");
        if (analysis.decision === "allow" && analysis.findings.length === 0) {
          restoreAndInsert(snapshot, text, selectionProvider);
          return { intercepted: true, inserted: true, decision: "allow" };
        }
        const actions = {
          block() { return { decision: "block", inserted: false }; },
          redact(findingIds) { const result = engine.redactText(text, findingIds, policy); restoreAndInsert(snapshot, result.redactedText, selectionProvider); return { decision: "redact_paste", inserted: true, result }; },
          allowOnce() { restoreAndInsert(snapshot, text, selectionProvider); return { decision: "paste_once", inserted: true }; },
        };
        renderReview({ findings: analysis.findings, actions });
        return { intercepted: true, review: true };
      } catch (error) {
        renderError(`Sentinel analysis failed. Paste remained blocked. ${error.message}`);
        return { intercepted: true, blocked: true, error };
      }
    }
    return { handlePaste };
  }

  root.SentinelPaste = Object.freeze({ editableTarget, isSupportedInput, captureSelection, restoreAndInsert, createController });
})(typeof globalThis !== "undefined" ? globalThis : window);
