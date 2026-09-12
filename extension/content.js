(() => {
  const ALLOWED_ACTIONS = new Set(["health", "analyze", "redact", "audit", "getAudit"]);

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
})();
