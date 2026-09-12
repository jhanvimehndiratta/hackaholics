const ENGINE = "http://127.0.0.1:8787";

const routes = {
  health: { path: "/health", method: "GET" },
  analyze: { path: "/analyze", method: "POST" },
  redact: { path: "/redact", method: "POST" },
  audit: { path: "/audit", method: "POST" },
  getAudit: { path: "/audit", method: "GET" },
  exportAudit: { path: "/audit/export", method: "GET" },
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.source !== "sentinel-demo" || !routes[message.action]) return false;

  const route = routes[message.action];
  const options = {
    method: route.method,
    headers: { "Content-Type": "application/json" },
    cache: "no-store",
  };
  if (route.method === "POST") options.body = JSON.stringify(message.payload || {});

  fetch(`${ENGINE}${route.path}`, options)
    .then(async (response) => {
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(payload.detail || `Local engine returned ${response.status}`);
      }
      sendResponse({ ok: true, payload });
    })
    .catch((error) => {
      sendResponse({
        ok: false,
        error: `Sentinel could not reach its local engine at ${ENGINE}. ${error.message}`,
      });
    });

  return true;
});
