const samples = {
  safe: "How should I structure retries in a small Python service?",
  sensitive:
    "Review this deployment: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE, DB_PASSWORD=Summer2026!, database postgres://service:hunter2@10.24.3.8/prod, internal host 192.168.1.42, and notify owner@example.com.",
  entropy:
    "Deploy service cluster with auth token=8sF3mQ9vL2xK7pR4nT6wY1zB5cD0hJ8u to staging gateway.",
  ambiguous:
    "The build artifact 550e8400e29b41d4a716446655440000 failed validation. What should I inspect next?",
};

const findingCopy = {
  aws_access_key: ["AWS access key", "Credential-shaped value matched an AWS access-key rule."],
  github_token: ["GitHub token", "Token prefix and length match a GitHub credential format."],
  api_key: ["API credential", "A named API key assignment contains a credential-shaped value."],
  database_url: ["Database credential", "This connection URL includes a username and password."],
  password: ["Password", "A named password field contains a value that should not leave this device."],
  email: ["Email address", "A personal contact address appears in the prompt."],
  internal_ip: ["Internal IP address", "This address is inside an RFC1918 private network range."],
  suspected_secret: ["Suspected secret (Entropy ≥ 3.5)", "A high-entropy token appears in a named secret context under Strict policy."],
};

const form = document.querySelector("#prompt-form");
const input = document.querySelector("#prompt-input");
const sendButton = document.querySelector("#send-button");
const composeBox = document.querySelector("#compose-box");
const scanLine = document.querySelector("#scan-line");
const formStatus = document.querySelector("#form-status");
const checkpointTitle = document.querySelector("#checkpoint-title");
const idleState = document.querySelector("#checkpoint-idle");
const reviewState = document.querySelector("#review-state");
const outcomeState = document.querySelector("#outcome-state");
const findingList = document.querySelector("#finding-list");
const findingCount = document.querySelector("#finding-count");
const reviewPolicyName = document.querySelector("#review-policy-name");
const livePreviewText = document.querySelector("#live-preview-text");
const messageStream = document.querySelector("#message-stream");
const emptyConversation = document.querySelector("#empty-conversation");
const activityList = document.querySelector("#activity-list");
const engineState = document.querySelector(".engine-state");
const engineLabel = document.querySelector("#engine-label");
const activePolicyIndicator = document.querySelector("#active-policy-indicator");
const factEntropy = document.querySelector("#fact-entropy");
const policyBalancedBtn = document.querySelector("#policy-balanced-btn");
const policyStrictBtn = document.querySelector("#policy-strict-btn");
const exportJsonBtn = document.querySelector("#export-json-btn");
const exportMdBtn = document.querySelector("#export-md-btn");
const pasteTestInput = document.querySelector("#paste-test-input");

let currentPolicy = "balanced";
let pending = null;
let activity = [];
const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

function dispatchRequest(detail) {
  return new Promise((resolve, reject) => {
    const requestId = crypto.randomUUID();
    const timeout = window.setTimeout(() => {
      window.removeEventListener("sentinel:response", onResponse);
      reject(new Error("Sentinel extension did not respond. Load the unpacked extension and retry."));
    }, 1500);

    function onResponse(event) {
      if (event.detail?.requestId !== requestId) return;
      window.clearTimeout(timeout);
      window.removeEventListener("sentinel:response", onResponse);
      if (event.detail.error) reject(new Error(event.detail.error));
      else resolve(event.detail.payload);
    }

    window.addEventListener("sentinel:response", onResponse);
    window.dispatchEvent(new CustomEvent("sentinel:request", { detail: { ...detail, requestId } }));
  });
}

async function engineRequest(action, payload = {}) {
  return dispatchRequest({ action, payload });
}

function setPolicy(policy) {
  currentPolicy = policy;
  policyBalancedBtn.classList.toggle("is-active", policy === "balanced");
  policyBalancedBtn.setAttribute("aria-checked", policy === "balanced" ? "true" : "false");
  policyStrictBtn.classList.toggle("is-active", policy === "strict");
  policyStrictBtn.setAttribute("aria-checked", policy === "strict" ? "true" : "false");

  if (activePolicyIndicator) {
    activePolicyIndicator.textContent = `Policy: ${policy === "strict" ? "Strict (Entropy ≥ 3.5)" : "Balanced"}`;
  }
  if (factEntropy) {
    factEntropy.textContent = policy === "strict" ? "Active (H ≥ 3.5)" : "Disabled in Balanced";
  }
  if (reviewPolicyName) {
    reviewPolicyName.textContent = policy;
  }
  resetCheckpoint(false);
}

function setSample(name) {
  input.value = samples[name] || "";
  document.querySelectorAll(".sample-button").forEach((button) => {
    button.classList.toggle("is-active", button.dataset.sample === name);
  });
  resetCheckpoint(false);
}

function setEngineStatus(status, label) {
  if (engineState) engineState.dataset.engineState = status;
  if (engineLabel) engineLabel.textContent = label;
}

async function checkEngine() {
  try {
    await engineRequest("health");
    setEngineStatus("online", "Local engine connected");
  } catch {
    setEngineStatus("offline", "Load extension + engine");
  }
}

function computeClientRedactionPreview(text, findings, selectedIds) {
  const selectedFindings = findings
    .filter((f) => selectedIds.includes(f.id))
    .sort((a, b) => b.range.start - a.range.start);

  let result = text;
  for (const finding of selectedFindings) {
    const { start, end } = finding.range;
    result = result.slice(0, start) + finding.replacement + result.slice(end);
  }
  return result;
}

function updateLivePreview() {
  if (!pending || !livePreviewText) return;
  const selectedIds = [...findingList.querySelectorAll("input:checked")].map((c) => c.value);
  const preview = computeClientRedactionPreview(pending.text, pending.findings, selectedIds);
  livePreviewText.textContent = preview;
}

function renderFindings(findings) {
  findingCount.textContent = `${findings.length} finding${findings.length === 1 ? "" : "s"}`;
  findingList.replaceChildren(
    ...findings.map((finding) => {
      const label = document.createElement("label");
      label.className = "finding-row";
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.checked = true;
      checkbox.value = finding.id;
      checkbox.addEventListener("change", updateLivePreview);

      const copy = document.createElement("span");
      copy.className = "finding-copy";
      const [name, explanation] = findingCopy[finding.type] || [finding.type, "A local rule marked this value for review."];
      const top = document.createElement("span");
      top.className = "finding-topline";
      const title = document.createElement("span");
      title.className = "finding-name";
      title.textContent = name;
      const severity = document.createElement("span");
      severity.className = `severity ${finding.severity.toLowerCase()}`;
      severity.textContent = finding.severity;
      top.append(title, severity);

      const detail = document.createElement("p");
      detail.textContent = explanation;

      const preview = document.createElement("code");
      preview.textContent = `${finding.safePreview} → ${finding.replacement}`;

      copy.append(top, detail, preview);
      label.append(checkbox, copy);
      return label;
    })
  );
  updateLivePreview();
}

function showReview(analysis) {
  pending = { text: input.value, findings: analysis.findings };
  if (reviewPolicyName) reviewPolicyName.textContent = currentPolicy;
  renderFindings(analysis.findings);
  idleState.hidden = true;
  outcomeState.hidden = true;
  reviewState.hidden = false;
  checkpointTitle.textContent = "Prompt paused locally";
  composeBox.classList.add("is-paused");
  sendButton.disabled = false;

  if (!reduceMotion) {
    reviewState.animate(
      [{ opacity: 0, transform: "translateX(12px)" }, { opacity: 1, transform: "translateX(0)" }],
      { duration: 320, easing: "cubic-bezier(.2,.8,.2,1)" }
    );
  }
}

function playIntercept(complete) {
  if (reduceMotion) {
    complete();
    return;
  }
  composeBox.animate(
    [{ transform: "translateY(0)" }, { transform: "translateY(-4px)" }, { transform: "translateY(0)" }],
    { duration: 520, easing: "cubic-bezier(.2,.8,.2,1)" }
  );
  const scan = scanLine.animate(
    [
      { opacity: 0, transform: "translateY(0)" },
      { opacity: 1, offset: 0.12 },
      { opacity: 1, transform: `translateY(${composeBox.offsetHeight - 2}px)`, offset: 0.82 },
      { opacity: 0 },
    ],
    { duration: 520, easing: "cubic-bezier(.45,0,.55,1)" }
  );
  scan.addEventListener("finish", complete, { once: true });
}

function addMessage(text, mode) {
  emptyConversation.hidden = true;
  const article = document.createElement("article");
  article.className = "message";
  const label = document.createElement("span");
  label.textContent = mode;
  const content = document.createElement("p");
  content.textContent = text;
  const meta = document.createElement("small");
  meta.textContent = `Simulated send • Policy: ${currentPolicy} • Zero Cloud Telemetry`;
  article.append(label, content, meta);
  messageStream.append(article);
  article.scrollIntoView({ behavior: reduceMotion ? "auto" : "smooth", block: "end" });
}

function addActivity(decision, categories, sent) {
  activity.unshift({ decision, categories, sent, policy: currentPolicy, time: new Date() });
  activityList.replaceChildren(
    ...activity.slice(0, 8).map((event) => {
      const item = document.createElement("li");
      const title = document.createElement("strong");
      title.textContent = event.decision;
      const detail = document.createTextNode(
        ` [${event.policy}] • ${event.sent ? "Sent" : "Not sent"} • ${event.categories.length ? event.categories.join(", ") : "No findings"} • ${event.time.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`
      );
      item.append(title, detail);
      return item;
    })
  );
}

async function audit(decision, findings, sent) {
  const findingTypes = [...new Set(findings.map((finding) => finding.type))];
  addActivity(decision.replaceAll("_", " "), findingTypes, sent);
  try {
    await engineRequest("audit", { decision, findingTypes, sent, policy: currentPolicy });
  } catch {
    // The visible session timeline remains sanitized even if persistence is unavailable.
  }
}

function showOutcome(kind, title, copy) {
  reviewState.hidden = true;
  idleState.hidden = true;
  outcomeState.hidden = false;
  outcomeState.dataset.outcome = kind;
  document.querySelector("#outcome-title").textContent = title;
  document.querySelector("#outcome-copy").textContent = copy;
  checkpointTitle.textContent = title;
  composeBox.classList.remove("is-paused");
  sendButton.disabled = false;
}

function resetCheckpoint(clearPending = true) {
  if (clearPending) pending = null;
  reviewState.hidden = true;
  outcomeState.hidden = true;
  idleState.hidden = false;
  checkpointTitle.textContent = "Ready to inspect";
  composeBox.classList.remove("is-paused");
  formStatus.textContent = "";
  sendButton.disabled = false;
}

async function submitPrompt() {
  const text = input.value.trim();
  if (!text) {
    formStatus.textContent = "Enter a prompt before sending.";
    return;
  }
  formStatus.textContent = "";
  sendButton.disabled = true;
  try {
    const analysis = await engineRequest("analyze", { text, policy: currentPolicy });
    playIntercept(async () => {
      if (analysis.decision === "allow") {
        addMessage(text, "Sent after local check");
        await audit("allow", [], true);
        showOutcome("sent", "Sent after local check", `No sensitive values matched under ${currentPolicy} policy.`);
      } else {
        showReview(analysis);
      }
    });
  } catch (error) {
    sendButton.disabled = false;
    formStatus.textContent = error.message;
    setEngineStatus("offline", "Local engine unavailable");
  }
}

function downloadFile(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// Export Audit Logs
if (exportJsonBtn) {
  exportJsonBtn.addEventListener("click", async () => {
    try {
      const res = await engineRequest("exportAudit", { format: "json" });
      const dataStr = typeof res === "string" ? res : JSON.stringify(res, null, 2);
      downloadFile(`sentinel_audit_${Date.now()}.json`, dataStr, "application/json");
    } catch {
      // Fallback to local activity log if engine endpoint is unreachable
      const localData = JSON.stringify({ auditLog: activity, exportedAt: new Date().toISOString() }, null, 2);
      downloadFile(`sentinel_audit_local_${Date.now()}.json`, localData, "application/json");
    }
  });
}

if (exportMdBtn) {
  exportMdBtn.addEventListener("click", async () => {
    try {
      const res = await engineRequest("exportAudit", { format: "markdown" });
      const mdStr = typeof res === "string" ? res : JSON.stringify(res);
      downloadFile(`sentinel_audit_${Date.now()}.md`, mdStr, "text/markdown");
    } catch {
      // Fallback to local markdown table
      let md = `# Sentinel Local Session Audit\n\n`;
      md += `| Timestamp | Policy | Decision | Sent | Categories |\n`;
      md += `|---|---|---|---|---|\n`;
      activity.forEach((ev) => {
        md += `| ${ev.time.toISOString()} | ${ev.policy} | ${ev.decision} | ${ev.sent} | ${ev.categories.join(", ") || "None"} |\n`;
      });
      downloadFile(`sentinel_audit_local_${Date.now()}.md`, md, "text/markdown");
    }
  });
}

// Policy buttons
if (policyBalancedBtn) policyBalancedBtn.addEventListener("click", () => setPolicy("balanced"));
if (policyStrictBtn) policyStrictBtn.addEventListener("click", () => setPolicy("strict"));

form.addEventListener("submit", (event) => {
  event.preventDefault();
  const interception = new CustomEvent("sentinel:before-send", { cancelable: true, detail: { text: input.value } });
  window.dispatchEvent(interception);
  submitPrompt();
});

document.querySelectorAll(".sample-button").forEach((button) => {
  button.addEventListener("click", () => setSample(button.dataset.sample));
});

document.querySelector("#block-button").addEventListener("click", async () => {
  if (!pending) return;
  await audit("block", pending.findings, false);
  showOutcome("blocked", "Blocked locally", "The original prompt did not cross into the simulated workspace.");
  pending = null;
});

document.querySelector("#allow-button").addEventListener("click", async () => {
  if (!pending) return;
  const current = pending;
  addMessage(current.text, "Allowed once");
  await audit("allow_once", current.findings, true);
  showOutcome("sent", "Allowed once", "The original prompt was sent for this interaction only. No bypass was saved.");
  pending = null;
});

document.querySelector("#redact-button").addEventListener("click", async () => {
  if (!pending) return;
  const ids = [...findingList.querySelectorAll("input:checked")].map((checkbox) => checkbox.value);
  if (!ids.length) {
    formStatus.textContent = "Select at least one finding to redact, or choose another action.";
    return;
  }
  try {
    const result = await engineRequest("redact", { text: pending.text, findingIds: ids, policy: currentPolicy });
    addMessage(result.redactedText, "Redacted locally");
    await audit("redact_send", pending.findings.filter((finding) => ids.includes(finding.id)), true);
    showOutcome("sent", "Redacted message sent", `${ids.length} sensitive value${ids.length === 1 ? " was" : "s were"} replaced before the simulated send.`);
    pending = null;
  } catch (error) {
    formStatus.textContent = error.message;
  }
});

document.querySelector("#reset-button").addEventListener("click", () => resetCheckpoint());

setSample("sensitive");
checkEngine();
