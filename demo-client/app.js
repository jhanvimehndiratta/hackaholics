const samples = {
  safe: "How should I structure retries in a small Python service?",
  sensitive:
    "Review this deployment: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE, DB_PASSWORD=Summer2026!, database postgres://service:hunter2@10.24.3.8/prod, internal host 192.168.1.42, and notify owner@example.com.",
  entropy:
    "Deploy service cluster with auth token=8sF3mQ9vL2xK7pR4nT6wY1zB5cD0hJ8u to staging gateway.",
  ambiguous:
    "The build artifact 550e8400e29b41d4a716446655440000 failed validation. What should I inspect next?",
};

const form = document.querySelector("#prompt-form");
const input = document.querySelector("#prompt-input");
const sendButton = document.querySelector("#send-button");
const formStatus = document.querySelector("#form-status");
const statusLine = document.querySelector("#status-line");
const reviewPolicyName = document.querySelector("#review-policy-name");
const findingCount = document.querySelector("#finding-count");
const livePreviewText = document.querySelector("#live-preview-text");
const checkpointTitle = document.querySelector("#checkpoint-title");
const idleState = document.querySelector("#state-idle");
const analyzingState = document.querySelector("#state-analyzing");
const reviewState = document.querySelector("#state-review");
const outcomeState = document.querySelector("#state-outcome");
const offlineState = document.querySelector("#state-offline");
const findingList = document.querySelector("#finding-list");
const outcomeTitle = document.querySelector("#outcome-title");
const outcomeCopy = document.querySelector("#outcome-copy");
const clipboardStatus = document.querySelector("#clipboard-status");
const copyButton = document.querySelector("#copy-button");
const resetButton = document.querySelector("#reset-button");
const redactButton = document.querySelector("#redact-button");
const blockButton = document.querySelector("#block-button");
const allowButton = document.querySelector("#allow-button");
const policyBalancedBtn = document.querySelector("#policy-balanced-btn");
const policyStrictBtn = document.querySelector("#policy-strict-btn");

let currentPolicy = "balanced";
let pending = null;
let lastSample = null;
let clipboardText = "";

async function engineRequest(action, payload = {}) {
  const engine = globalThis.SentinelEngine;
  if (!engine) throw new Error("The on-device browser engine failed to initialize.");
  if (action === "health") return { status: "local", service: "sentinel-browser-engine" };
  if (action === "analyze") return engine.analyzeText(payload.text, payload.policy);
  if (action === "redact") return engine.redactText(payload.text, payload.findingIds, payload.policy);
  throw new Error(`Unsupported browser-engine action: ${action}`);
}

function setState(state) {
  const states = {
    idle: idleState,
    analyzing: analyzingState,
    review: reviewState,
    outcome: outcomeState,
    offline: offlineState,
  };

  for (const [name, element] of Object.entries(states)) {
    if (element) element.hidden = name !== state;
  }

  if (state === "idle" && statusLine) statusLine.textContent = "Ready for local inspection.";
}

function setEngineStatus(status, label) {
  const badge = document.querySelector("#engine-status-badge");
  const engineLabel = document.querySelector("#engine-label");
  if (badge) badge.dataset.engineState = status;
  if (engineLabel) engineLabel.textContent = label;
}

function setFormStatus(message) {
  if (formStatus) formStatus.textContent = message;
}

function setClipboardResult(text, message = "") {
  clipboardText = text || "";
  if (copyButton) copyButton.disabled = !clipboardText;
  if (clipboardStatus) clipboardStatus.textContent = message;
}

async function writeClipboard(text) {
  setClipboardResult(text);

  if (!text || !navigator.clipboard?.writeText) {
    setClipboardResult(text, "Clipboard access failed — use Copy manually.");
    return false;
  }

  try {
    await navigator.clipboard.writeText(text);
    setClipboardResult(text, "Copied to clipboard");
    return true;
  } catch {
    setClipboardResult(text, "Clipboard access failed — use Copy manually.");
    return false;
  }
}

function setPolicy(policy) {
  currentPolicy = policy;
  if (policyBalancedBtn) policyBalancedBtn.setAttribute("aria-pressed", String(policy === "balanced"));
  if (policyStrictBtn) policyStrictBtn.setAttribute("aria-pressed", String(policy === "strict"));
}

function computePreview(text, findings, selectedIds) {
  const selectedFindings = findings
    .filter((finding) => selectedIds.includes(finding.id))
    .sort((a, b) => b.range.start - a.range.start);

  let result = text;
  for (const finding of selectedFindings) {
    const { start, end } = finding.range;
    result = result.slice(0, start) + finding.replacement + result.slice(end);
  }
  return result;
}

function renderFindings(findings) {
  if (!findingList) return;

  findingList.replaceChildren(
    ...findings.map((finding) => {
      const row = document.createElement("div");
      row.className = "finding-row";
      row.setAttribute("role", "row");

      const rule = document.createElement("div");
      rule.className = "finding-cell finding-rule";
      rule.setAttribute("role", "cell");
      rule.textContent = finding.type;

      const evidence = document.createElement("div");
      evidence.className = "finding-cell finding-evidence";
      evidence.setAttribute("role", "cell");
      const code = document.createElement("code");
      code.textContent = finding.safePreview;
      evidence.appendChild(code);

      const severity = document.createElement("div");
      severity.className = "finding-cell finding-severity";
      severity.setAttribute("role", "cell");
      severity.textContent = finding.severity;

      const action = document.createElement("div");
      action.className = "finding-cell finding-action";
      action.setAttribute("role", "cell");
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.checked = true;
      checkbox.value = finding.id;
      checkbox.setAttribute("aria-label", `Redact ${finding.type}`);
      checkbox.addEventListener("change", updatePreview);
      action.appendChild(checkbox);

      row.append(rule, evidence, severity, action);
      return row;
    })
  );
}

function getSelectedFindingIds() {
  if (!findingList) return [];
  return [...findingList.querySelectorAll('input[type="checkbox"]:checked')].map(
    (checkbox) => checkbox.value
  );
}

function updatePreview() {
  if (!pending || !livePreviewText) return;
  livePreviewText.textContent = computePreview(
    pending.text,
    pending.findings,
    getSelectedFindingIds()
  );
}

function showOutcome(title, copy) {
  if (outcomeTitle) outcomeTitle.textContent = title;
  if (outcomeCopy) outcomeCopy.textContent = copy;
  setState("outcome");
}

function showReview(analysis, text) {
  pending = { text, findings: analysis.findings };
  if (checkpointTitle) checkpointTitle.textContent = "Review required";
  if (reviewPolicyName) reviewPolicyName.textContent = currentPolicy;
  if (findingCount) {
    findingCount.textContent = `${analysis.findings.length} finding${
      analysis.findings.length === 1 ? "" : "s"
    }`;
  }
  renderFindings(analysis.findings);
  updatePreview();
  setState("review");
}

async function submitPrompt() {
  if (!input) return;
  const text = input.value.trim();
  if (!text) {
    setFormStatus("Paste text to inspect.");
    return;
  }

  setFormStatus("");
  setClipboardResult("");
  if (sendButton) sendButton.disabled = true;
  setState("analyzing");

  try {
    const analysis = await engineRequest("analyze", { text, policy: currentPolicy });
    if (analysis.decision === "allow") {
      pending = null;
      const copy =
        lastSample === "ambiguous"
          ? "Benign UUID false-positive test passed: zero findings."
          : `No sensitive values were detected under ${currentPolicy} policy.`;
      showOutcome("Original text allowed", copy);
    } else {
      showReview(analysis, text);
    }
  } catch (error) {
    setFormStatus(error.message);
    setState("offline");
  } finally {
    if (sendButton) sendButton.disabled = false;
  }
}

function handleBlock() {
  if (!pending) return;
  showOutcome("Blocked before insertion", "No text was inserted after local inspection.");
  setClipboardResult("");
  pending = null;
}

async function handleRedact() {
  if (!pending) return;
  const findingIds = getSelectedFindingIds();
  if (!findingIds.length) {
    setFormStatus("Select at least one finding to redact.");
    return;
  }

  try {
    const result = await engineRequest("redact", {
      text: pending.text,
      findingIds,
      policy: currentPolicy,
    });
    showOutcome(
      "Redacted locally",
      `${findingIds.length} sensitive value${findingIds.length === 1 ? " was" : "s were"} redacted.`
    );
    await writeClipboard(result.redactedText);
    setFormStatus(clipboardStatus?.textContent || "");
    pending = null;
  } catch (error) {
    setFormStatus(error.message);
  }
}

async function handleAllowOnce() {
  if (!pending) return;
  const originalText = pending.text;
  showOutcome("Allowed once", "Original text allowed for this inspection decision only.");
  await writeClipboard(originalText);
  setFormStatus(clipboardStatus?.textContent || "");
  pending = null;
}

function reset({ clearInput = true } = {}) {
  pending = null;
  lastSample = clearInput ? null : lastSample;
  if (clearInput && input) input.value = "";
  setFormStatus("");
  setClipboardResult("");
  if (findingList) findingList.replaceChildren();
  if (checkpointTitle) checkpointTitle.textContent = "Ready to inspect";
  setState("idle");
}

form?.addEventListener("submit", (event) => {
  event.preventDefault();
  submitPrompt();
});

if (!form) {
  sendButton?.addEventListener("click", (event) => {
    event.preventDefault();
    submitPrompt();
  });
}

redactButton?.addEventListener("click", handleRedact);
blockButton?.addEventListener("click", handleBlock);
allowButton?.addEventListener("click", handleAllowOnce);
resetButton?.addEventListener("click", () => reset());
copyButton?.addEventListener("click", () => writeClipboard(clipboardText));
policyBalancedBtn?.addEventListener("click", () => {
  setPolicy("balanced");
  reset();
});
policyStrictBtn?.addEventListener("click", () => {
  setPolicy("strict");
  reset();
});

document.querySelectorAll(".sample-button").forEach((button) => {
  button.addEventListener("click", () => {
    const sampleName = button.dataset.sample;
    lastSample = sampleName;
    setPolicy(sampleName === "entropy" ? "strict" : "balanced");
    if (input) input.value = samples[sampleName] || "";
    setState("idle");
  });
});

async function checkEngine() {
  try {
    await engineRequest("health");
    setEngineStatus("online", "On-device engine");
    setState("idle");
  } catch {
    setEngineStatus("offline", "Engine unavailable");
    setState("offline");
  }
}

setPolicy("balanced");
checkEngine();
