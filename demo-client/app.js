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
// Some legacy markup versions may not include all optional elements.
const input = document.querySelector("#prompt-input");
const sendButton = document.querySelector("#send-button");
const composeBox = document.querySelector("#compose-box");
const scanLine = document.querySelector("#scan-line");
const formStatus = document.querySelector("#form-status");

const promptPanel = document.querySelector("#prompt-panel");

const statusLine = document.querySelector("#status-line");
const privacyToggle = document.querySelector("#privacy-toggle");
const privacyNote = document.querySelector("#privacy-note");
// Optional elements: guard bindings below so missing markup can't crash startup.
const reviewPolicyName = document.querySelector("#review-policy-name");
const findingCount = document.querySelector("#finding-count");
const livePreviewText = document.querySelector("#live-preview-text");

// (Older markup references these IDs; the new UI may omit them.)
// Keep them optional and never assume existence.
const _unused_guards = { reviewPolicyName, findingCount, livePreviewText };

const checkpointTitle = document.querySelector("#checkpoint-title");
const idleState = document.querySelector("#state-idle");
const analyzingState = document.querySelector("#state-analyzing");
const reviewState = document.querySelector("#state-review");
const outcomeState = document.querySelector("#state-outcome");
const offlineState = document.querySelector("#state-offline");

const findingList = document.querySelector("#finding-list");

const outcomeTitle = document.querySelector("#outcome-title");
const outcomeCopy = document.querySelector("#outcome-copy");
const resetButton = document.querySelector("#reset-button");

const redactButton = document.querySelector("#redact-button");
const blockButton = document.querySelector("#block-button");
const allowButton = document.querySelector("#allow-button");

const exportMdBtn = document.querySelector("#export-md-btn");
const policyBalancedBtn = document.querySelector("#policy-balanced-btn");
const policyStrictBtn = document.querySelector("#policy-strict-btn");
const activePolicyIndicator = document.querySelector("#active-policy-indicator");

// NOTE: optional elements are guarded above so missing markup can't crash startup.

const policyButtons = [policyBalancedBtn, policyStrictBtn].filter(Boolean);

let currentPolicy = "balanced";
let pending = null;
let reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

async function engineRequest(action, payload = {}) {
  const engine = globalThis.SentinelEngine;
  if (!engine) throw new Error("The on-device browser engine failed to initialize.");
  if (action === "health") return { status: "local", service: "sentinel-browser-engine" };
  if (action === "analyze") return engine.analyzeText(payload.text, payload.policy);
  if (action === "redact") return engine.redactText(payload.text, payload.findingIds, payload.policy);
  throw new Error(`Unsupported browser-engine action: ${action}`);
}

function setState(state) {
  const map = {
    idle: idleState,
    analyzing: analyzingState,
    review: reviewState,
    outcome: outcomeState,
    offline: offlineState,
  };
  for (const [key, el] of Object.entries(map)) {
    if (!el) continue;
    el.hidden = key !== state;
  }
  if (state === "idle" && statusLine) statusLine.textContent = "Ready for local inspection.";
}

function setEngineStatus(status, label) {
  const engineBadge = document.querySelector("#engine-status-badge");
  const engineLabel = document.querySelector("#engine-label");
  if (engineBadge) engineBadge.dataset.engineState = status;
  if (engineLabel) engineLabel.textContent = label;
  if (stateLineForEngine(status)) {
    // no-op; we rely on offline panel for availability
  }
}

// Placeholder for older markup versions; intentionally no-op.
function stateLineForEngine() {
  return false;
}

function computePreview(text, findings, selectedIds) {
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

function renderFindings(findings) {
  if (!findingList) return;

  // table-like rows
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
      // Evidence must be masked: safePreview only.
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
      checkbox.addEventListener("change", () => updatePreview());
      action.appendChild(checkbox);

      return row;
    })
  );
}

function getSelectedFindingIds() {
  if (!findingList) return [];
  return [...findingList.querySelectorAll("input[type=checkbox]:checked")].map((c) => c.value);
}

function updatePreview() {
  if (!pending || !livePreviewText) return;
  const selectedIds = getSelectedFindingIds();
  const preview = computePreview(pending.text, pending.findings, selectedIds);
  livePreviewText.textContent = preview;
}

function showOffline() {
  setState("offline");
}

function showAnalyzing() {
  setState("analyzing");
}

function showReview(analysis) {
  pending = { text: input.value, findings: analysis.findings };

  if (checkpointTitle) checkpointTitle.textContent = "Review required";
  if (reviewPolicyName) reviewPolicyName.textContent = currentPolicy;
  if (findingCount) findingCount.textContent = `${analysis.findings.length} finding${analysis.findings.length === 1 ? "" : "s"}`;

  renderFindings(analysis.findings);
  updatePreview();

  setState("review");
}

function showOutcome(kind, title, copy) {
  outcomeTitle.textContent = title;
  outcomeCopy.textContent = copy;
  setState("outcome");
}

async function submitPrompt() {
  const text = input.value.trim();
  if (!text) {
    if (formStatus) formStatus.textContent = "Paste text to inspect.";
    return;
  }

  if (formStatus) formStatus.textContent = "";
  sendButton.disabled = true;

  try {
    const analysis = await engineRequest("analyze", { text, policy: currentPolicy });
    if (analysis.decision === "allow") {
      // No hidden send/chat model: show outcome only.
      pending = null;
      showOutcome("allowed", "Original text allowed", `No sensitive values were detected under ${currentPolicy} policy.`);
    } else {
      showReview(analysis);
    }
  } catch (error) {
    if (formStatus) formStatus.textContent = error.message;
    showOffline();
  } finally {
    sendButton.disabled = false;
  }
}

async function handleBlock() {
  if (!pending) return;
  showOutcome("blocked", "Blocked before insertion", "No text was inserted after local inspection.");
  pending = null;
}

async function handleRedact() {
  if (!pending) return;
  const ids = getSelectedFindingIds();
  if (!ids.length) {
    if (formStatus) formStatus.textContent = "Select at least one finding to redact.";
    return;
  }

  const result = await engineRequest("redact", { text: pending.text, findingIds: ids, policy: currentPolicy });
  showOutcome("redacted", "Redacted locally", `${ids.length} sensitive value${ids.length === 1 ? " was" : "s were"} redacted.`);
  if (livePreviewText) livePreviewText.textContent = result.redactedText;
  pending = null;
}

async function handleAllowOnce() {
  if (!pending) return;
  // Allow once = let original text through for that one inspection decision.
  showOutcome("allowed", "Allowed once", "Original text allowed for this inspection decision only.");
  pending = null;
}

function reset() {
  pending = null;
  input.value = "";
  if (formStatus) formStatus.textContent = "";
  setState("idle");
}

function initPolicyUI() {
  // Keep policy buttons if they exist in older markup.
  if (policyButtons.length === 2) {
    policyBalancedBtn?.addEventListener("click", () => {
      currentPolicy = "balanced";
      reset();
    });
    policyStrictBtn?.addEventListener("click", () => {
      currentPolicy = "strict";
      reset();
    });
  }
}

function initSampleUI() {
  document.querySelectorAll(".sample-button").forEach((button) => {
    button.addEventListener("click", () => {
      const name = button.dataset.sample;
      input.value = samples[name] || "";
      if (formStatus) formStatus.textContent = "";
      setState("idle");
    });
  });
}

function initPrivacyToggle() {
  if (!privacyToggle || !privacyNote) return;
  privacyToggle.addEventListener("click", () => {
    const expanded = privacyToggle.getAttribute("aria-expanded") === "true";
    privacyToggle.setAttribute("aria-expanded", String(!expanded));
    privacyNote.hidden = expanded;
  });
}

form?.addEventListener("submit", (event) => {
  event.preventDefault();
  submitPrompt();
});
// If markup accidentally omits #prompt-form, fall back to clicking the primary button.
sendButton?.addEventListener("click", (e) => {
  if (form) return;
  e.preventDefault();
  submitPrompt();
});

redactButton?.addEventListener("click", handleRedact);
blockButton?.addEventListener("click", handleBlock);
allowButton?.addEventListener("click", handleAllowOnce);
resetButton?.addEventListener("click", reset);

initSampleUI();
initPrivacyToggle();
initPolicyUI();

async function checkEngine() {
  try {
    await engineRequest("health");
    setEngineStatus("online", "On-device engine");
    setState("idle");
  } catch {
    setEngineStatus("offline", "Engine unavailable");
    showOffline();
  }
}

setState("idle");
checkEngine();
