const samples = {
  safe: "How should I structure retries in a small Python service?",
  sensitive:
    "Review this deployment: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE, database postgres://service:hunter2@10.24.3.8/prod, and notify owner@example.com.",
  ambiguous:
    "The build artifact 550e8400e29b41d4a716446655440000 failed validation. What should I inspect next?",
};

const findingCopy = {
  aws_access_key: ["AWS access key", "Credential-shaped value matched an AWS access-key rule."],
  github_token: ["GitHub token", "Token prefix and length match a GitHub credential format."],
  api_key: ["API credential", "A named API key assignment contains a credential-shaped value."],
  database_url: ["Database credential", "This connection URL includes a username and password."],
  email: ["Email address", "A personal contact address appears in the prompt."],
  internal_ip: ["Internal IP address", "This address is inside an RFC1918 private network range."],
  suspected_secret: ["Suspected secret", "A high-entropy value appears in a named secret context."],
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
const messageStream = document.querySelector("#message-stream");
const emptyConversation = document.querySelector("#empty-conversation");
const activityList = document.querySelector("#activity-list");
const engineState = document.querySelector(".engine-state");
const engineLabel = document.querySelector("#engine-label");

let pending = null;
let activity = [];
const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

function dispatchRequest(detail) {
  return new Promise((resolve, reject) => {
    const requestId = crypto.randomUUID();
    const timeout = window.setTimeout(() => {
      window.removeEventListener("sentinel:response", onResponse);
      reject(new Error("Sentinel extension did not respond. Load the unpacked extension and retry."));
    }, 180);

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
  try {
    return await dispatchRequest({ action, payload });
  } catch (extensionError) {
    const endpoint = action === "health" ? "/health" : `/${action}`;
    const options = action === "health" || action === "getAudit"
      ? {}
      : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) };
    try {
      const route = action === "getAudit" ? "/audit" : endpoint;
      const response = await fetch(`http://127.0.0.1:8787${route}`, options);
      if (!response.ok) throw new Error(`Local engine returned ${response.status}`);
      return response.json();
    } catch {
      throw extensionError;
    }
  }
}

function setSample(name) {
  input.value = samples[name];
  document.querySelectorAll(".sample-button").forEach((button) => {
    button.classList.toggle("is-active", button.dataset.sample === name);
  });
  resetCheckpoint(false);
}

function setEngineStatus(status, label) {
  engineState.dataset.engineState = status;
  engineLabel.textContent = label;
}

async function checkEngine() {
  try {
    await engineRequest("health");
    setEngineStatus("online", "Local engine connected");
  } catch {
    setEngineStatus("offline", "Load extension + engine");
  }
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
      const copy = document.createElement("span");
      copy.className = "finding-copy";
      const [name, explanation] = findingCopy[finding.type] || [finding.type, "A local rule marked this value for review."];
      const top = document.createElement("span");
      top.className = "finding-topline";
      const title = document.createElement("span");
      title.className = "finding-name";
      title.textContent = name;
      const severity = document.createElement("span");
      severity.className = "severity";
      severity.textContent = finding.severity;
      top.append(title, severity);
      const detail = document.createElement("p");
      detail.textContent = explanation;
      const preview = document.createElement("code");
      preview.textContent = `${finding.safePreview}  →  ${finding.replacement}`;
      copy.append(top, detail, preview);
      label.append(checkbox, copy);
      return label;
    })
  );
}

function showReview(analysis) {
  pending = { text: input.value, findings: analysis.findings };
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
  meta.textContent = "Simulated send • no external AI service";
  article.append(label, content, meta);
  messageStream.append(article);
  article.scrollIntoView({ behavior: reduceMotion ? "auto" : "smooth", block: "end" });
}

function addActivity(decision, categories, sent) {
  activity.unshift({ decision, categories, sent, time: new Date() });
  activityList.replaceChildren(
    ...activity.slice(0, 5).map((event) => {
      const item = document.createElement("li");
      const title = document.createElement("strong");
      title.textContent = event.decision;
      const detail = document.createTextNode(
        `${event.sent ? "Sent" : "Not sent"} • ${event.categories.length ? event.categories.join(", ") : "No findings"} • ${event.time.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`
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
    await engineRequest("audit", { decision, findingTypes, sent });
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
    const analysis = await engineRequest("analyze", { text });
    playIntercept(async () => {
      if (analysis.decision === "allow") {
        addMessage(text, "Sent after local check");
        await audit("allow", [], true);
        showOutcome("sent", "Sent after local check", "No sensitive values matched the current local rules.");
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
    const result = await engineRequest("redact", { text: pending.text, findingIds: ids });
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
