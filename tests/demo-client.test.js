const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

require("../shared/sentinel-engine.js");

class Element {
  constructor(id = "") {
    this.id = id;
    this.value = "";
    this.textContent = "";
    this.hidden = false;
    this.disabled = false;
    this.checked = false;
    this.dataset = {};
    this.attributes = {};
    this.children = [];
    this.listeners = new Map();
  }

  setAttribute(name, value) {
    this.attributes[name] = String(value);
  }

  getAttribute(name) {
    return this.attributes[name] ?? null;
  }

  addEventListener(type, listener) {
    this.listeners.set(type, listener);
  }

  async dispatch(type) {
    const listener = this.listeners.get(type);
    if (listener) await listener({ preventDefault() {} });
  }

  appendChild(child) {
    this.children.push(child);
  }

  append(...children) {
    this.children.push(...children);
  }

  replaceChildren(...children) {
    this.children = children;
  }

  querySelectorAll(selector) {
    if (selector !== 'input[type="checkbox"]:checked') return [];
    return this.children
      .flatMap((row) => row.children)
      .flatMap((cell) => cell.children)
      .filter((element) => element.checked);
  }
}

function createHarness({ clipboardFails = false } = {}) {
  const ids = [
    "prompt-form",
    "prompt-input",
    "send-button",
    "form-status",
    "status-line",
    "review-policy-name",
    "finding-count",
    "live-preview-text",
    "checkpoint-title",
    "state-idle",
    "state-analyzing",
    "state-review",
    "state-outcome",
    "state-offline",
    "finding-list",
    "outcome-title",
    "outcome-copy",
    "clipboard-status",
    "copy-button",
    "reset-button",
    "redact-button",
    "block-button",
    "allow-button",
    "policy-balanced-btn",
    "policy-strict-btn",
    "engine-status-badge",
    "engine-label",
  ];
  const elements = Object.fromEntries(ids.map((id) => [id, new Element(id)]));
  const samples = ["safe", "sensitive", "entropy", "ambiguous"].map((name) => {
    const element = new Element();
    element.dataset.sample = name;
    return element;
  });
  const writes = [];

  const document = {
    querySelector(selector) {
      return elements[selector.slice(1)] || null;
    },
    querySelectorAll(selector) {
      return selector === ".sample-button" ? samples : [];
    },
    createElement() {
      return new Element();
    },
  };
  const navigator = {
    clipboard: {
      async writeText(text) {
        if (clipboardFails) throw new Error("denied");
        writes.push(text);
      },
    },
  };
  const context = vm.createContext({
    document,
    navigator,
    SentinelEngine: globalThis.SentinelEngine,
    console,
  });
  const source = fs.readFileSync(path.join(__dirname, "../demo-client/app.js"), "utf8");
  vm.runInContext(source, context);

  return { elements, samples: Object.fromEntries(samples.map((sample) => [sample.dataset.sample, sample])), writes };
}

async function inspectSample(harness, name) {
  await harness.samples[name].dispatch("click");
  await harness.elements["prompt-form"].dispatch("submit");
}

test("strict entropy selects Strict and renders masked suspected_secret evidence", async () => {
  const harness = createHarness();
  await inspectSample(harness, "entropy");

  assert.equal(harness.elements["policy-strict-btn"].getAttribute("aria-pressed"), "true");
  assert.equal(harness.elements["state-review"].hidden, false);
  const [row] = harness.elements["finding-list"].children;
  assert.equal(row.children[0].textContent, "suspected_secret");
  assert.equal(row.children[1].children[0].textContent, "8sF3…");
  assert.equal(row.children.length, 4);
});

test("balanced entropy is allowed while benign UUID reports a zero-finding false-positive test", async () => {
  const entropy = createHarness();
  await entropy.samples.entropy.dispatch("click");
  await entropy.elements["policy-balanced-btn"].dispatch("click");
  entropy.elements["prompt-input"].value = "Deploy service cluster with auth token=8sF3mQ9vL2xK7pR4nT6wY1zB5cD0hJ8u to staging gateway.";
  await entropy.elements["prompt-form"].dispatch("submit");
  assert.equal(entropy.elements["state-outcome"].hidden, false);
  assert.equal(entropy.elements["finding-list"].children.length, 0);

  const uuid = createHarness();
  await inspectSample(uuid, "ambiguous");
  assert.equal(uuid.elements["state-outcome"].hidden, false);
  assert.match(uuid.elements["outcome-copy"].textContent, /false-positive test passed: zero findings/i);
  assert.equal(uuid.elements["finding-list"].children.length, 0);
});

test("redact and allow once copy the correct text and show confirmation", async () => {
  const redacted = createHarness();
  await inspectSample(redacted, "sensitive");
  await redacted.elements["redact-button"].dispatch("click");
  assert.equal(redacted.elements["clipboard-status"].textContent, "Copied to clipboard");
  assert.equal(redacted.elements["copy-button"].disabled, false);
  assert.doesNotMatch(redacted.writes.at(-1), /AKIAIOSFODNN7EXAMPLE|Summer2026|hunter2/);

  const allowed = createHarness();
  await inspectSample(allowed, "sensitive");
  const original = allowed.elements["prompt-input"].value.trim();
  await allowed.elements["allow-button"].dispatch("click");
  assert.equal(allowed.elements["clipboard-status"].textContent, "Copied to clipboard");
  assert.equal(allowed.writes.at(-1), original);
});

test("clipboard failure preserves the manual copy result and reset restores Ready", async () => {
  const harness = createHarness({ clipboardFails: true });
  await inspectSample(harness, "sensitive");
  await harness.elements["allow-button"].dispatch("click");
  assert.equal(
    harness.elements["clipboard-status"].textContent,
    "Clipboard access failed — use Copy manually."
  );
  assert.equal(harness.elements["copy-button"].disabled, false);

  await harness.elements["reset-button"].dispatch("click");
  assert.equal(harness.elements["checkpoint-title"].textContent, "Ready to inspect");
  assert.equal(harness.elements["copy-button"].disabled, true);
  assert.equal(harness.elements["state-idle"].hidden, false);
});
