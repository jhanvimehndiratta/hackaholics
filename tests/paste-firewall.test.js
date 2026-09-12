const test = require("node:test");
const assert = require("node:assert/strict");

require("../shared/sentinel-engine.js");
require("../extension/paste-controller.js");

const { createController, isSupportedInput, restoreAndInsert } = globalThis.SentinelPaste;
const engine = globalThis.SentinelEngine;

function control(tagName = "TEXTAREA", type = "text", value = "hello world", start = 6, end = 11) {
  return {
    tagName, type, value, selectionStart: start, selectionEnd: end, isContentEditable: false,
    isConnected: true, parentElement: null, events: [], focus() {},
    getAttribute(name) { return name === "type" ? type : null; },
    setSelectionRange(a, b) { this.selectionStart = a; this.selectionEnd = b; },
    dispatchEvent(event) { this.events.push(event.type); },
  };
}

function pasteEvent(target, text) {
  return {
    target,
    clipboardData: { getData(type) { return type === "text/plain" ? text : ""; } },
    prevented: false, stopped: false,
    preventDefault() { this.prevented = true; },
    stopImmediatePropagation() { this.stopped = true; },
  };
}

function controller(overrides = {}) {
  const reviews = [];
  const errors = [];
  return {
    reviews, errors,
    instance: createController({
      engine,
      selectionProvider: () => null,
      renderReview: (review) => reviews.push(review),
      renderError: (error) => errors.push(error),
      ...overrides,
    }),
  };
}

test("supports approved fields and excludes passwords", () => {
  for (const type of ["text", "search", "url", "email"]) assert.equal(isSupportedInput(control("INPUT", type)), true);
  assert.equal(isSupportedInput(control("TEXTAREA")), true);
  assert.equal(isSupportedInput(control("INPUT", "password")), false);
  assert.equal(isSupportedInput(control("INPUT", "number")), false);
});

test("blocks synchronously and never inserts sensitive text while analysis is pending", async () => {
  let resolveAnalysis;
  const delayedEngine = { ...engine, analyzeText: () => new Promise((resolve) => { resolveAnalysis = resolve; }) };
  const target = control();
  const event = pasteEvent(target, "API_KEY=synthetic-secret-value");
  const { instance } = controller({ engine: delayedEngine });
  const pending = instance.handlePaste(event);
  assert.equal(event.prevented, true);
  assert.equal(event.stopped, true);
  assert.equal(target.value, "hello world");
  resolveAnalysis(engine.analyzeText("API_KEY=synthetic-secret-value"));
  await pending;
  assert.equal(target.value, "hello world");
});

test("analysis failure remains fail-closed", async () => {
  const target = control();
  const event = pasteEvent(target, "API_KEY=synthetic-secret-value");
  const { instance, errors } = controller({ engine: { analyzeText: () => Promise.reject(new Error("blocked response")) } });
  const result = await instance.handlePaste(event);
  assert.equal(result.blocked, true);
  assert.equal(target.value, "hello world");
  assert.match(errors[0], /remained blocked/);
});

test("textarea block, redact, and allow-once preserve the captured selection", async () => {
  const sensitive = "API_KEY=synthetic-secret-value";
  for (const action of ["block", "redact", "allowOnce"]) {
    const target = control();
    const event = pasteEvent(target, sensitive);
    const { instance, reviews } = controller();
    await instance.handlePaste(event);
    assert.equal(target.value, "hello world");
    const review = reviews[0];
    if (action === "block") {
      review.actions.block();
      assert.equal(target.value, "hello world");
    } else if (action === "redact") {
      review.actions.redact(review.findings.map((finding) => finding.id));
      const expected = engine.redactText(sensitive, review.findings.map((finding) => finding.id)).redactedText;
      assert.equal(target.value, `hello ${expected}`);
      assert.equal(target.selectionStart, 6 + expected.length);
    } else {
      review.actions.allowOnce();
      assert.equal(target.value, `hello ${sensitive}`);
      assert.equal(target.selectionStart, 6 + sensitive.length);
    }
    if (action === "block") {
      assert.equal(target.selectionStart, 6);
      assert.equal(target.selectionEnd, 11);
    } else {
      assert.equal(target.selectionStart, target.selectionEnd);
    }
  }
});

test("contenteditable replacement restores the caret after inserted text", () => {
  const inserted = [];
  const range = {
    deleteContents() { inserted.push("deleted"); },
    insertNode(node) { inserted.push(node); },
    setStartAfter(node) { this.after = node; },
    collapse(value) { this.collapsed = value; },
  };
  const selection = { removed: false, added: null, removeAllRanges() { this.removed = true; }, addRange(value) { this.added = value; } };
  const target = {
    isContentEditable: true, isConnected: true, events: [], focus() {},
    ownerDocument: { createTextNode(text) { return { textContent: text }; } },
    dispatchEvent(event) { this.events.push(event.type); },
  };
  restoreAndInsert({ kind: "contenteditable", target, range }, "safe text", () => selection);
  assert.equal(inserted[1].textContent, "safe text");
  assert.equal(range.after, inserted[1]);
  assert.equal(range.collapsed, true);
  assert.equal(selection.added, range);
});
