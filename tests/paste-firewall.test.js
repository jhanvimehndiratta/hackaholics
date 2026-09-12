const test = require("node:test");
const assert = require("node:assert/strict");

require("../shared/sentinel-engine.js");
require("../extension/paste-controller.js");

const { createController, editableTarget, isSupportedInput, restoreAndInsert } = globalThis.SentinelPaste;
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

test("resolves a nested paste event target to the outer contenteditable host", () => {
  const editor = { tagName: "DIV", isContentEditable: true, parentElement: null };
  const paragraph = { tagName: "P", isContentEditable: false, parentElement: editor };
  const textLeaf = { nodeType: 3, parentElement: null, parentNode: paragraph };

  assert.equal(editableTarget(textLeaf), editor);
  assert.equal(isSupportedInput(textLeaf), true);
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

test("paused origin inserts programmatically while protected origin analyzes", async () => {
  const target = control();
  const event = pasteEvent(target, "synthetic text");
  const { instance } = controller({ sitePolicy: { isPaused: async () => true }, pageOrigin: "https://example.com" });
  const result = await instance.handlePaste(event);
  assert.equal(result.decision, "site_paused");
  assert.equal(target.value, "hello synthetic text");
});

test("policy failures remain fail-closed", async () => {
  for (const response of [undefined, "paused"]) {
    const target = control();
    const { instance } = controller({ sitePolicy: { isPaused: async () => response }, pageOrigin: "https://example.com" });
    assert.equal((await instance.handlePaste(pasteEvent(target, "synthetic text"))).blocked, true);
    assert.equal(target.value, "hello world");
  }
  const target = control();
  const { instance } = controller({ sitePolicy: { isPaused: async () => { throw new Error("storage unavailable"); } }, pageOrigin: "https://example.com" });
  assert.equal((await instance.handlePaste(pasteEvent(target, "synthetic text"))).blocked, true);
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

test("redact and allow-once insert into contenteditable only after approval while block changes nothing", async () => {
  const sensitive = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";

  for (const action of ["block", "redact", "allowOnce"]) {
    const inserted = [];
    const range = {
      deleteContents() { inserted.push("deleted"); },
      insertNode(node) { inserted.push(node); },
      setStartAfter(node) { this.after = node; },
      collapse(value) { this.collapsed = value; },
      cloneRange() { return this; },
    };
    const selection = {
      rangeCount: 1,
      getRangeAt() { return range; },
      removeAllRanges() {},
      addRange() {},
    };
    const ownerDocument = {
      createTextNode(text) { return { textContent: text }; },
      defaultView: { InputEvent: class { constructor(type) { this.type = type; } } },
    };
    const editor = {
      tagName: "DIV", isContentEditable: true, isConnected: true, parentElement: null,
      ownerDocument, events: [], focus() {}, dispatchEvent(event) { this.events.push(event.type); },
    };
    const child = { tagName: "P", isContentEditable: false, parentElement: editor };
    const event = pasteEvent(child, sensitive);
    const { instance, reviews } = controller({ selectionProvider: () => selection });

    await instance.handlePaste(event);
    assert.equal(event.prevented, true);
    assert.equal(event.stopped, true);
    assert.deepEqual(inserted, []);

    const review = reviews[0];
    if (action === "block") {
      review.actions.block();
      assert.deepEqual(inserted, []);
    } else if (action === "redact") {
      const ids = review.findings.map((finding) => finding.id);
      review.actions.redact(ids);
      const expected = engine.redactText(sensitive, ids).redactedText;
      assert.equal(inserted[1].textContent, expected);
      assert.equal(inserted[1].textContent.includes("AKIAIOSFODNN7EXAMPLE"), false);
    } else {
      review.actions.allowOnce();
      assert.equal(inserted[1].textContent, sensitive);
    }
  }
});

test("nested contenteditable paste is intercepted before analysis and inserts nothing before approval", async () => {
  let resolveAnalysis;
  const sensitive = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
  const inserted = [];
  const range = {
    deleteContents() { inserted.push("deleted"); },
    insertNode(node) { inserted.push(node); },
    setStartAfter() {},
    collapse() {},
    cloneRange() { return this; },
  };
  const selection = {
    rangeCount: 1,
    getRangeAt() { return range; },
    removeAllRanges() {},
    addRange() {},
  };
  const editor = {
    tagName: "DIV", isContentEditable: true, isConnected: true, parentElement: null,
    ownerDocument: {
      createTextNode(text) { return { textContent: text }; },
      defaultView: { InputEvent: class { constructor(type) { this.type = type; } } },
    },
    focus() {}, dispatchEvent() {},
  };
  const child = { tagName: "SPAN", isContentEditable: false, parentElement: editor };
  const event = pasteEvent(child, sensitive);
  const delayedEngine = {
    ...engine,
    analyzeText() { return new Promise((resolve) => { resolveAnalysis = resolve; }); },
  };
  const { instance, reviews } = controller({ engine: delayedEngine, selectionProvider: () => selection });

  const pending = instance.handlePaste(event);
  assert.equal(event.prevented, true);
  assert.equal(event.stopped, true);
  assert.deepEqual(inserted, []);
  assert.equal(reviews.length, 0);

  resolveAnalysis(engine.analyzeText(sensitive));
  await pending;
  assert.deepEqual(inserted, []);
  assert.equal(reviews.length, 1);
});

test("redact and allow-once notify controlled inputs through the native value setter", async () => {
  const sensitive = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";

  for (const action of ["redact", "allowOnce"]) {
    let storedValue = "hello world";
    let setterCalls = 0;
    const inputPrototype = {};
    Object.defineProperty(inputPrototype, "value", {
      configurable: true,
      get() { return storedValue; },
      set(value) { setterCalls += 1; storedValue = value; },
    });
    const target = Object.create(inputPrototype);
    Object.assign(target, {
      tagName: "TEXTAREA", type: "text", selectionStart: 6, selectionEnd: 11,
      isContentEditable: false, isConnected: true, parentElement: null, events: [],
      focus() {}, getAttribute() { return null; },
      setSelectionRange(start, end) { this.selectionStart = start; this.selectionEnd = end; },
      dispatchEvent(event) { this.events.push(event.type); },
      ownerDocument: {
        defaultView: {
          HTMLTextAreaElement: { prototype: inputPrototype },
          HTMLInputElement: { prototype: {} },
          InputEvent: class { constructor(type) { this.type = type; } },
        },
      },
    });
    const { instance, reviews } = controller();

    await instance.handlePaste(pasteEvent(target, sensitive));
    assert.equal(storedValue, "hello world");
    const review = reviews[0];
    if (action === "redact") review.actions.redact(review.findings.map((finding) => finding.id));
    else review.actions.allowOnce();

    assert.equal(setterCalls, 1);
    assert.equal(target.events.includes("input"), true);
    if (action === "redact") assert.equal(storedValue.includes("AKIAIOSFODNN7EXAMPLE"), false);
    else assert.equal(storedValue, `hello ${sensitive}`);
  }
});

test("disconnected targets fail closed when an approval action tries to insert", async () => {
  const sensitive = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
  const target = control();
  const { instance, reviews } = controller();
  await instance.handlePaste(pasteEvent(target, sensitive));
  target.isConnected = false;

  assert.throws(
    () => reviews[0].actions.redact(reviews[0].findings.map((finding) => finding.id)),
    /no longer available/
  );
  assert.equal(target.value, "hello world");
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
  let inputEventOptions;
  class InputEventMock {
    constructor(type, options) { this.type = type; inputEventOptions = options; }
  }
  const target = {
    isContentEditable: true, isConnected: true, events: [], focus() {},
    ownerDocument: {
      createTextNode(text) { return { textContent: text }; },
      defaultView: { InputEvent: InputEventMock },
    },
    dispatchEvent(event) { this.events.push(event.type); },
  };
  restoreAndInsert({ kind: "contenteditable", target, range }, "safe text", () => selection);
  assert.equal(inserted[1].textContent, "safe text");
  assert.equal(range.after, inserted[1]);
  assert.equal(range.collapsed, true);
  assert.equal(selection.added, range);
  assert.equal(inputEventOptions.bubbles, true);
  assert.equal(inputEventOptions.composed, true);
  assert.equal(inputEventOptions.inputType, "insertFromPaste");
  assert.equal(inputEventOptions.data, "safe text");
});
