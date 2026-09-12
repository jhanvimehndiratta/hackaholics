const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

require("../shared/sentinel-engine.js");
const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures/browser-engine-parity.json"), "utf8"));
const { analyzeText, redactText, AuditStore } = globalThis.SentinelEngine;

for (const item of fixture.cases) {
  test(`Python parity: ${item.name}`, () => {
    assert.deepEqual(analyzeText(item.text, item.policy), item.analysis);
    const ids = item.analysis.findings.map((finding) => finding.id);
    assert.deepEqual(redactText(item.text, ids, item.policy), item.redactions.all);
  });
}

test("policy and finding validation match Python", () => {
  assert.throws(() => analyzeText("hello", "invalid_policy"), /Invalid policy 'invalid_policy'/);
  assert.throws(() => redactText("hello", ["finding-999"]), /Unknown finding IDs: finding-999/);
});

function normalizeAudit(value) {
  if (Array.isArray(value)) return value.map(normalizeAudit);
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, key === "timestamp" || key === "exportDate" ? "<timestamp>" : normalizeAudit(item)]));
  return value;
}

test("audit output matches Python and never stores raw text", () => {
  const store = new AuditStore();
  const sensitive = fixture.cases.find((item) => item.name === "all-findings");
  store.record("redact_send", sensitive.analysis.findings, true, "strict");
  store.record("block", sensitive.analysis.findings, false, "strict");
  assert.deepEqual(normalizeAudit(store.export("json")), fixture.audit.json);
  const markdown = store.export("markdown").replace(/- \*\*Export Date:\*\* .+/, "- **Export Date:** <timestamp>").replace(/\| \d{4}-[^|]+ \|/g, "| <timestamp> |");
  assert.equal(markdown, fixture.audit.markdown);
  assert.equal(JSON.stringify(store.list()).includes("AKIAIOSFODNN7EXAMPLE"), false);
});
