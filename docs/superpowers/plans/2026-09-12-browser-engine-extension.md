# Browser Engine and Real-Time Extension Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the GitHub Pages application analyze arbitrary text entirely in-browser and make the Chrome extension protect supported editable fields on normal webpages using the exact same deterministic engine.

**Architecture:** A dependency-free classic script exposes `globalThis.SentinelEngine`; `demo-client/index.html` and `extension/manifest.json` both load that exact file before their respective application/content scripts. Python-generated synthetic fixtures define the parity contract. The public site and extension run locally without FastAPI, while FastAPI remains the reference and optional higher-assurance mode.

**Tech Stack:** Python 3 standard library, browser-safe JavaScript, Node.js built-in test runner, DOM test harness, Chrome Manifest V3, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-12-browser-engine-extension-design.md`

## Global Constraints

- The extension content script must not depend on ES-module loading; load the classic shared engine script before `content.js`.
- GitHub Pages and the extension must execute the same detector file, not copied implementations.
- Python-generated fixture files are the parity source of truth.
- Parity covers findings, ranges, deterministic IDs, previews, replacements, redactions, policies, and sanitized audit output.
- Paste handling is fail-closed if engine initialization or analysis fails.
- Original sensitive text must never enter the target value or DOM before explicit approval.
- Test selection/caret restoration for both `textarea` and contenteditable.
- `<all_urls>` applies only to normal HTTP/HTTPS pages and must be clearly explained as a broad permission.
- Inspect only textarea, text/search/url/email inputs, and contenteditable; never inspect password inputs.
- Clipboard text must never be sent to FastAPI or any cloud service in the public extension path.
- All fixtures, examples, tests, and screenshots must use synthetic secrets only.
- Never claim that opening GitHub Pages installs or activates the extension.

---

## File Structure

- Create `shared/sentinel-engine.js`: classic-script IIFE; the sole JavaScript implementation of detection, redaction, and audit.
- Create `engine/tests/generate_browser_fixtures.py`: invokes Python reference functions and writes deterministic synthetic parity fixtures.
- Create `tests/fixtures/browser-engine-parity.json`: generated expected cases owned by Python.
- Create `tests/browser-engine.test.js`: Node parity tests against the generated fixture.
- Create `tests/paste-firewall.test.js`: DOM-contract tests using a small fake DOM/target harness and exported paste-controller seams.
- Modify `demo-client/index.html`: load `../shared/sentinel-engine.js` before `app.js` (GitHub Pages artifact must include `shared/`).
- Modify `demo-client/app.js`: replace extension message bridge with a direct adapter over `SentinelEngine` and implement standalone paste review.
- Modify `extension/manifest.json`: add `<all_urls>` and load `../shared/sentinel-engine.js` before `content.js` from an extension-local copy path supported by the packaged tree.
- Modify `.github/workflows/pages.yml`: stage both `demo-client/` and `shared/` into one Pages artifact so relative paths resolve.
- Modify `extension/content.js`: consume `globalThis.SentinelEngine`, constrain targets, capture selection, intercept synchronously, fail closed, and insert only after decisions.
- Modify `extension/background.js`: remove the default localhost analysis relay or leave only an explicitly optional, unused reference-mode path; no paste flow may depend on it.
- Modify `.github/workflows/ci.yml`: generate/check fixtures and run Node parity and paste-firewall tests.
- Modify `README.md`: document standalone Pages mode, all-sites extension permission, exclusions, local-only processing, installation boundary, and optional FastAPI reference mode.

---

### Task 1: Establish Python-Owned Parity Fixtures

**Files:**
- Create: `engine/tests/generate_browser_fixtures.py`
- Create: `tests/fixtures/browser-engine-parity.json`
- Modify: `engine/tests/test_engine.py`

**Interfaces:**
- Consumes: `engine.detectors.analyze_text(text, policy)`, `engine.redact.redact_text(text, finding_ids, policy)`, `engine.audit.AuditStore`.
- Produces: JSON object `{ "schemaVersion": 1, "cases": [...], "audit": {...} }`; each case contains `name`, `text`, `policy`, `analysis`, and `redactions`.

- [ ] **Step 1: Add a deterministic fixture-generation test**

Add a test that runs the generator in memory and asserts representative cases exist: safe text; every finding type; balanced/strict divergence; RFC1918 boundaries and exclusions; password syntaxes; punctuation; nested database URL; overlapping API/AWS match; invalid policy; unknown finding ID. Use only documented synthetic values such as `AKIAIOSFODNN7EXAMPLE`, `github_pat_11AA0abcdefghijklmnopqrstuv`, and `owner@example.com`.

```python
fixture = build_fixture()
case_names = {case["name"] for case in fixture["cases"]}
self.assertTrue({"safe", "all-findings", "strict-entropy", "overlap"} <= case_names)
self.assertNotIn("realSecret", json.dumps(fixture))
```

- [ ] **Step 2: Run the focused Python test and confirm failure**

Run: `PYTHONPATH=. python3 -m unittest engine.tests.test_engine.BrowserFixtureTests -v`

Expected: FAIL because `build_fixture` does not exist.

- [ ] **Step 3: Implement fixture generation through Python reference APIs**

Use fixed case ordering and stable JSON formatting. Normalize audit timestamps to `"<timestamp>"` in expected fixture data while preserving every other audit field and Markdown line. Do not hand-author expected findings.

```python
def build_fixture():
    cases = []
    for spec in CASE_SPECS:
        analysis = analyze_text(spec["text"], policy=spec["policy"])
        redactions = {
            "all": redact_text(spec["text"], [f["id"] for f in analysis["findings"]], spec["policy"])
        }
        cases.append({**spec, "analysis": analysis, "redactions": redactions})
    return {"schemaVersion": 1, "cases": cases, "audit": build_audit_fixture()}
```

- [ ] **Step 4: Generate and verify the fixture**

Run:

```bash
PYTHONPATH=. python3 engine/tests/generate_browser_fixtures.py tests/fixtures/browser-engine-parity.json
PYTHONPATH=. python3 -m unittest discover -s engine/tests -v
```

Expected: fixture created; all Python tests pass.

- [ ] **Step 5: Commit the reference contract**

```bash
git add engine/tests/generate_browser_fixtures.py engine/tests/test_engine.py tests/fixtures/browser-engine-parity.json
git commit -m "test: define browser engine parity fixtures"
```

---

### Task 2: Implement the Shared Browser Engine with Exact Parity

**Files:**
- Create: `shared/sentinel-engine.js`
- Create: `tests/browser-engine.test.js`

**Interfaces:**
- Produces: `globalThis.SentinelEngine.analyzeText(text, policy = "balanced")`, `redactText(text, findingIds, policy = "balanced")`, and `new AuditStore()` with `record`, `list`, `export`, and `clear`.
- Error messages: invalid policy matches `Invalid policy '<value>'. Must be 'balanced' or 'strict'.`; unknown IDs match `Unknown finding IDs: <sorted IDs>`.

- [ ] **Step 1: Write fixture-driven Node tests**

Load `shared/sentinel-engine.js` through `require`, assert the global exists, iterate every generated case, and deep-compare `analyzeText` and each redaction result. Compare audit JSON after replacing runtime ISO timestamps with `"<timestamp>"`; compare normalized Markdown output.

```javascript
require("../shared/sentinel-engine.js");
const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
for (const testCase of fixture.cases) {
  test(testCase.name, () => {
    assert.deepStrictEqual(
      globalThis.SentinelEngine.analyzeText(testCase.text, testCase.policy),
      testCase.analysis
    );
  });
}
```

- [ ] **Step 2: Run the parity suite and confirm failure**

Run: `node --test tests/browser-engine.test.js`

Expected: FAIL because `shared/sentinel-engine.js` does not exist.

- [ ] **Step 3: Implement detection and preview logic**

Translate Python regex behavior carefully, using explicit match-index/range helpers rather than relying on unsupported Python regex features. Validate RFC1918 octets numerically, calculate Shannon entropy, trim unquoted API terminal periods, and preserve UTF-16 browser string offsets consistently for fixture inputs.

Expose only the public API on `globalThis.SentinelEngine`; keep rule tables/helpers inside an IIFE.

- [ ] **Step 4: Implement sorting, suppression, deterministic IDs, and redaction**

Use the Python sort keys and priority table verbatim. Re-analyze during redaction, reject unknown IDs, remove contained selected ranges, then replace from right to left.

- [ ] **Step 5: Implement sanitized browser audit**

Store only event ID, ISO timestamp, decision, policy, sorted unique categories, finding count, and Boolean sent value. Ensure `list()` returns copies and exports never include analyzed text.

- [ ] **Step 6: Run parity and Python suites**

```bash
node --test tests/browser-engine.test.js
PYTHONPATH=. python3 -m unittest discover -s engine/tests -v
```

Expected: all cases pass in both runtimes.

- [ ] **Step 7: Prove fixture drift is detectable**

Regenerate to a temporary file and byte-compare:

```bash
PYTHONPATH=. python3 engine/tests/generate_browser_fixtures.py "$CLAUDE_JOB_DIR/tmp/browser-engine-parity.json"
cmp tests/fixtures/browser-engine-parity.json "$CLAUDE_JOB_DIR/tmp/browser-engine-parity.json"
```

Expected: exit 0.

- [ ] **Step 8: Commit the shared engine**

```bash
git add shared/sentinel-engine.js tests/browser-engine.test.js
git commit -m "feat: add parity-tested browser engine"
```

---

### Task 3: Make GitHub Pages Fully Standalone

**Files:**
- Modify: `demo-client/index.html`
- Modify: `demo-client/app.js`
- Modify: `.github/workflows/pages.yml`
- Test: `tests/browser-engine.test.js`

**Interfaces:**
- Consumes: `globalThis.SentinelEngine` from Task 2.
- Produces: direct client adapter with actions `health`, `analyze`, `redact`, `audit`, `getAudit`, `exportAudit`, preserving existing UI payload shapes.

- [ ] **Step 1: Add tests for the direct client adapter**

Extract or expose an adapter factory usable under Node. Assert health returns `{status: "local", service: "sentinel-browser-engine"}`, arbitrary text is analyzed, audit stays in browser memory, and no adapter operation calls `fetch` or extension messaging.

- [ ] **Step 2: Run the adapter tests and confirm failure**

Run: `node --test tests/browser-engine.test.js`

Expected: FAIL because the browser adapter is absent.

- [ ] **Step 3: Load the engine before the application**

In `demo-client/index.html`, place the classic engine script immediately before `app.js`:

```html
<script src="shared/sentinel-engine.js"></script>
<script src="app.js"></script>
```

The Pages artifact root must contain both `index.html` and `shared/sentinel-engine.js`.

- [ ] **Step 4: Replace extension dispatch with direct engine calls**

Map existing actions synchronously/through resolved promises to shared-engine methods. Preserve the current UI flow while changing status text to `On-device browser engine` and removing extension timeout/error language.

- [ ] **Step 5: Stage the Pages artifact correctly**

Update `.github/workflows/pages.yml` to create a temporary `_site`, copy `demo-client/*` into its root, and copy `shared/sentinel-engine.js` into `_site/shared/`; upload `_site` rather than only `demo-client`.

```yaml
- name: Build static site
  run: |
    mkdir -p _site/shared
    cp -R demo-client/. _site/
    cp shared/sentinel-engine.js _site/shared/sentinel-engine.js
```

- [ ] **Step 6: Verify standalone behavior and bundle layout**

Run a local static server from a similarly staged directory and confirm `GET /`, `/app.js`, and `/shared/sentinel-engine.js` return 200. With FastAPI stopped and no extension loaded, submit both arbitrary safe text and a synthetic credential and verify allow/review/redaction behavior.

- [ ] **Step 7: Commit standalone Pages mode**

```bash
git add demo-client/index.html demo-client/app.js .github/workflows/pages.yml
git commit -m "feat: run Sentinel entirely in the browser"
```

---

### Task 4: Refactor Paste Handling into a Testable Fail-Closed Controller

**Files:**
- Create: `extension/paste-controller.js`
- Create: `tests/paste-firewall.test.js`
- Modify: `extension/content.js`

**Interfaces:**
- Produces: `globalThis.SentinelPaste.createController({engine, renderReview, renderError})` and target helpers `isSupportedInput`, `captureSelection`, `restoreAndInsert`.
- Controller receives a paste event and returns a result promise, but blocking (`preventDefault`, `stopImmediatePropagation`) occurs synchronously before analysis.

- [ ] **Step 1: Write supported-target and exclusion tests**

Test textarea and text/search/url/email inputs as supported; password, number, checkbox, and non-editable elements as unsupported. Test contenteditable ancestors discovered through `closest`/ancestor traversal.

- [ ] **Step 2: Write the pre-insertion safety tests**

Create synthetic paste events and target fakes. Assert both cancellation methods execute before `engine.analyzeText`; during the unresolved analysis promise, assert the textarea value and contenteditable text contain none of the clipboard payload.

```javascript
const pending = deferred();
const engine = { analyzeText: () => pending.promise };
const result = controller.handlePaste(event);
assert.equal(event.defaultPrevented, true);
assert.equal(target.value, "existing");
assert.equal(target.textContent, "existing");
```

- [ ] **Step 3: Write fail-closed tests**

Reject the analysis promise and return malformed/undefined results. Assert the original and redacted text are never inserted, the paste remains canceled, and `renderError` receives local failure copy.

- [ ] **Step 4: Write selection/caret restoration tests**

For textarea, replace a selected range and assert `selectionStart`/`selectionEnd` collapse immediately after inserted text. For contenteditable, use a DOM Range or deterministic range fake to replace the selected nodes and assert the caret is positioned after the inserted text node.

- [ ] **Step 5: Run tests and confirm failure**

Run: `node --test tests/paste-firewall.test.js`

Expected: FAIL because `extension/paste-controller.js` does not exist.

- [ ] **Step 6: Implement the minimal controller and helpers**

The controller must snapshot selection before async work; render only safe finding metadata; expose closures for `block`, `redact`, and `allowOnce`; revalidate target connectivity and selection before insertion. `redact` calls the shared engine's `redactText` rather than trusting UI-generated text.

- [ ] **Step 7: Run DOM-contract tests**

Run: `node --test tests/paste-firewall.test.js`

Expected: all supported-target, pre-insertion, failure, action, and caret tests pass.

- [ ] **Step 8: Commit the paste controller**

```bash
git add extension/paste-controller.js extension/content.js tests/paste-firewall.test.js
git commit -m "feat: add fail-closed paste controller"
```

---

### Task 5: Package the All-Sites Manifest V3 Extension

**Files:**
- Modify: `extension/manifest.json`
- Modify: `extension/content.js`
- Modify: `extension/background.js`
- Test: `tests/paste-firewall.test.js`

**Interfaces:**
- Consumes, in exact order: `shared/sentinel-engine.js`, `paste-controller.js`, `content.js`.
- Produces: local paste interception on HTTP/HTTPS pages for supported fields only.

- [ ] **Step 1: Add manifest contract tests**

Assert `content_scripts[0].matches` is exactly `['<all_urls>']` or the explicit HTTP/HTTPS equivalent, and `js` loads the exact shared detector bundle before `paste-controller.js` and `content.js`. Assert no remote script URLs and no localhost host permission is needed for the default path.

- [ ] **Step 2: Run manifest tests and confirm failure**

Run: `node --test tests/paste-firewall.test.js`

Expected: FAIL against the old manifest ordering and match set.

- [ ] **Step 3: Update the manifest and package path**

Because a Chrome extension cannot load files outside its extension root, make `shared/sentinel-engine.js` physically part of the extension package without maintaining a second implementation. The repository source of truth remains `shared/sentinel-engine.js`; add a deterministic packaging/check script that copies it to `extension/shared/sentinel-engine.js` and CI byte-compares both. Manifest order:

```json
"matches": ["<all_urls>"],
"js": ["shared/sentinel-engine.js", "paste-controller.js", "content.js"],
"run_at": "document_start"
```

- [ ] **Step 4: Wire content script to the local shared engine**

Remove `chrome.runtime.sendMessage` from the paste-analysis path. Register the capture listener only for `http:` and `https:` documents. Use `SentinelEngine` and `SentinelPaste`; if either is missing, synchronously block supported paste attempts and show a local initialization error.

- [ ] **Step 5: Remove misleading required-backend behavior**

Either remove `background.js` and localhost `host_permissions` entirely from the public manifest, or retain an explicitly optional reference-mode service worker that is not invoked by default. Tests must prove paste analysis works when runtime messaging and `fetch` throw.

- [ ] **Step 6: Run extension tests and syntax checks**

```bash
node --test tests/paste-firewall.test.js
node --check shared/sentinel-engine.js
node --check extension/shared/sentinel-engine.js
node --check extension/paste-controller.js
node --check extension/content.js
```

Expected: all pass; byte comparison confirms the packaged engine equals the Pages engine.

- [ ] **Step 7: Manual real-site smoke test with synthetic data**

Load unpacked extension, visit representative normal HTTPS pages with textarea/input/contenteditable controls, and verify safe insertion, review-before-insertion, Block, Redact, Allow once, password exclusion, and fail-closed behavior. Do not capture real account data in screenshots.

- [ ] **Step 8: Commit public extension packaging**

```bash
git add extension/manifest.json extension/content.js extension/background.js extension/shared/sentinel-engine.js scripts/package-extension-engine.py tests/paste-firewall.test.js
git commit -m "feat: protect editable fields across websites"
```

---

### Task 6: Add CI Gates and Privacy Documentation

**Files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `README.md`
- Modify: `demo-client/index.html`
- Modify: `demo-client/app.js`

**Interfaces:**
- Consumes: all test commands and package checks from Tasks 1–5.
- Produces: clear runtime/permission copy and CI enforcement against parity drift.

- [ ] **Step 1: Add a CI drift test**

Generate fixtures and packaged extension engine into temporary files, compare them against committed outputs, then run Python, Node parity, paste-controller, JSON, and syntax checks. CI fails when Python behavior changes without regenerated fixtures or when the extension bundle differs from the Pages bundle.

- [ ] **Step 2: Update public-site runtime copy**

State that arbitrary text is analyzed locally by the on-device browser engine with no extension, FastAPI, or cloud. Keep a separate callout: cross-site real-time protection requires an unpacked extension or future Chrome Web Store installation; opening the site cannot install it.

- [ ] **Step 3: Document `<all_urls>` clearly**

Explain that the permission is broad because the hackathon extension protects editable fields across normal webpages. List allowed field types, password exclusion, inaccessible browser/extension pages, local-only processing, no clipboard persistence, and no cloud transmission.

- [ ] **Step 4: Correct architecture and feature documentation**

Describe three modes accurately: standalone Pages, all-sites browser extension, optional Python reference engine. Remove statements that imply FastAPI or an extension is required for Pages. Remove unsupported `Permissive` policy claims because the reference accepts only `balanced` and `strict`.

- [ ] **Step 5: Run the complete verification suite**

```bash
PYTHONPATH=. python3 -m unittest discover -s engine/tests -v
PYTHONPATH=. python3 engine/tests/generate_browser_fixtures.py "$CLAUDE_JOB_DIR/tmp/browser-engine-parity.json"
cmp tests/fixtures/browser-engine-parity.json "$CLAUDE_JOB_DIR/tmp/browser-engine-parity.json"
python3 scripts/package-extension-engine.py --check
node --test tests/browser-engine.test.js tests/paste-firewall.test.js
python3 -m json.tool extension/manifest.json >/dev/null
node --check shared/sentinel-engine.js
node --check demo-client/app.js
node --check extension/paste-controller.js
node --check extension/content.js
```

Expected: every command exits 0.

- [ ] **Step 6: Perform end-to-end verification**

- GitHub Pages: with FastAPI stopped and extension absent, analyze arbitrary safe and synthetic-sensitive inputs; verify review and redaction.
- Extension: with FastAPI stopped, verify supported fields across HTTP/HTTPS pages, password exclusion, pre-insertion blocking, and all three decisions.
- Failure: force `analyzeText` to reject/throw and verify nothing is inserted.
- Privacy: inspect DevTools Network while pasting synthetic secrets and verify no request contains clipboard content.
- DOM: observe target value/HTML before choosing an action and verify the original synthetic secret is absent.

- [ ] **Step 7: Commit CI and documentation**

```bash
git add .github/workflows/ci.yml README.md demo-client/index.html demo-client/app.js
git commit -m "docs: explain standalone and all-sites protection"
```

---

### Task 7: Final Cross-Implementation Review

**Files:**
- Review all files changed by Tasks 1–6.

**Interfaces:**
- Verifies the approved spec and all global constraints; produces no new API.

- [ ] **Step 1: Review exact bundle identity and load order**

Confirm the Pages artifact and extension package contain byte-identical engine scripts and that manifest order is engine → paste controller → content script.

- [ ] **Step 2: Review privacy invariants**

Trace every paste path and prove cancellation precedes analysis, sensitive text is not rendered in overlay/target before approval, failures insert nothing, password inputs are excluded, and no network API receives clipboard text.

- [ ] **Step 3: Review fixture authority and coverage**

Confirm expected parity values are generated only by Python and compare complete finding metadata, IDs, ranges, policy behavior, redactions, and audit output using synthetic data.

- [ ] **Step 4: Re-run complete verification**

Run the exact Task 6 Step 5 suite from a clean checkout and record outputs.

- [ ] **Step 5: Prepare deployment commit without pushing automatically**

Confirm the working tree contains only intended changes. Pushing to `jhanvimehndiratta/hackaholics` is an external action and requires the user's explicit command or approval at execution time.
