# Sentinel Browser Engine and Real-Time Extension Design

## Context

Sentinel currently depends on a Chrome extension bridge and a FastAPI service on `127.0.0.1:8787`. The public GitHub Pages client therefore renders successfully but cannot analyze text on its own. The project needs two independent browser-facing modes:

1. A public GitHub Pages application that analyzes arbitrary text entirely in the browser.
2. A public Manifest V3 extension that intercepts paste events in supported editable fields on normal webpages.

The Python engine remains the behavioral reference and an optional higher-assurance local mode. Neither the hosted application nor the public extension requires FastAPI.

## Goals

- Match the Python engine's externally observable behavior in JavaScript.
- Analyze arbitrary text locally in the public site without sample-only shortcuts.
- Use the same JavaScript engine for real-time paste interception on ordinary webpages.
- Prevent sensitive clipboard content from entering the target DOM before an explicit user decision.
- Preserve sanitized audit behavior without storing raw prompts or secrets.
- Clearly explain broad extension permissions and installation boundaries.

## Non-goals

- GitHub Pages does not host or emulate FastAPI.
- Visiting the public site does not install or activate the extension.
- The extension does not operate on browser-controlled pages, extension pages, or password fields.
- No clipboard text is sent to a cloud service.
- No attempt is made to bypass browser security restrictions.

## Architecture

### Shared browser engine

Add a dependency-free, browser-safe JavaScript engine that exposes a stable global such as `globalThis.SentinelEngine`. It must not rely on ES-module loading inside extension content scripts. The extension manifest loads the shared engine script before `content.js`; the GitHub Pages client includes it with a normal script tag before `app.js`.

The engine exposes:

- `analyzeText(text, policy)`
- `redactText(text, findingIds, policy)`
- `AuditStore`

It implements the same detectors, policy validation, entropy threshold, overlap suppression, finding ordering, deterministic IDs, safe previews, replacements, redaction validation, and sanitized audit exports as the Python reference.

### Python-owned parity fixtures

Python remains the source of truth. A Python fixture-generation step runs the reference implementation over synthetic test inputs and emits expected JSON fixtures. JavaScript tests consume those fixtures and compare complete observable results. Fixture inputs must use synthetic secrets only.

The parity contract covers:

- Decisions and policy errors
- Finding IDs, types, severities, rules, previews, replacements, and ranges
- Overlap precedence and finding order
- Selected and full redaction results
- Unknown finding-ID errors
- Audit event fields and ordering
- JSON and Markdown audit summaries, excluding nondeterministic timestamp equality

### Standalone GitHub Pages application

The demo client uses the shared browser engine directly for health, analysis, redaction, audit, and export. It no longer waits for an extension response. The status area identifies the active runtime as an on-device browser engine.

Paste in the demo playground follows the same review-before-insertion contract as the extension. Arbitrary text is supported; samples remain convenience inputs only.

### Real-time extension

The extension declares `<all_urls>` for normal webpage access and explains why this broad permission is needed. Chrome's restricted schemes remain unavailable; the implementation also explicitly limits itself to HTTP and HTTPS documents.

Supported editable targets:

- `textarea`
- `input[type=text]`
- `input[type=search]`
- `input[type=url]`
- `input[type=email]`
- `contenteditable` elements

Excluded targets include password inputs and all unsupported input types.

The manifest loads the browser engine before `content.js`. The content script performs analysis locally and does not depend on the service worker, FastAPI, dynamic imports, or cloud requests for its default paste path.

## Paste data flow and safety invariant

1. A capture/capture-phase paste listener identifies a supported editable target.
2. It immediately calls `preventDefault()` and `stopImmediatePropagation()` before reading or analyzing the clipboard payload.
3. It snapshots the target and selection/caret state.
4. The shared engine analyzes the clipboard text locally.
5. Safe text may be inserted after successful analysis according to the defined safe flow. Sensitive text opens the Sentinel decision overlay without inserting the original payload.
6. `Block` inserts nothing.
7. `Redact and insert` recomputes validated redaction and inserts only the redacted output.
8. `Allow once` inserts the original text for this event only.
9. Selection/caret is restored correctly for both textarea-like controls and contenteditable ranges.
10. If analysis throws, is unavailable, or fails to return a valid result, the paste remains blocked and a clear local error is shown.

The load-bearing invariant is: **the original sensitive clipboard text must never enter the target DOM before the user explicitly chooses Allow once.** The overlay must render only safe previews and replacements, never the raw secret.

## Error handling

- Invalid policy values produce the same error semantics as Python.
- Unknown finding IDs are rejected before redaction.
- Engine initialization or analysis failure fails closed: no insertion occurs.
- Lost or invalid selection state does not trigger insertion at an arbitrary location; the user must retry.
- Unsupported or restricted pages receive no injected behavior.
- Audit failures cannot weaken paste blocking or cause raw values to be retained.

## Permissions and privacy communication

The README and extension-facing UI explain that `<all_urls>` is broad because real-time interception must work across normal webpages with editable fields. They also state:

- Processing occurs locally in the browser.
- Clipboard text is never sent to a cloud service.
- Password fields are excluded.
- Browser and extension pages are not accessible.
- The public GitHub Pages site works independently.
- Cross-site interception requires installing the extension, either unpacked for the demo or through a future Chrome Web Store listing.
- Opening GitHub Pages does not auto-install the extension.

## Testing

### Parity tests

- Generate canonical fixtures from Python.
- Run JavaScript engine tests against those fixtures.
- Compare findings, IDs, ranges, metadata, previews, replacements, policies, redactions, and audit behavior.
- Ensure every fixture and screenshot uses synthetic credentials and identities.

### DOM and extension tests

- Verify interception for every supported field type.
- Verify password and unsupported fields are ignored.
- Verify selection replacement and caret restoration in `textarea` and contenteditable targets.
- Verify the sensitive original is absent from target value/DOM before any action.
- Verify Block inserts nothing.
- Verify Redact inserts only validated redacted text.
- Verify Allow once inserts the original only after selection.
- Simulate engine failure by blocking or replacing the analysis response and confirm paste remains blocked.
- Verify the content script has no network dependency in its default path.

### End-to-end checks

- GitHub Pages analyzes arbitrary text with no extension and no FastAPI process.
- The unpacked extension intercepts paste on representative HTTP/HTTPS editable pages.
- Local FastAPI tests continue passing as the reference implementation.
- CI runs Python tests, fixture generation/consistency checks, JavaScript parity tests, and syntax/manifest validation.

## Security boundaries

- All fixtures, examples, demos, and screenshots use synthetic secrets only.
- No raw prompt or clipboard value enters audit records.
- No network fallback is allowed for browser analysis.
- `<all_urls>` is limited in code to supported editable elements in HTTP/HTTPS documents.
- Public installation requires a Chrome Web Store release or an unpacked developer installation; the website cannot install the extension automatically.
