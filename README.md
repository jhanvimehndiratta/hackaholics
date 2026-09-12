# Sentinel — Local Prompt & Clipboard Privacy Firewall

[![Sentinel CI](https://github.com/jhanvimehndiratta/hackaholics/actions/workflows/ci.yml/badge.svg)](https://github.com/jhanvimehndiratta/hackaholics/actions/workflows/ci.yml)
[![Pages](https://github.com/jhanvimehndiratta/hackaholics/actions/workflows/pages.yml/badge.svg)](https://jhanvimehndiratta.github.io/hackaholics/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Sentinel detects and redacts sensitive values before an AI prompt or clipboard paste leaves your control. Detection is deterministic and runs on-device; clipboard text is never sent to a cloud service.

## Try the standalone web app

Open **https://jhanvimehndiratta.github.io/hackaholics/**. The GitHub Pages app analyzes arbitrary text locally using the browser engine. It requires no FastAPI server and no extension.

The page is a controlled prompt simulation. Visiting it **does not install or activate the Chrome extension** and therefore cannot intercept paste events on other websites.

## Browser extension

The extension uses the same browser engine as the Pages app and intercepts paste before insertion on supported fields:

- `textarea`
- `input` types `text`, `search`, `url`, and `email`
- `contenteditable` regions

It does not inspect password inputs. Chrome does not inject content scripts into protected pages such as `chrome://`, browser settings, or extension pages.

### Why it requests access to all sites

The manifest uses `<all_urls>` so Sentinel can protect supported editable fields on ordinary websites, including AI chat sites. This is a broad permission: Chrome may describe it as permission to read and change data on websites you visit. Sentinel uses that access only to observe paste events in the supported fields above, analyze clipboard text locally, and display a local review dialog. It has no cloud endpoint, telemetry, or host permission.

Paste handling is fail-closed: Sentinel cancels the browser paste synchronously. Safe text is inserted only after analysis succeeds. Sensitive text remains outside the target DOM until you explicitly choose **Allow once**; **Redact and paste** inserts only the redacted result. If analysis fails, nothing is inserted.

### Install from source

1. Clone the repository:
   ```bash
   git clone https://github.com/jhanvimehndiratta/hackaholics.git
   cd hackaholics
   ```
2. Open `chrome://extensions` in Chrome or Chromium.
3. Enable **Developer mode**.
4. Choose **Load unpacked** and select the `extension/` directory.

A future Chrome Web Store listing can provide normal installation; GitHub Pages cannot install an extension automatically.

## Detection policies

- **Balanced:** database URLs containing credentials, AWS and GitHub tokens, named API keys/passwords, email addresses, and RFC1918 private IPv4 addresses.
- **Strict:** Balanced rules plus high-entropy values in named secret contexts (Shannon entropy `>= 3.5`).

Findings include deterministic IDs, exact character ranges, severity, a safe preview, and a replacement. Redaction reanalyzes the original text and applies validated replacements from right to left. Audit records contain decisions and finding categories, never raw prompt or clipboard values.

## Optional Python reference mode

The FastAPI implementation remains the higher-assurance reference and fixture authority. It is not required by the Pages app or extension.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 -m uvicorn engine.app:app --host 127.0.0.1 --port 8787
```

Run the local static client separately if desired:

```bash
python3 -m http.server 4173 --bind 127.0.0.1 --directory demo-client
```

## Tests

```bash
PYTHONPATH=. python3 -m unittest discover -s engine/tests -v
node --test tests/browser-engine.test.js tests/paste-firewall.test.js
cmp shared/sentinel-engine.js extension/shared/sentinel-engine.js
```

The Python generator owns `tests/fixtures/browser-engine-parity.json`. CI regenerates it and detects drift, compares complete analyses/redactions/audit exports, tests fail-closed paste behavior and caret restoration, verifies bundle identity, and validates manifest script order.

## Repository layout

```text
engine/                       Python reference detector, redactor, audit, API
shared/sentinel-engine.js     Browser-safe classic-script engine
extension/shared/             Byte-identical packaged browser engine
extension/paste-controller.js Testable fail-closed paste controller
extension/content.js          All-sites interception and local review UI
demo-client/                  Standalone GitHub Pages app
tests/                        Browser parity and paste-firewall tests
```

## GitHub automation

- `.github/workflows/ci.yml` tests Python 3.9–3.12 and the browser/extension implementation.
- `.github/workflows/pages.yml` publishes `demo-client/` plus the shared engine.
- In **Settings → Pages**, choose **GitHub Actions** as the source.
- `.devcontainer/devcontainer.json` provides Codespaces support for ports `8787` and `4173`.

All included credentials and test values are synthetic.

## License

MIT — see [LICENSE](LICENSE).
