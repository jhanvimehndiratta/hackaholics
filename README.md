# Sentinel — Zero-Cloud Local Prompt & Clipboard Privacy Firewall

[![Sentinel CI](https://github.com/jhanvimehndiratta/hackaholics/actions/workflows/ci.yml/badge.svg)](https://github.com/jhanvimehndiratta/hackaholics/actions/workflows/ci.yml)
[![Deploy Demo to GitHub Pages](https://github.com/jhanvimehndiratta/hackaholics/actions/workflows/pages.yml/badge.svg)](https://github.com/jhanvimehndiratta/hackaholics/actions/workflows/pages.yml)
[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/jhanvimehndiratta/hackaholics)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/downloads/)
[![Chrome Extension Manifest V3](https://img.shields.io/badge/extension-Manifest%20V3-brightgreen.svg)](https://developer.chrome.com/docs/extensions/develop/migrate/what-is-mv3)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Sentinel** is a high-assurance, local-first privacy firewall that intercepts AI prompts and clipboard paste events before sensitive data can leak to external LLMs or cloud providers.

All detection, pattern analysis, Shannon entropy scoring, and redaction execute **100% locally on localhost with zero outbound cloud telemetry**.

---

## Architecture Overview

```text
┌────────────────────────────────────────────────────────┐
│               Browser / Web Client / DOM               │
│                                                        │
│  User types prompt / pastes clipboard data into input  │
└──────────────────────────┬─────────────────────────────┘
                           │ Intercepted in capture phase
                           ▼
┌────────────────────────────────────────────────────────┐
│           Chrome Extension (Manifest V3)               │
│                                                        │
│  • Content Script: intercepts paste & prompt submit    │
│  • Background Service Worker: relays to localhost      │
└──────────────────────────┬─────────────────────────────┘
                           │ Local HTTP (127.0.0.1:8787)
                           ▼
┌────────────────────────────────────────────────────────┐
│         Sentinel Deterministic Engine (FastAPI)        │
│                                                        │
│  • RFC1918 Private IPv4 Detector (10/8, 172.16/12, etc)│
│  • High-Entropy & Generic API Secret Detector          │
│  • Named Credentials & Config Assignment Parser        │
│  • Structured Database URL Detector                    │
│  • PII (Emails, Names, Phone) Detector                 │
│  • Overlap & Precedence Conflict Resolver              │
│  • In-Memory Zero-Secret Audit Trail                   │
└──────────────────────────┬─────────────────────────────┘
                           │ Explainable Findings & Policy
                           ▼
┌────────────────────────────────────────────────────────┐
│               Interactive Decision Modal               │
│                                                        │
│     [ Block ]    [ Redact & Send ]    [ Allow Once ]   │
└────────────────────────────────────────────────────────┘
```

---

## 🚀 GitHub Repository

This project is published from [`jhanvimehndiratta/hackaholics`](https://github.com/jhanvimehndiratta/hackaholics) on the `main` branch.

To clone it:

```bash
git clone https://github.com/jhanvimehndiratta/hackaholics.git
cd hackaholics
```

To push an existing local checkout that does not yet have a remote:

```bash
git remote add origin https://github.com/jhanvimehndiratta/hackaholics.git
git branch -M main
git push -u origin main
```

---

### 2. Automated GitHub Actions CI

Once pushed, GitHub Actions immediately runs the test and validation matrix on every push or PR:

- **Python Version Matrix**: Automatically tests against **Python 3.9, 3.10, 3.11, and 3.12**.
- **Engine Unit Tests**: Runs `unittest discover -s engine/tests -v` (28/28 tests verifying RFC1918 rules, redaction safety, reverse index slicing, entropy detection, and audit isolation).
- **Extension & Client Validation**: Verifies Chrome Manifest V3 JSON schema compliance and validates JavaScript syntax using `node --check`.

Workflow file: [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

---

### 3. Automated GitHub Pages Demo

The static client is published at [jhanvimehndiratta.github.io/hackaholics](https://jhanvimehndiratta.github.io/hackaholics/).

One repository setting is required: open **Settings → Pages**, then set **Source** to **GitHub Actions**. If the source remains **Deploy from a branch**, GitHub runs the legacy `pages-build-deployment` flow and may render this README instead of `demo-client/`.

A push to `main` that changes `demo-client/` or the Pages workflow deploys the static files through [`.github/workflows/pages.yml`](.github/workflows/pages.yml).

> **Static hosting boundary:** GitHub Pages hosts only the HTML, CSS, and JavaScript client. It does not run the FastAPI backend. Live analysis still requires the engine on `127.0.0.1:8787` and the unpacked Chrome extension. If Chrome blocks a hosted HTTPS page from reaching localhost, use Pages as a static preview and run the fully functional demo at `http://127.0.0.1:4173`.

---

### 4. 1-Click GitHub Codespaces

Sentinel includes a complete [`.devcontainer/devcontainer.json`](.devcontainer/devcontainer.json) configuration:

1. Click **Code** > **Codespaces** > **Create codespace on main**.
2. Codespaces automatically installs Python 3.11, Node.js, and dependencies via `pip install -r requirements.txt`.
3. Ports `8787` (Engine API) and `4173` (Demo Web Client) are automatically forwarded.

---

## 💻 Local Quickstart

### Prerequisites
- Python 3.9+
- Google Chrome or Chromium-based browser
- Node.js 18+ (optional, for JS validation)

### 1. Start the Engine & Demo Client

```bash
# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Option A: Start both services together
bash scripts/run-demo.sh

# Option B: Start services independently
python3 -m uvicorn engine.app:app --host 127.0.0.1 --port 8787
python3 -m http.server 4173 --bind 127.0.0.1 --directory demo-client
```

Open your browser at `http://127.0.0.1:4173`.

---

### 2. Install the Chrome Extension

1. Open Chrome and navigate to `chrome://extensions`.
2. Toggle **Developer mode** in the top right.
3. Click **Load unpacked** and select the `sentinel/extension/` directory.
4. Refresh `http://127.0.0.1:4173` — the top header will display **● Engine Online (127.0.0.1:8787)**.

---

## 🧪 Testing

Run the comprehensive unit test suite:

```bash
PYTHONPATH=. python3 -m unittest discover -s engine/tests -v
```

Validate Manifest V3 and JavaScript syntax:

```bash
node -e 'const m = JSON.parse(require("fs").readFileSync("extension/manifest.json")); if (m.manifest_version !== 3) throw new Error();'
node --check demo-client/app.js
node --check extension/background.js
node --check extension/content.js
```

---

## 🛡️ Key Features

- **DOM Paste Firewall**: Captures clipboard paste events in the DOM capture phase, blocks propagation, analyzes payload against localhost rules, and triggers an interactive redaction modal before insertion.
- **RFC1918 Private IPv4 Detector**: Accurately matches `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16` boundaries while ignoring public IPs, loopbacks, and non-RFC1918 ranges.
- **Deterministic Redaction**: Multi-tiered suppression hierarchy prevents range corruption and double-masking.
- **Configurable Policy Modes**:
  - `Strict`: Flags all potential secrets, emails, internal IPs, and high-entropy strings.
  - `Balanced`: Standard protection for API keys, passwords, and private infrastructure.
  - `Permissive`: Blocks only critical secrets and database credentials.
- **Zero-Cloud Audit Export**: Export activity logs in JSON or Markdown directly from the local in-memory audit store without persisting raw sensitive text.

---

## 📁 Repository Structure

```text
sentinel/
├── .devcontainer/
│   └── devcontainer.json        # 1-Click GitHub Codespaces configuration
├── .github/
│   └── workflows/
│       ├── ci.yml               # Python 3.9-3.12 CI matrix & JS syntax check
│       └── pages.yml            # Automated GitHub Pages static deployment
├── demo-client/                 # Interactive web workspace & paste demo
│   ├── index.html
│   ├── app.js
│   └── styles.css
├── engine/                      # Deterministic Python detection & redaction engine
│   ├── app.py                   # FastAPI REST API endpoints
│   ├── domain.py                # Regex, entropy, and redaction logic
│   └── tests/                   # 28-case standard library test suite
│       └── test_engine.py
├── extension/                   # Manifest V3 Chrome Extension
│   ├── manifest.json
│   ├── background.js            # Service worker communicating with 127.0.0.1:8787
│   ├── content.js               # DOM paste & submit interceptor
│   └── icons/
├── scripts/
│   └── run-demo.sh              # One-command local startup script
├── .gitignore
├── requirements.txt
└── README.md
```

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.
