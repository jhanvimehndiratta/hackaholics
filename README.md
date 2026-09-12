# Sentinel

Sentinel is a local-first privacy firewall for AI prompts. It intercepts a prompt in a controlled demonstration workspace, analyzes it on localhost with deterministic rules, and lets the user block it, redact selected findings, or allow that one interaction.

The MVP uses **local pattern- and entropy-assisted detection**. It does not call an AI model, upload prompts for inspection, or depend on a paid/external service.

## What the demo proves

```text
Prompt composed in controlled workspace
              ↓
Chrome extension intercepts before simulated send
              ↓
Service worker sends text to 127.0.0.1:8787
              ↓
Deterministic engine returns explainable findings
              ↓
Block | Redact & Send | Allow Once
              ↓
Only the permitted result reaches the transcript
```

- **Block** keeps the original prompt out of the simulated workspace.
- **Redact & Send** replaces selected engine-issued finding ranges with deterministic placeholders before sending.
- **Allow Once** sends the original for that interaction only. Nothing is allowlisted, so the next submission is analyzed again.
- The activity rail and in-memory engine audit store only timestamps, decisions, finding categories/counts, and whether a simulated send occurred. They do not store raw prompts or secrets.

## Project structure

```text
sentinel/
├── demo-client/        # Static controlled AI workspace
├── engine/             # FastAPI API and pure-Python detection domain
│   └── tests/          # Standard-library unittest suite
├── extension/          # Manifest V3 content script + service worker
├── scripts/run-demo.sh # Starts both local services
├── requirements.txt
└── README.md
```

## Requirements

- Python 3.10+
- Chrome or Chromium with extension developer mode
- No internet connection, external AI service, or paid API is required.

## Setup

From the `sentinel/` directory, create an isolated environment and install the small local stack:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

Start the engine and client together:

```bash
bash scripts/run-demo.sh
```

Or start them separately:

```bash
python3 -m uvicorn engine.app:app --host 127.0.0.1 --port 8787
python3 -m http.server 4173 --bind 127.0.0.1 --directory demo-client
```

Open `http://127.0.0.1:4173`.

## Load the extension

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Choose **Load unpacked**.
4. Select the absolute path to `sentinel/extension/`.
5. Refresh the controlled workspace. Its header should report **Local engine connected**.

The Manifest V3 content script listens only on localhost/127.0.0.1 pages. It relays a fixed allowlist of request actions to the background service worker. The service worker alone has host permission for `127.0.0.1:8787`; this is the chosen Chromium-safe fallback for extension-to-localhost/private-network handling. No browser security setting needs to be disabled.

The static client includes a direct-localhost fallback so the interface can still be inspected during development. The judged extension flow is visible in Chrome DevTools: the content script receives `sentinel:request`, and its service worker issues the engine request.

## Demo inputs

The workspace includes three one-click samples:

- **Safe** — a normal implementation question; no findings, so it sends immediately after the local check.
- **Sensitive** — AWS-shaped access key, password-bearing PostgreSQL URL, internal IP, and email; review appears before any send.
- **Ambiguous** — a long UUID-like build identifier without a named secret context; it is not overclaimed as a secret.

Secret-like entropy detection is deliberately supporting evidence only. It requires a named `token`, `secret`, `key`, or `password` context, at least 24 token characters, and Shannon entropy of at least 3.5 bits per character.

## Automated tests

The engine domain suite uses only Python's standard library, so it can run before dependencies are installed. From the repository directory containing `sentinel/`:

```bash
PYTHONPATH=sentinel python3 -m unittest discover -s sentinel/engine/tests -v
```

It verifies each required detector class, public-IP exclusion, explainable findings, range-safe redaction, unknown finding rejection, sanitized audit data, and non-persistence of Allow Once.

## Manual smoke-test checklist

- [ ] Start the engine and demo client.
- [ ] Load the unpacked extension and refresh the workspace.
- [ ] Confirm the header reads **Local engine connected**.
- [ ] Submit the **Sensitive** sample.
- [ ] Confirm the checkpoint review appears before a message enters the transcript.
- [ ] Choose **Redact & Send** and verify only placeholders reach the transcript.
- [ ] Reset, repeat with **Block**, and verify no message is sent.
- [ ] Reset, repeat with **Allow once**, and verify the original is sent for that interaction.
- [ ] Submit the sensitive sample again and verify review appears again (no persistent bypass).
- [ ] Submit **Safe** and verify it sends immediately.
- [ ] Submit **Ambiguous** and verify the context-free identifier is not called a secret.
- [ ] Inspect `GET http://127.0.0.1:8787/audit` and verify events contain no raw prompt values.

## API contract

- `GET /health` — local service readiness.
- `POST /analyze` with `{ "text": "..." }` — returns `allow` or `review_required` and safe findings.
- `POST /redact` with `{ "text": "...", "findingIds": ["finding-1"] }` — recomputes the analysis and accepts only IDs valid for that text.
- `POST /audit` — records a sanitized decision event.
- `GET /audit` — returns the current in-memory demo audit record.

## Limitations and claims

This is a controlled demonstration client, not an integration with ChatGPT, Claude, Gemini, or another third-party AI workspace. The audit is a demo audit record, not immutable enterprise logging. Pattern-based local detection can miss novel secret formats and can produce false positives; rules and entropy thresholds require tuning for a real organization. The in-memory audit resets when the engine restarts. Findings are deterministic and explainable, but this MVP is not a replacement for a mature DLP platform.
