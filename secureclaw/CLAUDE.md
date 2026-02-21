# CLAUDE.md

This file is the primary context document for Claude Code. Read this fully before making any changes to the codebase.

## Project Overview

SecureClaw is a secure, open-source agentic AI platform for WhatsApp, built on the official Meta WhatsApp Cloud API and powered by Claude Opus 4.6. It is being developed as a proposed joint initiative between Meta and Anthropic.

The project was initiated by an independent developer who retains no credit, equity, or IP. All rights belong to Meta and Anthropic.

## Why This Project Exists

OpenClaw (formerly Clawdbot / Moltbot) went viral in January 2026 with 179,000+ GitHub stars but was banned by Meta and major enterprises in February 2026 due to:

- 512 documented security vulnerabilities (8 critical)
- 341 malicious skills on its marketplace (ClawHavoc campaign)
- Use of unofficial WhatsApp web scraping (violates Meta ToS)
- No sandboxing — skills had direct host filesystem access
- Prompt injection vulnerabilities allowing malicious emails to hijack the agent
- OpenClaw is now owned by OpenAI (Meta's competitor)

SecureClaw is the security-first, official-API alternative.

## Core Principles (Never Violate These)

1. **Official API only** — Never use unofficial WhatsApp web scraping. Only the Meta WhatsApp Cloud API.
2. **Security first** — Every feature must pass the security test suite before merging.
3. **Sandboxed execution** — Skills ALWAYS run in Docker containers. No exceptions.
4. **Least privilege secrets** — Skills only receive the secrets they explicitly declare in their manifest.
5. **Prompt injection defense** — All external content (emails, documents, web pages) must be wrapped as untrusted before passing to the LLM.
6. **Test before deploy** — Run `python tests/run_all.py` and all 98 tests must pass before any deployment.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.11+ |
| Web framework | FastAPI + Uvicorn |
| AI model | Claude Opus 4.6 (adaptive thinking) via Anthropic SDK |
| WhatsApp | Meta WhatsApp Cloud API (official) |
| Skill isolation | Docker containers |
| Secrets | Fernet encrypted vault (cryptography library) |
| Auth | Phone number whitelist + RBAC + optional PIN |
| Testing | Custom security test suite (tests/run_all.py) |

## Project Structure

```
secureclaw/
├── CLAUDE.md                  ← YOU ARE HERE
├── main.py                    ← FastAPI app entry point + webhook endpoints
├── requirements.txt           ← Python dependencies
├── .env.template              ← Environment variable template (copy to .env)
├── .gitignore                 ← Ensures .env and config/ never get committed
├── README.md                  ← Public-facing documentation
│
├── core/
│   ├── __init__.py
│   └── agent.py               ← Claude Opus 4.6 agentic loop (main AI logic)
│
├── security/
│   ├── __init__.py
│   ├── auth.py                ← Phone whitelist + permissions + PIN system
│   ├── injection.py           ← Prompt injection filter (25+ attack patterns)
│   ├── sandbox.py             ← Docker skill execution + resource limits
│   └── vault.py               ← Encrypted secrets storage + per-skill scoping
│
├── api/
│   ├── __init__.py
│   └── webhook.py             ← Meta webhook handler + WhatsApp message sender
│
├── skills/
│   ├── __init__.py
│   ├── registry.py            ← Skill definitions + handler implementations
│   └── docker/                ← Dockerfiles for sandboxed skill execution
│       ├── web_search/        ← Tavily API search container
│       ├── summarize_url/     ← URL fetch & extract container
│       └── weather/           ← OpenWeather API container
│
├── tests/
│   └── run_all.py             ← 98-test security suite (run before every deploy)
│
└── config/                    ← Created at runtime, NEVER commit this folder
    ├── whitelist.json          ← Authorized phone numbers (auto-generated)
    └── vault.enc               ← Encrypted secrets (auto-generated)
```

## Key Files to Understand First

When working on this project, always read these files before making changes:

1. **security/injection.py** — The prompt injection filter. Any new external data source (email, web, document) must pass through `filter_external_content()` before reaching the LLM.
2. **security/auth.py** — The `Permission` enum defines all capabilities. New skills must map to existing permissions.
3. **core/agent.py** — The main agentic loop. Uses Opus 4.6 with `thinking={"type": "adaptive"}`. Do not change the model or disable thinking.
4. **tests/run_all.py** — The test suite. When adding new security features, add corresponding tests here.

## Environment Variables Required

```
ANTHROPIC_API_KEY=        # From console.anthropic.com
WHATSAPP_TOKEN=           # Meta Cloud API bearer token
WHATSAPP_PHONE_ID=        # WhatsApp Phone Number ID
WEBHOOK_VERIFY_TOKEN=     # Random string for Meta webhook verification
ADMIN_PHONE=              # Your WhatsApp number in E.164 format (+6512345678)
VAULT_ENCRYPTION_KEY=     # Auto-generated on first run — copy output to here
```

## How to Run

```bash
# Install dependencies
pip install -r requirements.txt

# Create __init__.py files if missing
touch core/__init__.py security/__init__.py api/__init__.py skills/__init__.py

# Create config directory
mkdir -p config

# Run security tests first
ADMIN_PHONE="+6512345678" python tests/run_all.py

# Start the server
python main.py

# In another terminal, expose via ngrok
ngrok http 8000
```

## How to Add a New Skill

1. Define the skill in `skills/registry.py` as a `Skill` dataclass
2. Declare `requires_network` (True/False) and `required_secrets` (list of env var names)
3. Define the `input_schema` (used to build Anthropic tool definition)
4. Create the Docker image for the skill (in `skills/docker/<skill_name>/`)
5. Register it in `SkillRegistry._register_builtins()` or via `registry.register(skill)`
6. Add a test in `tests/run_all.py` under `test_sandbox_config()`
7. Run the full test suite — all 98 tests must pass

## How to Add a New Injection Pattern

When discovering a new prompt injection attack pattern:

1. Open `security/injection.py`
2. Add the regex pattern to `INJECTION_PATTERNS` with an appropriate label
3. Add a test case in `tests/run_all.py` under `test_prompt_injection()`
4. Run `python tests/run_all.py --component injection` to verify it catches the attack
5. Also verify no safe messages are caught as false positives

## Current Status

- [x] Core architecture scaffolded
- [x] Security test suite — 98 tests, all passing
- [x] Prompt injection filter — 25+ attack patterns
- [x] Authentication & RBAC system
- [x] Encrypted secrets vault
- [x] Docker sandbox configuration
- [x] Webhook handler structure
- [x] 4 built-in skills fully implemented (web_search, summarize_url, set_reminder, get_weather)
- [x] Web search skill — Tavily API integration with error handling
- [x] URL summarization skill — HTML fetching, tag stripping, text extraction
- [x] Reminder skill — async scheduling with delay parsing (e.g., "in 30 minutes")
- [x] Weather skill — OpenWeather API with formatted display
- [x] Docker images for each built-in skill (skills/docker/)
- [x] 20 handler-level tests with mocked HTTP responses
- [x] Timestamp validation for webhook replay attack prevention
- [x] Rate limiting per phone number
- [ ] Meta developer app setup & credentials
- [ ] ngrok / production webhook configured
- [ ] First end-to-end message test
- [ ] Meta BSP application submitted

## Partnership Context

This project is simultaneously being proposed to:

- **Meta** — as a WhatsApp Business Solution Provider (BSP) initiative
- **Anthropic** — as a collaboration using Claude Opus 4.6 as the AI backbone

The pitch document (SecureClaw_Meta_Anthropic_Collaboration_Pitch.docx) has been prepared and is ready to submit. The developer is not seeking credit — all IP is intended for Meta and Anthropic jointly.

## Security Rules for Claude Code

When working in this codebase:

- **Never** hardcode API keys, tokens, or secrets in any file
- **Never** bypass the injection filter — all external content must go through `filter_external_content()`
- **Never** remove Docker isolation from the sandbox
- **Never** give skills broader secret access than they declare in `required_secrets`
- **Always** run the test suite after security-related changes
- **Never** commit the `config/` directory or `.env` file
- **Always** use E.164 format for phone numbers (+countrycode + number)
- **Always** use `hmac.compare_digest()` for token comparisons (prevents timing attacks)

## Contacts & Resources

- Meta WhatsApp Cloud API docs: https://developers.facebook.com/docs/whatsapp/cloud-api
- Anthropic Claude API docs: https://docs.anthropic.com
- Anthropic Console: https://console.anthropic.com
- Meta Developer Console: https://developers.facebook.com
- ngrok (for local webhook testing): https://ngrok.com
