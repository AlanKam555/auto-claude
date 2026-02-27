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
6. **Test before deploy** — Run `python tests/run_all.py` and all 213 tests must pass before any deployment.

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
│   ├── vault.py               ← Encrypted secrets storage + per-skill scoping
│   └── audit.py               ← Structured audit logging (JSON lines)
│
├── api/
│   ├── __init__.py
│   ├── webhook.py             ← Meta webhook handler + WhatsApp message sender
│   └── admin.py               ← Admin REST API (/admin/stats, /users, /skills)
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
│   └── run_all.py             ← 213-test security suite (run before every deploy)
│
├── config/                    ← Created at runtime, NEVER commit this folder
│   ├── whitelist.json          ← Authorized phone numbers (auto-generated)
│   ├── vault.enc               ← Encrypted secrets (auto-generated)
│   ├── reminders.json          ← Persistent reminders (auto-generated)
│   └── history/                ← Conversation history per phone (auto-generated)
│
├── Dockerfile                 ← Production container image
├── docker-compose.yml         ← Full stack orchestration
├── pyproject.toml             ← PEP 518 project metadata
└── .github/
    └── workflows/
        └── ci.yml             ← Automated testing on push/PR
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
7. Run the full test suite — all tests must pass

## How to Add a New Injection Pattern

When discovering a new prompt injection attack pattern:

1. Open `security/injection.py`
2. Add the regex pattern to `INJECTION_PATTERNS` with an appropriate label
3. Add a test case in `tests/run_all.py` under `test_prompt_injection()`
4. Run `python tests/run_all.py --component injection` to verify it catches the attack
5. Also verify no safe messages are caught as false positives

## Current Status

### Core Architecture
- [x] FastAPI + Uvicorn application with health check endpoint
- [x] Multi-layer security pipeline (auth → rate limit → injection → skill/Claude → filter → deliver)
- [x] Docker sandbox for skill execution with resource limits
- [x] Fernet-encrypted secrets vault with per-skill scoping
- [x] Production Dockerfile and docker-compose.yml

### Security (25+ attack patterns)
- [x] Prompt injection filter — 25+ pattern categories with severity weighting
- [x] Base64-encoded payload detection
- [x] External content wrapping (`filter_external_content()`)
- [x] Response filtering — API keys, tokens, private keys, env vars redacted
- [x] HMAC-SHA256 webhook signature verification
- [x] Timestamp replay protection (5-minute window)
- [x] Per-phone rate limiting with configurable windows
- [x] Message deduplication (5-minute ID tracking)
- [x] Request body size limiting (1 MB max)

### Authentication & Authorization
- [x] Phone number whitelist with E.164 normalization
- [x] 3-tier RBAC — user, power_user, admin (9 permissions)
- [x] Optional PIN system with constant-time comparison
- [x] Open access mode for development/testing
- [x] Permission-based skill filtering (users only see/execute allowed skills)

### AI & Skills
- [x] Claude tool-use integration — skills invoked via natural language (no slash command needed)
- [x] 4 built-in content skills: web_search, summarize_url, set_reminder, get_weather
- [x] 3 admin skills: /whitelist, /vault, /reminders
- [x] System skills: /help, /status, /clear
- [x] Persistent conversation history per phone (config/history/)
- [x] Persistent reminders with disk storage (config/reminders.json)
- [x] Docker images for each skill (skills/docker/)
- [x] Context window trimming with token estimation

### Message Delivery
- [x] Message chunking for WhatsApp's 4096-char limit (paragraph/line/space boundaries)
- [x] Exponential backoff retry on transient delivery failures
- [x] Sequential chunk delivery with ordering guarantees
- [x] Read receipts — messages marked as read via WhatsApp API
- [x] Media message handling — graceful responses for images, audio, video, documents, stickers, location

### Input Sanitization
- [x] Phone number sanitization — strip non-digit chars, enforce E.164, max length
- [x] Message content sanitization — strip control chars, enforce length limit (10 KB)

### Admin REST API
- [x] `/admin/stats` — system metrics, uptime, version (API key protected)
- [x] `/admin/users` — list whitelisted users and roles (API key protected)
- [x] `/admin/skills` — list registered skills with metadata (API key protected)

### Claude API Resilience
- [x] Exponential backoff retry on rate limits (429), server errors (5xx), connection errors
- [x] Configurable max retries via `CLAUDE_MAX_RETRIES` env var

### Audit Trail
- [x] Structured JSON audit log (config/audit.log) with size-based rotation
- [x] All security events logged — auth, injection, skill exec, cooldown, Claude errors
- [x] Phone number masking for privacy
- [x] `read_recent_events()` API for programmatic access
- [x] Integrated into full pipeline (agent, webhook, skills)

### Skill Cooldowns
- [x] Per-user, per-skill cooldowns to prevent API abuse
- [x] Configurable cooldown durations per skill (SKILL_COOLDOWNS dict)
- [x] Separate tracking per user — one user's cooldown doesn't affect others

### Testing — 213 tests, all passing
- [x] 25 injection detection tests (patterns + false-positive safety)
- [x] 18 auth & RBAC tests (whitelist, roles, rate limits, PIN)
- [x] 10 sandbox configuration tests
- [x] 8 vault encryption tests (CRUD, persistence, clear)
- [x] 7 webhook tests (signature, timestamp, message extraction)
- [x] 7 skill routing tests (matching, enable/disable, schema)
- [x] 20 skill handler tests (mocked HTTP, error handling)
- [x] 12 admin skill tests (whitelist/vault CRUD, permissions)
- [x] 3 integration tests (imports, pipeline, gitignore)
- [x] 10 end-to-end pipeline tests (auth → injection → skill → response)
- [x] 14 agent feature tests (tool-use, history, chunking, retry)
- [x] 25 application & hardening tests (health, versioning, edge cases)
- [x] 16 production feature tests (dedup, permissions, context trimming, metrics)
- [x] 20 v1.2 enhancement tests (sanitization, media, admin API, retry, receipts)
- [x] 18 v1.3 feature tests (audit logging, cooldowns, export, deep health, status events)

### DevOps
- [x] GitHub Actions CI workflow (Python 3.11/3.12, all tests)
- [x] Production Dockerfile (non-root, health check)
- [x] docker-compose.yml for full stack deployment
- [x] pyproject.toml for PEP 518 compliance
- [x] /metrics endpoint for operational monitoring
- [x] Structured JSON logging (LOG_FORMAT=json)
- [x] Graceful shutdown with reminder flush

### Remaining (External/Deployment)
- [ ] Meta developer app setup & credentials
- [ ] ngrok / production webhook configured
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
