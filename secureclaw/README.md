# SecureClaw

Secure AI assistant for WhatsApp, built on the official Meta WhatsApp Cloud API and powered by Claude.

## What is SecureClaw?

SecureClaw is a security-first alternative to OpenClaw for building AI-powered WhatsApp assistants. Every message passes through a multi-layer security pipeline before reaching the AI, and all skills execute inside Docker sandboxes.

### Security Features

- **25+ prompt injection patterns** detected and blocked (with severity weighting)
- **Docker-sandboxed skills** with no host filesystem access, resource limits, non-root execution
- **Least-privilege secrets** — skills only receive declared credentials
- **External content filtering** — emails, docs, and web pages wrapped as untrusted
- **Encrypted vault** — Fernet-encrypted secret storage with 0o600 permissions
- **RBAC** — 3-tier role-based access (user, power_user, admin) with 9 permissions
- **Rate limiting** — per-number message throttling with configurable windows
- **Webhook signature verification** — HMAC-SHA256 + timestamp replay protection (5-min window)
- **Response filtering** — API keys, tokens, private keys automatically redacted
- **175-test security suite** — must pass before every deployment

### AI Features

- **Claude tool-use integration** — skills invoked via natural language, no slash commands needed
- **Persistent conversation history** — per-phone context across sessions
- **Message chunking** — long responses split at paragraph/line boundaries for WhatsApp's 4096-char limit
- **Exponential backoff retry** — resilient message delivery with smart retry logic

## Quick Start

```bash
# Clone and install
git clone <repo-url> && cd secureclaw
pip install -r requirements.txt

# Set up environment
cp .env.template .env
# Edit .env with your API keys

# Run security tests
ADMIN_PHONE="+6512345678" python tests/run_all.py

# Start the server
python main.py

# Expose via ngrok (separate terminal)
ngrok http 8000
```

### Docker Deployment

```bash
# Build and run with Docker Compose
docker-compose up -d

# Or build manually
docker build -t secureclaw .
docker run -p 8000:8000 --env-file .env secureclaw
```

## Architecture

```
User (WhatsApp)
  -> Meta Cloud API
    -> Webhook (HMAC-SHA256 signature + timestamp validation)
      -> Auth Check (phone whitelist + RBAC)
        -> Rate Limit Check
          -> Injection Detection (25+ patterns)
            -> Skill Router (slash commands get priority)
              -> Claude API (with tool-use for natural language skill invocation)
                -> Docker Sandbox (for skill execution)
              -> Response Filter (redact secrets)
                -> Message Chunker (WhatsApp 4096-char limit)
                  -> WhatsApp Reply (with retry + backoff)
```

## Built-in Skills

| Skill | Command | Tool-Use | Network | Secrets |
|-------|---------|----------|---------|---------|
| Web Search | `/search <query>` | Yes | Yes | `TAVILY_API_KEY` |
| Summarize URL | `/summarize <url>` | Yes | Yes | -- |
| Set Reminder | `/remind <message> [in N min]` | Yes | No | -- |
| Get Weather | `/weather <location>` | Yes | Yes | `OPENWEATHER_API_KEY` |

### Admin Skills

| Skill | Command | Description |
|-------|---------|-------------|
| Whitelist | `/whitelist [add/remove/role]` | Manage phone number access |
| Vault | `/vault [list/set/get/delete]` | Manage encrypted secrets |
| Reminders | `/reminders` | View pending reminders |

### System Skills

| Skill | Command | Description |
|-------|---------|-------------|
| Help | `/help` | Show available commands |
| Status | `/status` | Check service health |
| Clear | `/clear` | Clear conversation history |

## Tech Stack

- **Python 3.11+** with FastAPI + Uvicorn
- **Claude** via Anthropic SDK (with tool-use)
- **Meta WhatsApp Cloud API** (official)
- **Docker** for skill sandboxing
- **Fernet** for encrypted vault (cryptography library)
- **6 production dependencies** — minimal attack surface

## Project Structure

```
secureclaw/
├── main.py                    # FastAPI app entry point
├── core/
│   └── agent.py               # Claude agent with tool-use, history, security pipeline
├── security/
│   ├── auth.py                # Phone whitelist + RBAC + rate limiting + PIN
│   ├── injection.py           # 25+ injection patterns + response filtering
│   ├── sandbox.py             # Docker isolation + resource limits
│   └── vault.py               # Fernet-encrypted secrets storage
├── api/
│   └── webhook.py             # Meta webhook handler + chunked reply + retry
├── skills/
│   ├── registry.py            # Skill definitions + all handler implementations
│   └── docker/                # Dockerfiles for sandboxed execution
├── tests/
│   └── run_all.py             # 175-test security suite
├── config/                    # Runtime data (gitignored)
├── Dockerfile                 # Production container
├── docker-compose.yml         # Full stack orchestration
├── pyproject.toml             # PEP 518 project metadata
└── .github/workflows/ci.yml  # Automated CI testing
```

## Testing

```bash
# Run all 175 tests
python tests/run_all.py

# Run specific component
python tests/run_all.py --component injection     # 25 tests
python tests/run_all.py --component auth           # 18 tests
python tests/run_all.py --component sandbox        # 10 tests
python tests/run_all.py --component vault          # 8 tests
python tests/run_all.py --component webhook        # 7 tests
python tests/run_all.py --component skills         # 7 tests
python tests/run_all.py --component skill_handlers # 20 tests
python tests/run_all.py --component admin          # 12 tests
python tests/run_all.py --component integration    # 3 tests
python tests/run_all.py --component e2e            # 10 tests
python tests/run_all.py --component agent_features # 14 tests
python tests/run_all.py --component app            # 25 tests
python tests/run_all.py --component production     # 16 tests
```

## Configuration

All configuration is via environment variables. See `.env.template` for the full list.

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | Yes | Claude API key |
| `WHATSAPP_TOKEN` | Recommended | Meta Cloud API bearer token |
| `WHATSAPP_PHONE_ID` | Recommended | WhatsApp Phone Number ID |
| `WHATSAPP_APP_SECRET` | Recommended | For webhook signature verification |
| `WEBHOOK_VERIFY_TOKEN` | Recommended | Random string for Meta webhook setup |
| `ADMIN_PHONE` | Recommended | Admin phone in E.164 format |
| `CLAUDE_MODEL` | No | Override AI model (default: claude-sonnet-4-5-20250929) |
| `RATE_LIMIT_MAX` | No | Max messages per window (default: 30) |
| `RATE_LIMIT_WINDOW` | No | Window in seconds (default: 3600) |

## License

MIT
