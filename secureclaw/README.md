# SecureClaw

Secure AI assistant for WhatsApp, built on the official Meta WhatsApp Cloud API and powered by Claude.

## What is SecureClaw?

SecureClaw is a security-first alternative to OpenClaw for building AI-powered WhatsApp assistants. Every message passes through a multi-layer security pipeline before reaching the AI, and all skills execute inside Docker sandboxes.

### Security Features

- **25+ prompt injection patterns** detected and blocked
- **Docker-sandboxed skills** with no host filesystem access
- **Least-privilege secrets** — skills only receive declared credentials
- **External content filtering** — emails, docs, and web pages wrapped as untrusted
- **Encrypted vault** — Fernet-encrypted secret storage
- **RBAC** — role-based access with phone number whitelisting
- **Rate limiting** — per-number message throttling
- **Webhook signature verification** — HMAC-SHA256 + timestamp replay protection
- **78-test security suite** — must pass before every deployment

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Set up environment
cp .env.template .env
# Edit .env with your API keys

# Create config directory
mkdir -p config

# Run security tests
ADMIN_PHONE="+6512345678" python tests/run_all.py

# Start the server
python main.py

# Expose via ngrok (separate terminal)
ngrok http 8000
```

## Architecture

```
User (WhatsApp) → Meta Cloud API → Webhook → Auth → Rate Limit
    → Injection Filter → Skill Router → Docker Sandbox → Claude API
    → Response Filter → WhatsApp Reply
```

## Built-in Skills

| Skill | Command | Network | Secrets |
|-------|---------|---------|---------|
| Web Search | `/search <query>` | Yes | `TAVILY_API_KEY` |
| Summarize URL | `/summarize <url>` | Yes | — |
| Set Reminder | `/remind <message>` | No | — |
| Get Weather | `/weather <location>` | Yes | `OPENWEATHER_API_KEY` |

## Tech Stack

- **Python 3.11+** with FastAPI + Uvicorn
- **Claude** via Anthropic SDK
- **Meta WhatsApp Cloud API** (official)
- **Docker** for skill sandboxing
- **Fernet** for encrypted vault

## Testing

```bash
# Run all 78 tests
python tests/run_all.py

# Run specific component
python tests/run_all.py --component injection
python tests/run_all.py --component auth
python tests/run_all.py --component sandbox
python tests/run_all.py --component vault
python tests/run_all.py --component webhook
python tests/run_all.py --component skills
```

## License

MIT
