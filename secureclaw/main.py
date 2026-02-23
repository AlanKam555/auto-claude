"""
SecureClaw — Secure AI Assistant for WhatsApp.

FastAPI application entry point. Hosts the WhatsApp webhook endpoint
and serves the SecureClaw agent with full security pipeline.

Usage:
    python main.py                    # Start server on port 8000
    python main.py --port 9000        # Custom port
    python main.py --reload           # Dev mode with auto-reload
"""

import argparse
import logging
import os
import sys
import time
from pathlib import Path
from threading import Lock

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from api.admin import router as admin_router
from api.webhook import router as webhook_router

__version__ = "1.2.0"

# Load environment variables from .env file
load_dotenv()

# Configure structured logging
_log_format = os.environ.get("LOG_FORMAT", "text")
if _log_format == "json":
    logging.basicConfig(
        level=logging.INFO,
        format='{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","message":"%(message)s"}',
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
else:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
logger = logging.getLogger("secureclaw")

# Ensure config directory exists
(Path(__file__).parent / "config").mkdir(exist_ok=True)

# Track server start time for uptime reporting
_start_time = time.time()

# Maximum request body size (1 MB — WhatsApp payloads are small)
MAX_REQUEST_BODY_BYTES = 1_048_576

# ── Metrics counters (thread-safe) ──
_metrics_lock = Lock()
_metrics = {
    "messages_received": 0,
    "messages_blocked": 0,
    "messages_processed": 0,
    "skill_invocations": 0,
    "claude_calls": 0,
    "errors": 0,
    "total_processing_ms": 0.0,
}


def record_metric(key: str, value: float = 1) -> None:
    """Thread-safe metric increment."""
    with _metrics_lock:
        _metrics[key] = _metrics.get(key, 0) + value


def get_metrics() -> dict:
    """Return a snapshot of current metrics."""
    with _metrics_lock:
        snapshot = dict(_metrics)
    processed = snapshot["messages_processed"]
    snapshot["avg_processing_ms"] = (
        round(snapshot["total_processing_ms"] / processed, 1) if processed > 0 else 0
    )
    return snapshot


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="SecureClaw",
        description="Secure AI Assistant for WhatsApp — powered by Claude",
        version=__version__,
        docs_url=None,    # Disable Swagger UI in production
        redoc_url=None,   # Disable ReDoc in production
    )

    # CORS — restrict to Meta's webhook origins in production
    allowed_origins = os.environ.get("CORS_ORIGINS", "").split(",")
    allowed_origins = [o.strip() for o in allowed_origins if o.strip()]
    if allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=allowed_origins,
            allow_methods=["GET", "POST"],
            allow_headers=["*"],
        )

    # Request size limiter middleware
    @app.middleware("http")
    async def limit_request_size(request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > MAX_REQUEST_BODY_BYTES:
            return Response(
                content='{"detail": "Request body too large"}',
                status_code=413,
                media_type="application/json",
            )
        return await call_next(request)

    # Include routers
    app.include_router(webhook_router)
    app.include_router(admin_router)

    @app.get("/health")
    async def health_check():
        """Health check endpoint for monitoring and orchestration."""
        uptime_seconds = int(time.time() - _start_time)
        hours, remainder = divmod(uptime_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)

        return {
            "status": "healthy",
            "service": "secureclaw",
            "version": __version__,
            "uptime": f"{hours}h {minutes}m {seconds}s",
            "uptime_seconds": uptime_seconds,
        }

    @app.get("/metrics")
    async def metrics_endpoint():
        """Operational metrics for monitoring dashboards."""
        return {
            "service": "secureclaw",
            "version": __version__,
            "uptime_seconds": int(time.time() - _start_time),
            **get_metrics(),
        }

    return app


app = create_app()


async def graceful_shutdown() -> None:
    """Cleanup on shutdown: flush pending reminders and log."""
    logger.info("Shutting down SecureClaw...")
    try:
        from skills.registry import _save_reminders
        _save_reminders()
        logger.info("Reminders flushed to disk")
    except Exception as e:
        logger.error("Failed to flush reminders on shutdown: %s", e)
    logger.info("SecureClaw stopped.")


@app.on_event("shutdown")
async def shutdown_event():
    await graceful_shutdown()


def validate_env() -> list[str]:
    """Validate required environment variables. Returns list of warnings."""
    warnings = []
    required = ["ANTHROPIC_API_KEY"]
    recommended = [
        "WHATSAPP_TOKEN",
        "WHATSAPP_PHONE_ID",
        "WEBHOOK_VERIFY_TOKEN",
        "ADMIN_PHONE",
    ]

    for var in required:
        if not os.environ.get(var):
            logger.error("MISSING REQUIRED: %s", var)
            sys.exit(1)

    for var in recommended:
        if not os.environ.get(var):
            warnings.append(f"Missing recommended env var: {var}")

    return warnings


def main() -> None:
    """Main entry point — parse args and start the server."""
    parser = argparse.ArgumentParser(description="SecureClaw Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload (dev mode)")
    args = parser.parse_args()

    logger.info("SecureClaw starting...")

    warnings = validate_env()
    for w in warnings:
        logger.warning(w)

    logger.info("Server starting on %s:%d", args.host, args.port)

    uvicorn.run(
        "main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()
