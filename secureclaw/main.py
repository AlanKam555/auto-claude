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

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from api.webhook import router as webhook_router

__version__ = "1.0.0"

# Load environment variables from .env file
load_dotenv()

# Configure logging
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

    # Include webhook routes
    app.include_router(webhook_router)

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

    return app


app = create_app()


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
