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
from pathlib import Path

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI

from api.webhook import router as webhook_router

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


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="SecureClaw",
        description="Secure AI Assistant for WhatsApp — powered by Claude Opus 4.6",
        version="1.0.0",
        docs_url=None,    # Disable Swagger UI in production
        redoc_url=None,   # Disable ReDoc in production
    )

    # Include webhook routes
    app.include_router(webhook_router)

    @app.get("/health")
    async def health_check():
        """Health check endpoint for monitoring."""
        return {
            "status": "healthy",
            "service": "secureclaw",
            "version": "1.0.0",
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
