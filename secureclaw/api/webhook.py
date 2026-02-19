"""
SecureClaw WhatsApp Webhook Handler.

Handles Meta/WhatsApp Cloud API webhook verification and inbound messages.
Includes signature validation, timestamp replay protection, and rate limiting.
"""

import hashlib
import hmac
import logging
import os
import time
from typing import Optional

from fastapi import APIRouter, Request, Response, HTTPException, Query

from core.agent import SecureClawAgent, MessageContext

logger = logging.getLogger(__name__)

router = APIRouter()

# Module-level agent instance (initialized on first request)
_agent: Optional[SecureClawAgent] = None

# Replay protection: reject requests older than this
MAX_TIMESTAMP_AGE_SECONDS = 300  # 5 minutes


def get_agent() -> SecureClawAgent:
    """Get or create the singleton agent instance."""
    global _agent
    if _agent is None:
        _agent = SecureClawAgent()
    return _agent


def verify_webhook_signature(payload: bytes, signature: str) -> bool:
    """
    Verify the X-Hub-Signature-256 header from Meta.
    Returns True if the signature is valid.
    """
    app_secret = os.environ.get("WHATSAPP_APP_SECRET", "")
    if not app_secret:
        logger.warning("WHATSAPP_APP_SECRET not set — skipping signature verification")
        return True

    if not signature or not signature.startswith("sha256="):
        return False

    expected = hmac.new(
        app_secret.encode("utf-8"),
        payload,
        hashlib.sha256,
    ).hexdigest()

    received = signature.removeprefix("sha256=")
    return hmac.compare_digest(expected, received)


def validate_timestamp(timestamp_header: Optional[str]) -> bool:
    """
    Validate the X-Hub-Timestamp header to prevent replay attacks.
    Returns True if the timestamp is within the acceptable window.
    """
    if not timestamp_header:
        # If no timestamp header, allow but log warning
        logger.warning("No X-Hub-Timestamp header — replay protection reduced")
        return True

    try:
        request_time = int(timestamp_header)
    except ValueError:
        logger.warning("Invalid X-Hub-Timestamp value: %s", timestamp_header)
        return False

    now = int(time.time())
    age = abs(now - request_time)

    if age > MAX_TIMESTAMP_AGE_SECONDS:
        logger.warning(
            "Rejected stale webhook: age=%ds, max=%ds",
            age,
            MAX_TIMESTAMP_AGE_SECONDS,
        )
        return False

    return True


@router.get("/webhook")
async def verify_webhook(
    hub_mode: str = Query(None, alias="hub.mode"),
    hub_verify_token: str = Query(None, alias="hub.verify_token"),
    hub_challenge: str = Query(None, alias="hub.challenge"),
) -> Response:
    """
    Meta webhook verification endpoint.
    Meta sends a GET request with a challenge to verify the webhook URL.
    """
    verify_token = os.environ.get("WEBHOOK_VERIFY_TOKEN", "")

    if hub_mode == "subscribe" and hub_verify_token == verify_token:
        logger.info("Webhook verified successfully")
        return Response(content=hub_challenge, media_type="text/plain")

    logger.warning("Webhook verification failed (mode=%s)", hub_mode)
    raise HTTPException(status_code=403, detail="Verification failed")


@router.post("/webhook")
async def handle_webhook(request: Request) -> dict:
    """
    Handle inbound WhatsApp messages from Meta Cloud API.

    Validates signature, checks timestamp, extracts message,
    processes through the security pipeline, and sends response.
    """
    body = await request.body()

    # Signature verification
    signature = request.headers.get("X-Hub-Signature-256", "")
    if not verify_webhook_signature(body, signature):
        logger.warning("Invalid webhook signature")
        raise HTTPException(status_code=401, detail="Invalid signature")

    # Timestamp validation (replay protection)
    timestamp_header = request.headers.get("X-Hub-Timestamp")
    if not validate_timestamp(timestamp_header):
        raise HTTPException(status_code=401, detail="Request too old")

    # Parse the webhook payload
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    # Extract message from Meta's webhook format
    message_info = _extract_message(data)
    if not message_info:
        # Not a message event (could be status update, etc.)
        return {"status": "ok"}

    phone, text, message_id = message_info

    # Process through the agent
    agent = get_agent()
    ctx = MessageContext(
        phone=phone,
        text=text,
        message_id=message_id,
    )

    response = await agent.process_message(ctx)

    # Send response via WhatsApp
    if not response.blocked:
        await _send_whatsapp_message(phone, response.text)

    logger.info(
        "Processed message from %s***: blocked=%s, skill=%s, time=%.0fms",
        phone[:6],
        response.blocked,
        response.skill_used,
        response.processing_time_ms,
    )

    return {"status": "ok"}


def _extract_message(data: dict) -> Optional[tuple[str, str, str]]:
    """
    Extract phone, text, and message_id from Meta webhook payload.
    Returns None if this isn't a text message event.
    """
    try:
        entry = data.get("entry", [{}])[0]
        changes = entry.get("changes", [{}])[0]
        value = changes.get("value", {})
        messages = value.get("messages", [])

        if not messages:
            return None

        message = messages[0]
        if message.get("type") != "text":
            return None

        phone = message.get("from", "")
        text = message.get("text", {}).get("body", "")
        message_id = message.get("id", "")

        if not phone or not text:
            return None

        return phone, text, message_id
    except (IndexError, KeyError, TypeError):
        return None


async def _send_whatsapp_message(phone: str, text: str) -> bool:
    """
    Send a text message via WhatsApp Cloud API.
    Returns True on success.
    """
    token = os.environ.get("WHATSAPP_TOKEN")
    phone_id = os.environ.get("WHATSAPP_PHONE_ID")

    if not token or not phone_id:
        logger.error("WhatsApp credentials not configured")
        return False

    import httpx

    url = f"https://graph.facebook.com/v21.0/{phone_id}/messages"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    payload = {
        "messaging_product": "whatsapp",
        "to": phone,
        "type": "text",
        "text": {"body": text[:4096]},  # WhatsApp limit
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(url, headers=headers, json=payload)
            if resp.status_code == 200:
                return True
            logger.error("WhatsApp API error: %s %s", resp.status_code, resp.text)
            return False
    except Exception as e:
        logger.error("Failed to send WhatsApp message: %s", e)
        return False
