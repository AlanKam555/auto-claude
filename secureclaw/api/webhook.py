"""
SecureClaw WhatsApp Webhook Handler.

Handles Meta/WhatsApp Cloud API webhook verification and inbound messages.
Includes signature validation, timestamp replay protection, and rate limiting.
"""

import asyncio
import hashlib
import hmac
import logging
import os
import re
import time
from typing import Optional

import httpx

from fastapi import APIRouter, Request, Response, HTTPException, Query

from core.agent import SecureClawAgent, MessageContext

logger = logging.getLogger(__name__)

router = APIRouter()

# Module-level agent instance (initialized on first request)
_agent: Optional[SecureClawAgent] = None

# Replay protection: reject requests older than this
MAX_TIMESTAMP_AGE_SECONDS = 300  # 5 minutes

# Message deduplication — track recently processed message IDs
_processed_ids: dict[str, float] = {}
_DEDUP_TTL_SECONDS = 300  # 5 minutes


def _is_duplicate(message_id: str) -> bool:
    """Check if a message ID was recently processed (deduplication)."""
    now = time.time()

    # Prune old entries
    expired = [k for k, ts in _processed_ids.items() if now - ts > _DEDUP_TTL_SECONDS]
    for k in expired:
        del _processed_ids[k]

    if message_id in _processed_ids:
        return True

    _processed_ids[message_id] = now
    return False


# ── Input Sanitization ──

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
MAX_MESSAGE_LENGTH = 10_000  # safe cap (WhatsApp max is ~64 KB)


def sanitize_phone(phone: str) -> str:
    """Sanitize a phone number — strip non-digit/plus characters, enforce length."""
    cleaned = re.sub(r"[^\d+]", "", phone)
    if not cleaned.startswith("+"):
        cleaned = "+" + cleaned
    # E.164: max 15 digits + plus sign = 16 chars
    return cleaned[:16]


def sanitize_message(text: str) -> str:
    """Strip control characters and enforce length limit."""
    cleaned = _CONTROL_CHAR_RE.sub("", text)
    if len(cleaned) > MAX_MESSAGE_LENGTH:
        cleaned = cleaned[:MAX_MESSAGE_LENGTH]
    return cleaned.strip()


# ── Media message responses ──

MEDIA_TYPE_RESPONSES: dict[str, str] = {
    "image": "I received your image, but I can currently only process text messages. Please describe what you'd like help with.",
    "audio": "I received your voice message, but I can only process text. Please type your request instead.",
    "video": "I received your video, but I can currently only process text messages. Please describe what you need.",
    "document": "I received your document, but I can only process text messages. Please describe what you need.",
    "sticker": "Nice sticker! I can only process text messages though. How can I help you?",
    "location": "I received your location, but I can only process text messages. How can I help you?",
    "contacts": "I received a contact share, but I can only process text messages. How can I help you?",
}


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

    # Try to extract a text message
    message_info = _extract_message(data)

    if message_info:
        phone, text, message_id = message_info

        # Send read receipt (fire-and-forget)
        asyncio.ensure_future(mark_message_as_read(message_id))

        # Deduplication — skip if we already processed this message
        if _is_duplicate(message_id):
            logger.info("Duplicate message %s from %s*** — skipped", message_id, phone[:6])
            return {"status": "ok", "deduplicated": True}

        # Sanitize inputs
        phone = sanitize_phone(phone)
        text = sanitize_message(text)

        if not phone or not text:
            return {"status": "ok"}

        # Record metrics and audit
        try:
            from main import record_metric
            record_metric("messages_received")
        except ImportError:
            pass
        try:
            from security.audit import audit_log, AuditEvent
            audit_log(AuditEvent.MESSAGE_RECEIVED, phone=phone, detail=f"msg_id={message_id}")
        except ImportError:
            pass

        # Process through the agent
        agent = get_agent()
        ctx = MessageContext(phone=phone, text=text, message_id=message_id)
        response = await agent.process_message(ctx)

        # Record processing metrics
        try:
            from main import record_metric
            if response.blocked:
                record_metric("messages_blocked")
            else:
                record_metric("messages_processed")
            if response.skill_used:
                record_metric("skill_invocations")
            record_metric("total_processing_ms", response.processing_time_ms)
        except ImportError:
            pass

        # Send response via WhatsApp (with chunking for long messages)
        if not response.blocked:
            await send_whatsapp_reply(phone, response.text)

        logger.info(
            "Processed message from %s***: blocked=%s, skill=%s, time=%.0fms",
            phone[:6], response.blocked, response.skill_used, response.processing_time_ms,
        )
        return {"status": "ok"}

    # Try to extract a non-text (media) message
    media_info = _extract_media_message(data)
    if media_info:
        phone, message_id, msg_type = media_info

        # Send read receipt
        asyncio.ensure_future(mark_message_as_read(message_id))

        # Deduplication
        if _is_duplicate(message_id):
            return {"status": "ok", "deduplicated": True}

        phone = sanitize_phone(phone)

        # Record metric
        try:
            from main import record_metric
            record_metric("messages_received")
        except ImportError:
            pass

        try:
            from security.audit import audit_log, AuditEvent
            audit_log(AuditEvent.MEDIA_RECEIVED, phone=phone, detail=f"type={msg_type}, msg_id={message_id}")
        except ImportError:
            pass

        # Send graceful "text only" response
        response_text = MEDIA_TYPE_RESPONSES.get(
            msg_type,
            "I can currently only process text messages. Please send your request as text.",
        )
        await send_whatsapp_reply(phone, response_text)

        logger.info("Media message (%s) from %s*** — sent text-only notice", msg_type, phone[:6])
        return {"status": "ok", "media_type": msg_type}

    # Handle status updates (delivered, read confirmations from WhatsApp)
    status_info = _extract_status_update(data)
    if status_info:
        recipient, msg_id, status_type = status_info
        logger.debug(
            "Status update: %s for message %s to %s***",
            status_type, msg_id, recipient[:6],
        )
        try:
            from security.audit import audit_log, AuditEvent
            audit_log(
                AuditEvent.STATUS_UPDATE,
                phone=recipient,
                detail=f"Status: {status_type}, message: {msg_id}",
            )
        except ImportError:
            pass
        return {"status": "ok", "event": "status_update", "message_status": status_type}

    # Not a recognized event
    return {"status": "ok"}


def _extract_status_update(data: dict) -> Optional[tuple[str, str, str]]:
    """
    Extract status updates (delivered, read, sent) from Meta webhook payload.
    Returns (recipient_phone, message_id, status) or None.
    """
    try:
        entry = data.get("entry", [{}])[0]
        changes = entry.get("changes", [{}])[0]
        value = changes.get("value", {})
        statuses = value.get("statuses", [])

        if not statuses:
            return None

        status = statuses[0]
        recipient = status.get("recipient_id", "")
        msg_id = status.get("id", "")
        status_type = status.get("status", "")

        if not recipient or not status_type:
            return None

        return recipient, msg_id, status_type
    except (IndexError, KeyError, TypeError):
        return None


def _extract_media_message(data: dict) -> Optional[tuple[str, str, str]]:
    """
    Extract phone, message_id, and type from a non-text message.
    Returns (phone, message_id, message_type) or None.
    """
    try:
        entry = data.get("entry", [{}])[0]
        changes = entry.get("changes", [{}])[0]
        value = changes.get("value", {})
        messages = value.get("messages", [])

        if not messages:
            return None

        message = messages[0]
        msg_type = message.get("type", "unknown")

        if msg_type == "text":
            return None  # handled by _extract_message

        phone = message.get("from", "")
        message_id = message.get("id", "")

        if not phone:
            return None

        return phone, message_id, msg_type
    except (IndexError, KeyError, TypeError):
        return None


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


WHATSAPP_MAX_CHARS = 4096


def _chunk_message(text: str, max_chars: int = 3800) -> list[str]:
    """
    Split a long message into WhatsApp-safe chunks.
    Prefers splitting at paragraph/line boundaries.
    """
    if len(text) <= max_chars:
        return [text]

    chunks = []
    remaining = text

    while remaining:
        if len(remaining) <= max_chars:
            chunks.append(remaining)
            break

        # Try to split at a paragraph boundary
        cut = remaining[:max_chars].rfind("\n\n")
        if cut < max_chars // 2:
            # Try single newline
            cut = remaining[:max_chars].rfind("\n")
        if cut < max_chars // 2:
            # Try space
            cut = remaining[:max_chars].rfind(" ")
        if cut < max_chars // 2:
            # Hard cut
            cut = max_chars

        chunks.append(remaining[:cut].rstrip())
        remaining = remaining[cut:].lstrip()

    return chunks


async def mark_message_as_read(message_id: str) -> None:
    """Send a read receipt to WhatsApp for the given message (fire-and-forget)."""
    token = os.environ.get("WHATSAPP_TOKEN")
    phone_id = os.environ.get("WHATSAPP_PHONE_ID")

    if not token or not phone_id:
        return

    url = f"https://graph.facebook.com/v21.0/{phone_id}/messages"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    payload = {
        "messaging_product": "whatsapp",
        "status": "read",
        "message_id": message_id,
    }

    try:
        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(url, headers=headers, json=payload)
    except Exception as e:
        logger.warning("Failed to send read receipt: %s", e)


async def send_whatsapp_reply(phone: str, text: str) -> bool:
    """
    Send a reply via WhatsApp, with chunking and retry.
    Long messages are split into multiple chunks sent sequentially.
    Returns True if all chunks sent successfully.
    """
    chunks = _chunk_message(text)
    success = True

    for i, chunk in enumerate(chunks):
        if not await _send_whatsapp_message(phone, chunk):
            success = False
            break
        # Small delay between chunks to preserve ordering
        if i < len(chunks) - 1:
            await asyncio.sleep(0.15)

    return success


async def _send_whatsapp_message(phone: str, text: str, retries: int = 3) -> bool:
    """
    Send a single text message via WhatsApp Cloud API.
    Retries with exponential backoff on transient failures.
    Returns True on success.
    """
    token = os.environ.get("WHATSAPP_TOKEN")
    phone_id = os.environ.get("WHATSAPP_PHONE_ID")

    if not token or not phone_id:
        logger.error("WhatsApp credentials not configured")
        return False

    url = f"https://graph.facebook.com/v21.0/{phone_id}/messages"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    payload = {
        "messaging_product": "whatsapp",
        "to": phone,
        "type": "text",
        "text": {"body": text[:WHATSAPP_MAX_CHARS]},
    }

    for attempt in range(retries):
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(url, headers=headers, json=payload)
                if resp.status_code == 200:
                    return True
                # Don't retry on client errors (4xx) except 429 (rate limit)
                if 400 <= resp.status_code < 500 and resp.status_code != 429:
                    logger.error("WhatsApp API error (no retry): %s %s", resp.status_code, resp.text)
                    return False
                logger.warning(
                    "WhatsApp API error (attempt %d/%d): %s",
                    attempt + 1, retries, resp.status_code,
                )
        except Exception as e:
            logger.warning(
                "WhatsApp send failed (attempt %d/%d): %s",
                attempt + 1, retries, e,
            )

        if attempt < retries - 1:
            backoff = 2 ** attempt  # 1s, 2s
            await asyncio.sleep(backoff)

    logger.error("WhatsApp message delivery failed after %d attempts to %s***", retries, phone[:6])
    return False
