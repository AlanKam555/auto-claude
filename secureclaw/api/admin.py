"""
SecureClaw Admin REST API — Protected endpoints for system management.

All endpoints require the X-Admin-Key header matching the ADMIN_API_KEY env var.
These are meant for external dashboards, monitoring tools, and admin scripts.
"""

import logging
import os
import time
from typing import Optional

from fastapi import APIRouter, HTTPException, Header

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"])


def _verify_admin_key(x_admin_key: Optional[str] = None) -> None:
    """Verify the admin API key from the X-Admin-Key header."""
    expected = os.environ.get("ADMIN_API_KEY", "")
    if not expected:
        raise HTTPException(
            status_code=503,
            detail="Admin API not configured (set ADMIN_API_KEY)",
        )
    if not x_admin_key or x_admin_key != expected:
        raise HTTPException(status_code=401, detail="Invalid or missing admin API key")


@router.get("/stats")
async def admin_stats(x_admin_key: Optional[str] = Header(None)):
    """System statistics, metrics, and uptime."""
    _verify_admin_key(x_admin_key)

    try:
        from main import get_metrics, __version__, _start_time
    except ImportError:
        raise HTTPException(status_code=500, detail="Metrics unavailable")

    uptime = int(time.time() - _start_time)
    return {
        "service": "secureclaw",
        "version": __version__,
        "uptime_seconds": uptime,
        "metrics": get_metrics(),
    }


@router.get("/users")
async def admin_users(x_admin_key: Optional[str] = Header(None)):
    """List all whitelisted users and their roles."""
    _verify_admin_key(x_admin_key)

    from api.webhook import get_agent

    agent = get_agent()
    users = agent.auth.list_numbers()
    return {"users": users, "count": len(users)}


@router.get("/skills")
async def admin_skills(x_admin_key: Optional[str] = Header(None)):
    """List all registered skills with metadata."""
    _verify_admin_key(x_admin_key)

    from api.webhook import get_agent

    agent = get_agent()
    skills = agent.skills.list_skills()
    return {"skills": skills, "count": len(skills)}
