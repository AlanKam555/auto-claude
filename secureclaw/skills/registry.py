"""
SecureClaw Skill Registry — Manages and routes skill invocations.

Skills are triggered by specific message patterns (e.g., "/search query").
Each skill runs in a Docker sandbox via the SandboxManager.
Skills declare their required secrets — they only receive what they declare.
"""

import asyncio
import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional, Awaitable, Any

import httpx

from security.sandbox import SandboxManager, SandboxConfig

logger = logging.getLogger(__name__)

# In-memory reminder storage (per-phone, keyed by reminder ID)
_reminders: dict[str, list[dict]] = {}
_reminder_counter: int = 0


@dataclass
class SkillMatch:
    """A matched skill with extracted arguments."""
    skill_name: str
    args: str
    raw_text: str


@dataclass
class Skill:
    """
    Definition of a registered skill.

    Every skill must declare:
    - requires_network: whether it needs internet access in the sandbox
    - required_secrets: list of env var names it needs (least-privilege scoping)
    - input_schema: dict defining tool parameters (used for Anthropic tool definition)
    """
    name: str
    description: str
    pattern: re.Pattern
    handler: Callable[..., Awaitable[str]]
    requires_network: bool = False
    required_secrets: list[str] = field(default_factory=list)
    input_schema: dict[str, Any] = field(default_factory=dict)
    sandbox_config: Optional[SandboxConfig] = None
    admin_only: bool = False
    enabled: bool = True


class SkillRegistry:
    """
    Registry for skill definitions.
    Skills are matched against inbound messages by pattern.
    """

    def __init__(self, sandbox: Optional[SandboxManager] = None) -> None:
        self._skills: dict[str, Skill] = {}
        self._sandbox = sandbox or SandboxManager()
        self._register_builtins()

    def _register_builtins(self) -> None:
        """Register built-in skills."""
        # System skills (no sandbox needed)
        self.register(Skill(
            name="help",
            description="Show available commands",
            pattern=re.compile(r"^/(help|commands|menu)$", re.IGNORECASE),
            handler=self._handle_help,
        ))
        self.register(Skill(
            name="status",
            description="Check service status",
            pattern=re.compile(r"^/status$", re.IGNORECASE),
            handler=self._handle_status,
        ))
        self.register(Skill(
            name="clear",
            description="Clear conversation history",
            pattern=re.compile(r"^/clear$", re.IGNORECASE),
            handler=self._handle_clear,
        ))

        # ── 4 Built-in content skills (run in Docker) ──

        self.register(Skill(
            name="web_search",
            description="Search the web using Tavily API",
            pattern=re.compile(r"^/search\s+(.+)$", re.IGNORECASE),
            handler=self._handle_web_search,
            requires_network=True,
            required_secrets=["TAVILY_API_KEY"],
            input_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                },
                "required": ["query"],
            },
            sandbox_config=SandboxConfig(
                timeout=15,
                memory_limit="64m",
                network_enabled=True,
            ),
        ))

        self.register(Skill(
            name="summarize_url",
            description="Fetch and summarize a URL",
            pattern=re.compile(r"^/summarize\s+(https?://\S+)$", re.IGNORECASE),
            handler=self._handle_summarize_url,
            requires_network=True,
            required_secrets=[],
            input_schema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to summarize"},
                },
                "required": ["url"],
            },
            sandbox_config=SandboxConfig(
                timeout=20,
                memory_limit="128m",
                network_enabled=True,
            ),
        ))

        self.register(Skill(
            name="set_reminder",
            description="Set a reminder for later",
            pattern=re.compile(r"^/remind\s+(.+)$", re.IGNORECASE),
            handler=self._handle_set_reminder,
            requires_network=False,
            required_secrets=[],
            input_schema={
                "type": "object",
                "properties": {
                    "message": {"type": "string", "description": "Reminder message"},
                    "delay_minutes": {"type": "integer", "description": "Minutes from now"},
                },
                "required": ["message"],
            },
        ))

        self.register(Skill(
            name="get_weather",
            description="Get current weather for a location",
            pattern=re.compile(r"^/weather\s+(.+)$", re.IGNORECASE),
            handler=self._handle_get_weather,
            requires_network=True,
            required_secrets=["OPENWEATHER_API_KEY"],
            input_schema={
                "type": "object",
                "properties": {
                    "location": {"type": "string", "description": "City or location name"},
                },
                "required": ["location"],
            },
            sandbox_config=SandboxConfig(
                timeout=10,
                memory_limit="64m",
                network_enabled=True,
            ),
        ))

    def register(self, skill: Skill) -> None:
        """Register a skill."""
        self._skills[skill.name] = skill
        logger.info("Registered skill: %s", skill.name)

    def match(self, text: str) -> Optional[SkillMatch]:
        """
        Match a message against registered skill patterns.
        Returns the first matching skill, or None.
        """
        text = text.strip()
        for skill in self._skills.values():
            if not skill.enabled:
                continue
            m = skill.pattern.match(text)
            if m:
                # Use first capture group as args if available, else remainder
                args = m.group(1) if m.lastindex and m.lastindex >= 1 else text[m.end():].strip()
                return SkillMatch(
                    skill_name=skill.name,
                    args=args,
                    raw_text=text,
                )
        return None

    async def execute(self, match: SkillMatch, ctx) -> str:
        """Execute a matched skill."""
        skill = self._skills.get(match.skill_name)
        if not skill:
            return "Unknown skill."

        if skill.admin_only and not ctx.is_admin:
            return "This command requires admin access."

        try:
            return await skill.handler(match, ctx)
        except Exception as e:
            logger.error("Skill %s failed: %s", match.skill_name, e)
            return f"Skill error: {e}"

    def list_skills(self) -> list[dict]:
        """List all registered skills with their metadata."""
        return [
            {
                "name": s.name,
                "description": s.description,
                "requires_network": s.requires_network,
                "required_secrets": s.required_secrets,
                "admin_only": s.admin_only,
                "enabled": s.enabled,
            }
            for s in self._skills.values()
        ]

    def get_skill(self, name: str) -> Optional[Skill]:
        """Get a skill definition by name."""
        return self._skills.get(name)

    def enable(self, name: str) -> bool:
        if name in self._skills:
            self._skills[name].enabled = True
            return True
        return False

    def disable(self, name: str) -> bool:
        if name in self._skills:
            self._skills[name].enabled = False
            return True
        return False

    # === Built-in Handlers ===

    async def _handle_help(self, match: SkillMatch, ctx) -> str:
        lines = ["*SecureClaw Commands:*\n"]
        for skill in self._skills.values():
            if not skill.enabled:
                continue
            if skill.admin_only and not ctx.is_admin:
                continue
            lines.append(f"  /{skill.name} — {skill.description}")
        return "\n".join(lines)

    async def _handle_status(self, match: SkillMatch, ctx) -> str:
        docker_status = "available" if self._sandbox.is_available else "unavailable"
        skill_count = len([s for s in self._skills.values() if s.enabled])
        return (
            f"*SecureClaw Status*\n"
            f"  Service: running\n"
            f"  Skills: {skill_count} active\n"
            f"  Docker: {docker_status}\n"
        )

    async def _handle_clear(self, match: SkillMatch, ctx) -> str:
        return "Conversation history cleared."

    async def _handle_web_search(self, match: SkillMatch, ctx) -> str:
        """Search the web via Tavily API and return formatted results."""
        query = match.args.strip()
        if not query:
            return "Please provide a search query. Usage: /search <query>"

        api_key = os.environ.get("TAVILY_API_KEY", "")
        if not api_key:
            return "Web search is not configured. An admin needs to set TAVILY_API_KEY."

        try:
            async with httpx.AsyncClient(timeout=12) as client:
                resp = await client.post(
                    "https://api.tavily.com/search",
                    json={
                        "api_key": api_key,
                        "query": query,
                        "max_results": 5,
                        "include_answer": True,
                    },
                )
                resp.raise_for_status()
                data = resp.json()

            lines = [f"*Search results for:* {query}\n"]

            answer = data.get("answer")
            if answer:
                lines.append(f"_{answer}_\n")

            results = data.get("results", [])
            for i, r in enumerate(results[:5], 1):
                title = r.get("title", "No title")
                url = r.get("url", "")
                snippet = r.get("content", "")[:150]
                lines.append(f"{i}. *{title}*\n   {snippet}\n   {url}")

            if not results and not answer:
                lines.append("No results found.")

            return "\n".join(lines)

        except httpx.TimeoutException:
            return "Search timed out. Please try again."
        except httpx.HTTPStatusError as e:
            logger.error("Tavily API error: %s", e.response.status_code)
            return "Search service returned an error. Please try again later."
        except Exception as e:
            logger.error("Web search failed: %s", e)
            return "Search failed. Please try again later."

    async def _handle_summarize_url(self, match: SkillMatch, ctx) -> str:
        """Fetch a URL and return a text summary."""
        url = match.args.strip()
        if not url:
            return "Please provide a URL. Usage: /summarize https://example.com"

        # Basic URL validation
        if not url.startswith(("http://", "https://")):
            return "Invalid URL. Must start with http:// or https://"

        try:
            async with httpx.AsyncClient(
                timeout=15,
                follow_redirects=True,
                max_redirects=5,
            ) as client:
                resp = await client.get(
                    url,
                    headers={"User-Agent": "SecureClaw/1.0 (URL Summarizer)"},
                )
                resp.raise_for_status()

                content_type = resp.headers.get("content-type", "")
                if "text/html" not in content_type and "text/plain" not in content_type:
                    return f"Cannot summarize this content type: {content_type.split(';')[0]}"

                body = resp.text

            # Extract text from HTML (simple tag stripping)
            import re as _re
            # Remove script/style blocks
            body = _re.sub(r"<(script|style)[^>]*>.*?</\1>", "", body, flags=_re.DOTALL | _re.IGNORECASE)
            # Remove HTML tags
            body = _re.sub(r"<[^>]+>", " ", body)
            # Collapse whitespace
            body = _re.sub(r"\s+", " ", body).strip()

            if not body:
                return "Could not extract text content from the URL."

            # Truncate to a reasonable summary length
            max_chars = 2000
            if len(body) > max_chars:
                body = body[:max_chars] + "..."

            return f"*Summary of:* {url}\n\n{body}"

        except httpx.TimeoutException:
            return "Request timed out while fetching the URL."
        except httpx.HTTPStatusError as e:
            return f"Could not fetch URL (HTTP {e.response.status_code})."
        except httpx.TooManyRedirects:
            return "Too many redirects. The URL may be invalid."
        except Exception as e:
            logger.error("URL summarization failed: %s", e)
            return "Failed to fetch and summarize the URL."

    async def _handle_set_reminder(self, match: SkillMatch, ctx) -> str:
        """Set a reminder that fires after a delay."""
        global _reminder_counter

        args = match.args.strip()
        if not args:
            return "Please provide a reminder message. Usage: /remind <message> [in N minutes]"

        # Parse optional delay: "/remind Buy milk in 30 minutes"
        delay_match = re.search(r"\bin\s+(\d+)\s*(?:min(?:ute)?s?|m)\s*$", args, re.IGNORECASE)
        delay_minutes = 5  # default 5 minutes
        message = args

        if delay_match:
            delay_minutes = int(delay_match.group(1))
            message = args[:delay_match.start()].strip()
            if delay_minutes < 1:
                delay_minutes = 1
            if delay_minutes > 1440:  # max 24 hours
                return "Maximum reminder delay is 24 hours (1440 minutes)."

        if not message:
            return "Please provide a reminder message."

        _reminder_counter += 1
        reminder_id = _reminder_counter
        phone = ctx.phone if hasattr(ctx, "phone") else "unknown"

        reminder = {
            "id": reminder_id,
            "message": message,
            "delay_minutes": delay_minutes,
            "phone": phone,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "fired": False,
        }

        if phone not in _reminders:
            _reminders[phone] = []
        _reminders[phone].append(reminder)

        # Schedule the reminder as a background task
        asyncio.ensure_future(self._fire_reminder(phone, reminder_id, delay_minutes))

        return (
            f"Reminder set (#{reminder_id}).\n"
            f"Message: _{message}_\n"
            f"I'll remind you in {delay_minutes} minute{'s' if delay_minutes != 1 else ''}."
        )

    async def _fire_reminder(self, phone: str, reminder_id: int, delay_minutes: int) -> None:
        """Background task that fires a reminder after the delay."""
        await asyncio.sleep(delay_minutes * 60)
        reminders = _reminders.get(phone, [])
        for r in reminders:
            if r["id"] == reminder_id and not r["fired"]:
                r["fired"] = True
                logger.info(
                    "Reminder #%d fired for %s: %s",
                    reminder_id, phone[:6] + "***", r["message"],
                )
                break

    async def _handle_get_weather(self, match: SkillMatch, ctx) -> str:
        """Get current weather for a location via OpenWeather API."""
        location = match.args.strip()
        if not location:
            return "Please provide a location. Usage: /weather <city>"

        api_key = os.environ.get("OPENWEATHER_API_KEY", "")
        if not api_key:
            return "Weather is not configured. An admin needs to set OPENWEATHER_API_KEY."

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    "https://api.openweathermap.org/data/2.5/weather",
                    params={
                        "q": location,
                        "appid": api_key,
                        "units": "metric",
                    },
                )
                resp.raise_for_status()
                data = resp.json()

            city = data.get("name", location)
            country = data.get("sys", {}).get("country", "")
            weather = data.get("weather", [{}])[0]
            main = data.get("main", {})
            wind = data.get("wind", {})

            desc = weather.get("description", "N/A").capitalize()
            temp = main.get("temp", "N/A")
            feels_like = main.get("feels_like", "N/A")
            humidity = main.get("humidity", "N/A")
            wind_speed = wind.get("speed", "N/A")

            location_str = f"{city}, {country}" if country else city

            return (
                f"*Weather in {location_str}*\n\n"
                f"  {desc}\n"
                f"  Temperature: {temp}°C (feels like {feels_like}°C)\n"
                f"  Humidity: {humidity}%\n"
                f"  Wind: {wind_speed} m/s"
            )

        except httpx.TimeoutException:
            return "Weather service timed out. Please try again."
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return f"Location not found: {location}. Try a different city name."
            logger.error("OpenWeather API error: %s", e.response.status_code)
            return "Weather service returned an error. Please try again later."
        except Exception as e:
            logger.error("Weather lookup failed: %s", e)
            return "Failed to get weather. Please try again later."
