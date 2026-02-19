"""
SecureClaw Skill Registry — Manages and routes skill invocations.

Skills are triggered by specific message patterns (e.g., "/search query").
Each skill runs in a Docker sandbox via the SandboxManager.
Skills declare their required secrets — they only receive what they declare.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Callable, Optional, Awaitable, Any

from security.sandbox import SandboxManager, SandboxConfig

logger = logging.getLogger(__name__)


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
        # TODO: Implement Tavily API integration in Docker sandbox
        return f"Web search skill not yet implemented. Query: {match.args}"

    async def _handle_summarize_url(self, match: SkillMatch, ctx) -> str:
        # TODO: Implement URL fetch and summarization in Docker sandbox
        return f"URL summarization skill not yet implemented. URL: {match.args}"

    async def _handle_set_reminder(self, match: SkillMatch, ctx) -> str:
        # TODO: Implement scheduler-based reminders
        return f"Reminder skill not yet implemented. Message: {match.args}"

    async def _handle_get_weather(self, match: SkillMatch, ctx) -> str:
        # TODO: Implement OpenWeather API integration in Docker sandbox
        return f"Weather skill not yet implemented. Location: {match.args}"
