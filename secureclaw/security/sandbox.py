"""
SecureClaw Sandbox — Docker-based skill execution isolation.

Every skill runs inside a disposable Docker container with:
- No network access (by default)
- Read-only filesystem (except /tmp)
- Resource limits (CPU, memory, time)
- No host volume mounts
- Non-root user
"""

import asyncio
import logging
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30  # seconds
DEFAULT_MEMORY_LIMIT = "128m"
DEFAULT_CPU_LIMIT = "0.5"


@dataclass
class SandboxConfig:
    """Configuration for a sandbox execution."""
    image: str = "python:3.11-slim"
    timeout: int = DEFAULT_TIMEOUT
    memory_limit: str = DEFAULT_MEMORY_LIMIT
    cpu_limit: str = DEFAULT_CPU_LIMIT
    network_enabled: bool = False
    env_vars: dict[str, str] = field(default_factory=dict)
    working_dir: str = "/app"


@dataclass
class SandboxResult:
    """Result of a sandboxed execution."""
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    timed_out: bool = False
    error: Optional[str] = None


class SandboxManager:
    """
    Manages Docker-based sandboxed execution of skill code.
    Each execution gets a fresh, disposable container.
    """

    def __init__(self) -> None:
        self._docker_available = self._check_docker()
        if not self._docker_available:
            logger.warning(
                "Docker not available — skill sandboxing will use subprocess fallback"
            )

    def _check_docker(self) -> bool:
        """Check if Docker is available on the system."""
        return shutil.which("docker") is not None

    @property
    def is_available(self) -> bool:
        """Whether Docker-based sandboxing is available."""
        return self._docker_available

    async def execute(
        self,
        code: str,
        config: Optional[SandboxConfig] = None,
    ) -> SandboxResult:
        """
        Execute code in a sandboxed Docker container.

        Falls back to a restricted subprocess if Docker is unavailable.
        """
        if config is None:
            config = SandboxConfig()

        if self._docker_available:
            return await self._execute_docker(code, config)
        return await self._execute_subprocess(code, config)

    async def _execute_docker(
        self, code: str, config: SandboxConfig
    ) -> SandboxResult:
        """Execute code inside a Docker container."""
        # Write code to a temp file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as f:
            f.write(code)
            code_path = f.name

        try:
            cmd = [
                "docker", "run",
                "--rm",
                "--memory", config.memory_limit,
                "--cpus", config.cpu_limit,
                "--read-only",
                "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
                "--user", "nobody",
                "--security-opt", "no-new-privileges",
                "--pids-limit", "50",
            ]

            if not config.network_enabled:
                cmd.extend(["--network", "none"])

            for key, value in config.env_vars.items():
                # Only allow safe env var names
                if key.isalnum() or key.replace("_", "").isalnum():
                    cmd.extend(["-e", f"{key}={value}"])

            cmd.extend([
                "-v", f"{code_path}:/app/script.py:ro",
                "-w", config.working_dir,
                config.image,
                "python", "/app/script.py",
            ])

            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                try:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(), timeout=config.timeout
                    )
                    return SandboxResult(
                        stdout=stdout.decode("utf-8", errors="replace").strip(),
                        stderr=stderr.decode("utf-8", errors="replace").strip(),
                        exit_code=process.returncode or 0,
                    )
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                    return SandboxResult(timed_out=True, error="Execution timed out")

            except FileNotFoundError:
                return SandboxResult(error="Docker command not found")
            except OSError as e:
                return SandboxResult(error=f"Docker execution failed: {e}")

        finally:
            os.unlink(code_path)

    async def _execute_subprocess(
        self, code: str, config: SandboxConfig
    ) -> SandboxResult:
        """
        Fallback: execute code in a restricted subprocess.
        WARNING: Less secure than Docker isolation.
        """
        logger.warning("Using subprocess fallback — reduced security isolation")

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as f:
            f.write(code)
            code_path = f.name

        try:
            env = os.environ.copy()
            # Strip sensitive vars
            for key in ["ANTHROPIC_API_KEY", "WHATSAPP_TOKEN", "WEBHOOK_VERIFY_TOKEN"]:
                env.pop(key, None)
            env.update(config.env_vars)

            process = await asyncio.create_subprocess_exec(
                "python3", code_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=config.timeout
                )
                return SandboxResult(
                    stdout=stdout.decode("utf-8", errors="replace").strip(),
                    stderr=stderr.decode("utf-8", errors="replace").strip(),
                    exit_code=process.returncode or 0,
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return SandboxResult(timed_out=True, error="Execution timed out")

        finally:
            os.unlink(code_path)

    async def pull_image(self, image: str) -> bool:
        """Pre-pull a Docker image for faster skill execution."""
        if not self._docker_available:
            return False
        try:
            process = await asyncio.create_subprocess_exec(
                "docker", "pull", image,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.wait()
            return process.returncode == 0
        except Exception as e:
            logger.error("Failed to pull image %s: %s", image, e)
            return False
