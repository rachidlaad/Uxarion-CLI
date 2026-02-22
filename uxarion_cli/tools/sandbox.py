# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import shutil
import time
from pathlib import Path
from typing import AsyncGenerator, Dict, List, Optional, Tuple

from .models import ExecutionResult
from .utils import SESSIONS_DIR


class CommandBlocked(Exception):
    pass


class SecureSandbox:
    """Secure command execution sandbox with stream support and special actions."""

    def __init__(self, session_dir: Optional[Path] = None):
        target_dir = session_dir or SESSIONS_DIR / "default"
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            fallback_root = Path.cwd() / ".uxarion_local"
            fallback_root.mkdir(parents=True, exist_ok=True)
            target_dir = fallback_root / (session_dir.name if session_dir else "default")
            target_dir.mkdir(parents=True, exist_ok=True)
        self.session_dir = target_dir
        (self.session_dir / "actions").mkdir(exist_ok=True)
        # (self.session_dir / "screenshots").mkdir(exist_ok=True)  # DISABLED: browser automation removed

        # Block dangerous commands instead of maintaining restrictive allowlists
        self.blocklist: Tuple[re.Pattern, ...] = (
            re.compile(r"\brm\s+-rf\s+/"),  # Prevent recursive deletion
            re.compile(r"\bsudo\b"),  # No privilege escalation
            re.compile(r":\(\)\{:\|:&\};:"),  # Fork bomb protection
            re.compile(r"\bdd\s+if=|\bmkfs\b|\bmount\b|\bumount\b"),  # Filesystem manipulation
            re.compile(r"\bzap-scan\b"),  # Block zap-scan specifically
        )

        # Keep special actions that need custom handling
        self.special_actions = ("zap-scan",)

    async def execute_command_stream(self, cmd: str, action_id: str, timeout: int = 600) -> AsyncGenerator[Dict, None]:
        cmd = cmd.strip()
        self._validate_command(cmd)

        # DISABLED: Browser automation functionality removed
        # if cmd.startswith("browser-do "):
        #     async for evt in self._browser_do(cmd[len("browser-do "):], action_id):
        #         yield evt
        #     return
        if cmd.startswith("zap-scan "):
            async for evt in self._zap_scan(cmd[len("zap-scan "):], action_id):
                yield evt
            return

        # Add --batch flag for interactive tools like sqlmap
        if cmd.startswith("sqlmap "):
            if " --batch" not in cmd:
                cmd = f"{cmd} --batch"

        # Use simple subprocess.run approach like execute_command for reliability
        import subprocess
        import time

        start = time.monotonic()
        env = {**os.environ, "PYTHONUNBUFFERED": "1"}

        try:
            # Use subprocess.run with capture_output for simple, reliable capture
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                executable="/bin/bash"
            )

            stdout_lines = result.stdout.split('\n') if result.stdout else []
            stderr_lines = result.stderr.split('\n') if result.stderr else []

            # Yield stdout lines
            for line in stdout_lines:
                if line.strip():  # Only yield non-empty lines
                    yield {
                        "type": "output",
                        "stream": "stdout",
                        "line": line.strip(),
                        "action_id": action_id,
                    }

            # Yield stderr lines
            for line in stderr_lines:
                if line.strip():  # Only yield non-empty lines
                    yield {
                        "type": "output",
                        "stream": "stderr",
                        "line": line.strip(),
                        "action_id": action_id,
                    }

            # Yield completion event
            yield {"type": "complete", "rc": int(result.returncode), "action_id": action_id}

        except subprocess.TimeoutExpired:
            yield {
                "type": "output",
                "stream": "stderr",
                "line": "Command timed out",
                "action_id": action_id,
            }
            yield {"type": "complete", "rc": 124, "action_id": action_id}

    def _truncate_output(self, lines: List[str], max_lines: int = 10) -> str:
        """Simple output truncation: first 5 lines + ... + last few lines"""
        if len(lines) <= max_lines:
            return "\n".join(lines)

        first_5 = lines[:5]
        last_3 = lines[-3:]

        result = "\n".join(first_5)
        result += "\n\n... (truncated) ...\n\n"
        result += "\n".join(last_3)
        return result

    async def execute_command(self, cmd: str, timeout: int = 600) -> ExecutionResult:
        """Simple approach: capture full output then truncate"""
        start = time.monotonic()
        cmd = cmd.strip()
        self._validate_command(cmd)

        # Add --batch flag for interactive tools like sqlmap
        if cmd.startswith("sqlmap "):
            if " --batch" not in cmd:
                cmd = f"{cmd} --batch"

        env = {**os.environ, "PYTHONUNBUFFERED": "1"}

        try:
            # Use subprocess.run with capture_output for simple, reliable capture
            import subprocess
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                executable="/bin/bash"
            )

            # Split into lines for truncation
            stdout_lines = result.stdout.split('\n') if result.stdout else []
            stderr_lines = result.stderr.split('\n') if result.stderr else []

            # Apply simple truncation
            stdout_truncated = self._truncate_output(stdout_lines)
            stderr_truncated = self._truncate_output(stderr_lines)

            return ExecutionResult(
                command=cmd,
                stdout=stdout_truncated,
                stderr=stderr_truncated,
                exit_code=result.returncode,
                duration=(time.monotonic() - start)
            )

        except subprocess.TimeoutExpired:
            return ExecutionResult(
                command=cmd,
                stdout="Command timed out",
                stderr="",
                exit_code=124,
                duration=timeout
            )
        except Exception as e:
            return ExecutionResult(
                command=cmd,
                stdout="",
                stderr=f"Execution error: {str(e)}",
                exit_code=1,
                duration=(time.monotonic() - start)
            )

    def _validate_command(self, cmd: str) -> None:
        # Check blocklist first - reject dangerous commands
        for pat in self.blocklist:
            if pat.search(cmd):
                raise CommandBlocked(f"Command blocked by safety policy: {pat.pattern}")

        # Handle special actions that need custom processing (after blocklist check)
        if any(cmd.startswith(action) for action in self.special_actions):
            return

        # Allow most penetration testing tools by default (blocklist approach)

    async def _merge_streams(self, proc, out_iter, err_iter, timeout: int):
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        next_out = None
        next_err = None
        while True:
            if loop.time() > deadline:
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                yield {"type": "complete", "rc": 124}
                return
            if next_out is None:
                try:
                    next_out = await asyncio.wait_for(out_iter.__anext__(), timeout=0.2)
                except StopAsyncIteration:
                    next_out = "__DONE__"
                except asyncio.TimeoutError:
                    pass
            if next_err is None:
                try:
                    next_err = await asyncio.wait_for(err_iter.__anext__(), timeout=0.2)
                except StopAsyncIteration:
                    next_err = "__DONE__"
                except asyncio.TimeoutError:
                    pass
            if isinstance(next_out, dict):
                yield next_out
                next_out = None
            if isinstance(next_err, dict):
                yield next_err
                next_err = None
            if next_out == "__DONE__" and next_err == "__DONE__":
                return

    # DISABLED: Browser automation functionality removed
    # async def _browser_do(self, json_payload: str, action_id: str):
    #     try:
    #         spec = json.loads(json_payload)
    #         actions = spec.get("actions", [])
    #     except Exception as e:
    #         yield {"type": "output", "stream": "stderr", "line": f"Invalid browser-do JSON: {e}", "action_id": action_id}
    #         yield {"type": "complete", "rc": 2, "action_id": action_id}
    #         return
    #     for step in actions:
    #         t = (step.get("type") or step.get("action") or "").lower()
    #         if t in ("navigate", "goto"):
    #             url = step.get("url", "")
    #             yield {"type": "output", "stream": "stdout", "line": f"[browser] navigate {url}", "action_id": action_id}
    #             await asyncio.sleep(0.05)
    #         elif t == "type":
    #             sel = step.get("selector")
    #             txt = step.get("text", "")
    #             yield {"type": "output", "stream": "stdout", "line": f"[browser] type '{txt}' into {sel}", "action_id": action_id}
    #         elif t == "click":
    #             sel = step.get("selector")
    #             yield {"type": "output", "stream": "stdout", "line": f"[browser] click {sel}", "action_id": action_id}
    #         elif t == "scroll":
    #             yield {"type": "output", "stream": "stdout", "line": "[browser] scroll", "action_id": action_id}
    #         elif t == "inspect":
    #             yield {"type": "output", "stream": "stdout", "line": "[browser] inspect DOM", "action_id": action_id}
    #         elif t == "screenshot":
    #             path = await self._write_placeholder_png()
    #             yield {"type": "output", "stream": "stdout", "line": f"[browser] screenshot -> {path}", "action_id": action_id}
    #             yield {"type": "live_stream", "action_id": action_id, "path": str(path)}
    #         else:
    #             yield {"type": "output", "stream": "stderr", "line": f"[browser] unknown action: {t}", "action_id": action_id}
    #     yield {"type": "complete", "rc": 0, "action_id": action_id}

    # DISABLED: Screenshot functionality removed (only used by browser automation)
    # async def _write_placeholder_png(self) -> Path:
    #     data = (
    #         b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\x0bIDAT\x08\x99c``\x00\x00\x00\x04\x00\x01\x0e\x82\x02\x7e\x00\x00\x00\x00IEND\xAE\x42\x60\x82"
    #     )
    #     fname = f"screenshot_{int(time.time()*1000)}.png"
    #     path = self.session_dir / "screenshots" / fname
    #     path.write_bytes(data)
    #     return path

    async def _zap_scan(self, arg: str, action_id: str):
        url = arg.strip().split()[0] if arg.strip() else ""
        if not url:
            yield {"type": "output", "stream": "stderr", "line": "zap-scan requires URL", "action_id": action_id}
            yield {"type": "complete", "rc": 2, "action_id": action_id}
            return
        for p in (0, 25, 50, 75, 100):
            await asyncio.sleep(0.05)
            yield {"type": "output", "stream": "stdout", "line": f"[zap] progress {p}% on {url}", "action_id": action_id}
        yield {"type": "complete", "rc": 0, "action_id": action_id}
