#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Zevionx – AI-driven pentesting agent with single execution gateway."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set

import requests

try:
    from rich.console import Console
    RICH_AVAILABLE = True
except ImportError:  # pragma: no cover - rich optional
    Console = None  # type: ignore[assignment]
    RICH_AVAILABLE = False

try:
    from colorama import Fore, Style, init as colorama_init

    colorama_init()  # type: ignore[misc]
except Exception:  # pragma: no cover - colorama optional
    class _ForeFallback:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ""

    class _StyleFallback:
        RESET_ALL = ""
        BRIGHT = ""
        DIM = ""

    Fore = _ForeFallback()  # type: ignore[assignment]
    Style = _StyleFallback()  # type: ignore[assignment]


RESET = getattr(Style, "RESET_ALL", "")
DIM = getattr(Style, "DIM", "")
BRIGHT = getattr(Style, "BRIGHT", "")


def _color(text: str, prefix: str) -> str:
    return f"{prefix}{text}{RESET}" if prefix else text


openai_client = None
gemini_api_key = None

DEFAULT_PROVIDER = "openai"
OPENAI_MODEL = "gpt-5"
GEMINI_MODEL = "gemini-1.5-flash-latest"

DEFAULT_TIMEOUT_S = 600
MIN_TIMEOUT_S = 10
MAX_TIMEOUT_S = 3600
IDLE_TIMEOUT_S = 180
WALL_CLOCK_LIMIT_S: Optional[int] = None
SCHEMA_VERSION = "1.0"

_ENV_DEFAULT_TOOLS = os.environ.get("ZEVIONX_ALLOW_TOOLS") or os.environ.get("POWN_ALLOW_TOOLS")
DEFAULT_TOOL_ALLOW: Optional[Set[str]] = (
    {tool.strip() for tool in _ENV_DEFAULT_TOOLS.split(",") if tool.strip()}
    if _ENV_DEFAULT_TOOLS
    else None
)

DANGEROUS_PATTERNS = [
    r"\brm\s+-rf\s+/(?:\s|$)",
    r"\bmkfs\.",
    r"\bdd\s+if=",
    r"\bshutdown\b",
    r"\breboot\b",
    r":\(\)\s*{\s*:\s*\|\s*:\s*;\s*}\s*;\s*:",
    r"\bchown\s+-R\s+/",
    r"\bchmod\s+-R\s+777\s+/",
]
# ----------------------------------------------------------------------------
# Policy / memory containers
# ----------------------------------------------------------------------------


@dataclass
class Policy:
    dry_run: bool = False
    no_command_timeouts: bool = False
    idle_timeout_s: int = IDLE_TIMEOUT_S
    show_banner: bool = True
    jsonl_path: Optional[str] = None
    verbosity: str = "normal"


@dataclass
class Memory:
    history: List[Dict[str, Any]] = field(default_factory=list)
    discovered_vulns: List[str] = field(default_factory=list)


# ----------------------------------------------------------------------------
# Command execution (single gateway target)
# ----------------------------------------------------------------------------


def stream_command_execution(
    command: str,
    timeout: Optional[int] = DEFAULT_TIMEOUT_S,
    idle_timeout: Optional[int] = IDLE_TIMEOUT_S,
    *,
    workdir: Optional[str] = None,
    use_stdbuf: bool = False,
    emit_console: bool = True,
    line_callback: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Run a shell command and stream output to stdout."""
    if emit_console:
        print(f"\ncmd> {command}")
        print("\033[90m" + "─" * 80 + "\033[0m")

    try:
        run_cmd = command
        if use_stdbuf and command.lstrip()[:6] != "stdbuf":
            run_cmd = f"stdbuf -oL -eL {command}"
        start = time.time()
        last_output = start
        proc = subprocess.Popen(
            run_cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1,
            executable="/bin/bash",
            preexec_fn=os.setsid,
            cwd=workdir,
        )

        output_lines: List[str] = []
        termination_reason = "completed"
        last_line: Optional[str] = None
        last_line_time = start
        repeat_count = 0
        suppress_until = 0.0
        while True:
            now = time.time()
            if timeout and (now - start) > timeout:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGINT)
                    proc.wait(timeout=8)
                    termination_reason = "timeout"
                except Exception:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    termination_reason = "timeout_killed"
                if emit_console:
                    print(f"\033[91m⏰ Command timed out after {timeout}s\033[0m")
                break

            line = proc.stdout.readline()
            if not line and proc.poll() is not None:
                break
            if line:
                clean = line.rstrip("\n")
                output_lines.append(clean)
                if line_callback:
                    try:
                        line_callback(clean)
                    except Exception:
                        pass
                if clean == last_line and (now - last_line_time) < 2.0:
                    repeat_count += 1
                    if repeat_count > 5:
                        if now < suppress_until:
                            last_output = now
                            continue
                        suppress_until = now + 1.0
                        last_output = now
                        continue
                else:
                    repeat_count = 0
                    last_line = clean
                    last_line_time = now
                if emit_console:
                    print(f"\033[90m{clean}\033[0m")
                last_output = now

            if idle_timeout and (now - last_output) > idle_timeout:
                try:
                    if emit_console:
                        print(f"\033[91m🔕 No output for {idle_timeout}s — sending SIGINT\033[0m")
                    os.killpg(os.getpgid(proc.pid), signal.SIGINT)
                    proc.wait(timeout=8)
                    termination_reason = "idle"
                except Exception:
                    if emit_console:
                        print("\033[91m💀 Escalating to SIGKILL\033[0m")
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    termination_reason = "idle_killed"
                break

        returncode = proc.wait()
        duration = time.time() - start
        if emit_console:
            print("\033[90m" + "─" * 80 + "\033[0m")
            print(f"✅ Exit code: {returncode} | Duration: {duration:.1f}s\n")

        return {
            "returncode": returncode,
            "output": "\n".join(output_lines),
            "duration": round(duration, 2),
            "termination_reason": termination_reason,
        }
    except Exception as exc:
        if emit_console:
            print(f"\033[91m❌ Error: {exc}\033[0m")
        return {
            "returncode": 1,
            "output": f"Execution failed: {exc}",
            "duration": 0.0,
            "termination_reason": "error",
        }


def parse_max_commands(user_prompt: str) -> Optional[int]:
    """Extract strict command budgets from the user request."""
    patterns = [
        r"\bexactly\s+(\d+)\s+commands?\b",
        r"\brun\s+(\d+)\s+commands?\b",
        r"\b(\d+)\s+commands?\s*(?:max|maximum|only)?\b",
    ]
    for pat in patterns:
        match = re.search(pat, user_prompt, flags=re.IGNORECASE)
        if match:
            try:
                return max(1, int(match.group(1)))
            except ValueError:
                continue
    return None


def in_cidrs(ip: ipaddress._BaseAddress, cidrs: Optional[List[ipaddress._BaseNetwork]]) -> bool:
    if not cidrs:
        return True
    return any(ip in network for network in cidrs)


def parse_hosts_and_urls(s: str) -> tuple[Set[str], Set[str]]:
    urls = {
        match.group(0)
        for match in re.finditer(r"https?://[A-Za-z0-9\.\-]+(?::\d+)?(?:/[^\s]*)?", s)
    }

    hosts: Set[str] = set()

    for match in re.finditer(r"https?://([^/\s:]+)", s):
        token = match.group(1).strip("[]'\"")
        if token:
            hosts.add(token)

    for match in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", s):
        token = match.group(0).strip("[]'\"")
        if token:
            hosts.add(token)

    for match in re.finditer(r"\b[0-9a-fA-F]+:[0-9a-fA-F:]*[0-9a-fA-F]+\b", s):
        token = match.group(0).strip("[]'\"")
        if token:
            hosts.add(token)

    if "localhost" in s:
        hosts.add("localhost")

    hosts.discard("")
    return hosts, urls


def first_tool(cmd: str) -> str:
    try:
        parts = shlex.split(cmd)
    except Exception:
        return ""
    return parts[0] if parts else ""


def validate_freeform_command(
    cmd: str,
    *,
    scope_hosts: Set[str],
    allow_tools: Optional[Set[str]] = None,
    deny_tools: Set[str] = frozenset(),
    scope_cidrs: Optional[List[ipaddress._BaseNetwork]] = None,
) -> tuple[bool, str, Dict[str, Any]]:
    statement = cmd.strip()

    for pat in DANGEROUS_PATTERNS:
        if re.search(pat, statement):
            return False, f"dangerous pattern: {pat}", {"risk": 1.0}

    tool = first_tool(statement)
    if tool in deny_tools:
        return False, f"tool explicitly denied: {tool}", {"risk": 0.9}

    if tool and shutil.which(tool) is None:
        return False, f"tool not found on PATH: {tool}", {"risk": 0.6, "missing_tool": tool}

    hosts, _ = parse_hosts_and_urls(statement)
    if hosts:
        out_of_scope = {host for host in hosts if scope_hosts and host not in scope_hosts}
        if out_of_scope:
            return False, f"out-of-scope host(s): {', '.join(sorted(out_of_scope))}", {"risk": 0.7}
        if scope_cidrs:
            for host in hosts:
                try:
                    ip_obj = ipaddress.ip_address(host)
                except ValueError:
                    continue
                if not in_cidrs(ip_obj, scope_cidrs):
                    return False, f"IP {host} outside allowed CIDR ranges", {"risk": 0.7}

    if tool == "sqlmap" and "--batch" not in statement:
        return False, "sqlmap must include --batch (non-interactive)", {"risk": 0.4}

    return True, "ok", {"risk": 0.3, "tool": tool}


def validate_decision_schema(decision: Dict[str, Any]) -> tuple[bool, str]:
    if not isinstance(decision, dict):
        return False, "planner response not a JSON object"
    if "stop" not in decision or not isinstance(decision["stop"], bool):
        return False, "missing or invalid 'stop' boolean"
    if "reason" not in decision or not isinstance(decision["reason"], str):
        return False, "missing or invalid 'reason' string"
    stop_flag = decision["stop"]
    command_value = decision.get("command")
    if stop_flag:
        if command_value is not None and not isinstance(command_value, str):
            return False, "'command' must be string when provided"
    else:
        if not isinstance(command_value, str) or not command_value.strip():
            return False, "non-stop decisions must include a non-empty command string"
    timeout_hint = decision.get("timeout_hint")
    if timeout_hint is not None and not isinstance(timeout_hint, (int, float)):
        return False, "timeout_hint must be an integer or null"
    return True, "ok"


def load_api_keys() -> Dict[str, str]:
    keys: Dict[str, str] = {}
    try:
        with open(".env", "r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if stripped.startswith("OPENAI_API_KEY="):
                    keys["openai"] = stripped.split("=", 1)[1]
                if stripped.startswith("GEMINI_API_KEY="):
                    keys["gemini"] = stripped.split("=", 1)[1]
    except FileNotFoundError:
        pass

    env_openai = os.getenv("OPENAI_API_KEY")
    env_gemini = os.getenv("GEMINI_API_KEY")
    if env_openai and "openai" not in keys:
        keys["openai"] = env_openai
    if env_gemini and "gemini" not in keys:
        keys["gemini"] = env_gemini
    return keys


def get_openai_client():
    global openai_client
    if openai_client is None:
        keys = load_api_keys()
        if "openai" not in keys:
            raise RuntimeError("OPENAI_API_KEY not configured")
        from openai import OpenAI

        openai_client = OpenAI(api_key=keys["openai"])
    return openai_client


def get_gemini_key() -> str:
    global gemini_api_key
    if gemini_api_key is None:
        keys = load_api_keys()
        if "gemini" not in keys:
            raise RuntimeError("GEMINI_API_KEY not configured")
        gemini_api_key = keys["gemini"]
    return gemini_api_key


# ----------------------------------------------------------------------------
# Timeout helpers & sanitizers
# ----------------------------------------------------------------------------


def _clamp_timeout(value: Optional[int]) -> int:
    base = value if value is not None else DEFAULT_TIMEOUT_S
    return max(MIN_TIMEOUT_S, min(MAX_TIMEOUT_S, int(base)))


def _classify_command(cmd: str) -> str:
    lowered = cmd.lower()
    if re.search(r"\b(curl|wget)\b", lowered) and not re.search(r"(-i|-I|-d\s|--data|--proxy|--retry|\b-F\b)", lowered):
        return "http_probe_fast"
    if re.search(r"(-w\s|wordlist|--rate|--threads)", lowered):
        return "content_enum"
    if re.search(r"(-p-|--top-ports|-sC|-sV|-A|--level|--risk)", lowered):
        return "deep_scan"
    if re.search(r"(--forms|--batch|--crawl|--dbs|--tables)", lowered):
        return "automated_injection"
    return "generic"


def _suggest_timeout_for(cmd: str) -> int:
    category = _classify_command(cmd)
    return {
        "http_probe_fast": 60,
        "content_enum": 600,
        "deep_scan": 1200,
        "automated_injection": 1500,
        "generic": DEFAULT_TIMEOUT_S,
    }[category]


# ----------------------------------------------------------------------------
# AI helpers – chat JSON / text with hardening
# ----------------------------------------------------------------------------


def chat_json_openai(system: str, payload: Dict[str, Any], model: str = OPENAI_MODEL) -> Dict[str, Any]:
    client = get_openai_client()
    try:
        resp = client.chat.completions.create(
            model=model,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": json.dumps(payload, indent=2)},
            ],
            timeout=30,
        )
    except Exception as exc:
        raise RuntimeError(f"OpenAI JSON completion failed: {exc}") from exc
    content = resp.choices[0].message.content or "{}"
    return json.loads(content)


def chat_text_openai(system: str, payload: Dict[str, Any], model: str = OPENAI_MODEL) -> str:
    client = get_openai_client()
    try:
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": json.dumps(payload, indent=2)},
            ],
            timeout=30,
        )
    except Exception as exc:
        raise RuntimeError(f"OpenAI text completion failed: {exc}") from exc
    return resp.choices[0].message.content or ""


def _clean_json_candidate(raw: str) -> str:
    text = raw.strip()
    if text.startswith("```json"):
        text = text[7:]
    if text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    return text.strip()


def chat_json_gemini(system: str, payload: Dict[str, Any], model: str = GEMINI_MODEL) -> Dict[str, Any]:
    api_key = get_gemini_key()
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    prompt = (
        f"{system}\n\nContext:\n{json.dumps(payload, indent=2)}\n"
        "Respond with a single JSON object matching the schema."
    )
    body = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.1,
            "maxOutputTokens": 4000,
            "responseMimeType": "application/json",
        },
    }

    last_error: Optional[Exception] = None
    for attempt in range(3):
        try:
            response = requests.post(url, json=body, timeout=60)
            response.raise_for_status()
            data = response.json()
            candidates = data.get("candidates", [])
            if not candidates:
                raise RuntimeError(f"Gemini returned no candidates: {data}")
            content = candidates[0]["content"]["parts"][0]["text"]
            cleaned = _clean_json_candidate(content)
            try:
                parsed = json.loads(cleaned)
            except json.JSONDecodeError:
                # Balanced brace fallback
                start = cleaned.find("{")
                if start == -1:
                    raise
                depth = 0
                end = None
                for idx, char in enumerate(cleaned[start:], start=start):
                    if char == "{":
                        depth += 1
                    elif char == "}":
                        depth -= 1
                        if depth == 0:
                            end = idx + 1
                            break
                if end is None:
                    raise
                parsed = json.loads(cleaned[start:end])
            if isinstance(parsed, list):
                if not parsed:
                    raise RuntimeError("Gemini returned empty list")
                parsed = parsed[0]
            if not isinstance(parsed, dict):
                raise RuntimeError("Gemini response was not a JSON object")
            return parsed
        except Exception as err:  # noqa: PERF203
            last_error = err
            time.sleep(1)
    raise RuntimeError(f"Gemini JSON request failed: {last_error}")


def chat_text_gemini(system: str, payload: Dict[str, Any], model: str = GEMINI_MODEL) -> str:
    api_key = get_gemini_key()
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    prompt = f"{system}\n\nInput:\n{json.dumps(payload, indent=2)}\nRespond in plain text."
    body = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.1,
            "maxOutputTokens": 3000,
            "responseMimeType": "text/plain",
        },
    }
    response = requests.post(url, json=body, timeout=60)
    response.raise_for_status()
    data = response.json()
    candidates = data.get("candidates", [])
    if not candidates:
        return "No response"
    return candidates[0]["content"]["parts"][0]["text"]


def chat_json(
    system: str,
    payload: Dict[str, Any],
    provider: str = DEFAULT_PROVIDER,
    *,
    retries: int = 10,
    backoff_seconds: float = 1.0,
) -> Dict[str, Any]:
    last_error: Optional[Exception] = None
    for attempt in range(1, retries + 1):
        try:
            if provider == "openai":
                return chat_json_openai(system, payload)
            if provider == "gemini":
                return chat_json_gemini(system, payload)
            raise RuntimeError(f"Unknown provider {provider}")
        except Exception as exc:  # noqa: PERF203
            last_error = exc
            if attempt == retries:
                break
            time.sleep(backoff_seconds)
    raise RuntimeError(
        f"AI decision request failed after {retries} retries; connection appears unstable."
    ) from last_error


def chat_text(system: str, payload: Dict[str, Any], provider: str = DEFAULT_PROVIDER) -> str:
    if provider == "openai":
        return chat_text_openai(system, payload)
    if provider == "gemini":
        return chat_text_gemini(system, payload)
    raise RuntimeError(f"Unknown provider {provider}")


# ----------------------------------------------------------------------------
# Alignment, fallback, compression
# ----------------------------------------------------------------------------

ALIGN_INTENT_PROMPT = (
    "Rewrite the user's request into one concise paragraph describing goal, scope,"
    " targets, and constraints for an authorized penetration test."
    " Respond with JSON {\"intent_paragraph\": str, \"assumptions\": [str],"
    " \"derived_targets\": [str]} only."
)


def align_intent_paragraph(user_prompt: str, provider: str) -> Dict[str, Any]:
    try:
        result = chat_json(ALIGN_INTENT_PROMPT, {"user_request": user_prompt}, provider)
        return {
            "intent_paragraph": result.get("intent_paragraph", user_prompt.strip()),
            "assumptions": result.get("assumptions", []),
            "derived_targets": result.get("derived_targets", []),
        }
    except Exception as exc:
        raise RuntimeError(
            "Intent alignment failed; ensure internet connectivity and a valid provider configuration."
        ) from exc


def summarize_for_report(history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    summary: List[Dict[str, Any]] = []
    for item in history:
        obs = item.get("observation", {})
        summary.append(
            {
                "phase": item.get("phase", ""),
                "analysis": item.get("analysis", ""),
                "command": obs.get("command", ""),
                "returncode": obs.get("returncode", 0),
                "duration": obs.get("duration", 0),
                "output_excerpt": obs.get("output", "")[:300],
            }
        )
    return summary


def _history_excerpt(history: List[Dict[str, Any]], limit: int = 6) -> str:
    lines: List[str] = []
    for item in reversed(history[-limit:]):
        obs = item.get("observation", {})
        cmd = (obs.get("command") or item.get("command") or "").strip()
        rc = obs.get("returncode")
        note = ""
        termination = obs.get("termination_reason")
        if termination == "dry-run":
            note = "dry-run"
        elif item.get("validator", {}).get("ok") is False:
            reason = item.get("validator", {}).get("reason", "")
            note = f"rejected: {reason}".strip()
        elif obs.get("tool_info", {}).get("present") is False:
            path_hint = obs.get("tool_info", {}).get("path", "")
            note = f"tool_not_found: {path_hint}".strip()
        else:
            output_text = obs.get("output") or ""
            for line in output_text.splitlines():
                stripped = line.strip()
                if stripped:
                    note = stripped[:120]
                    break
        if note:
            if len(note) > 120:
                note = note[:117] + "…"
            lines.append(f"- {cmd} :: rc={rc} :: {note}")
        else:
            lines.append(f"- {cmd} :: rc={rc}")
    return "\n".join(lines) if lines else "(none)"


def detect_header_vulns(command: str, output: str, *, scheme: str = "http") -> Optional[List[str]]:
    lowered_cmd = command.lower()
    if "curl -i" not in lowered_cmd:
        return None
    if not (
        re.search(r"^HTTP/\d\.\d\s+\d{3}", output, re.MULTILINE)
        or re.search(r"^[A-Za-z-]+:\s", output, re.MULTILINE)
    ):
        return None
    headers = output.lower()
    missing = []
    if "x-frame-options" not in headers:
        missing.append("X-Frame-Options")
    if "content-security-policy" not in headers:
        missing.append("Content-Security-Policy")
    if scheme == "https" and "strict-transport-security" not in headers:
        missing.append("Strict-Transport-Security")
    return missing if missing else None


def should_finish(decision: Dict[str, Any], observation: Dict[str, Any]) -> bool:
    phase = (decision.get("phase") or "").lower()
    if phase == "report":
        return True
    finish_note = (decision.get("finish_if") or "").strip().lower()
    if finish_note and finish_note != "":
        obs_output = observation.get("output", "").lower()
        if finish_note in obs_output:
            return True
    return False


def extract_evidence(output: str, max_lines: int = 6) -> List[str]:
    if not output:
        return []
    heuristics = [
        r"\b(server|version|powered|allowed|method|header|missing|warning|error|vulnerab|cookie|auth|login)\b",
        r"^[A-Z][A-Za-z0-9\-]+:\s*",
        r"^/[A-Za-z0-9._\-]+",
        r"\b\d{3}\b",
    ]
    rx = re.compile("|".join(heuristics), re.IGNORECASE)
    lines = [ln.strip() for ln in output.splitlines() if ln.strip()]
    hits = [ln for ln in lines if rx.search(ln)]
    evidence: List[str] = []
    seen = set()
    for line in hits:
        key = line.lower()
        if key in seen:
            continue
        seen.add(key)
        evidence.append(line)
        if len(evidence) >= max_lines:
            break
    return evidence


def analyze_shell(command: str, sandbox_dir: str) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    info["has_sequence"] = bool(re.search(r";|&&|\|\|", command))
    info["has_subshell"] = ("`" in command) or ("$(" in command)

    segments = [seg.strip() for seg in command.split("|")]
    info["pipe_count"] = max(len(segments) - 1, 0)
    allowed_sinks = {"head", "tail", "grep", "awk", "sed", "cut", "tee"}
    info["pipe_ok"] = True
    info["pipe_sink"] = None
    if info["pipe_count"] > 1:
        info["pipe_ok"] = False
    elif info["pipe_count"] == 1:
        sink_tool = first_tool(segments[-1])
        info["pipe_sink"] = sink_tool
        if sink_tool not in allowed_sinks:
            info["pipe_ok"] = False

    redirects: List[str] = []
    for match in re.finditer(r"(?:^|\s)([0-9]*>{1,2})\s*(\S+)", command):
        redirect_target = match.group(2).strip('"\'')
        redirects.append(redirect_target)
    info["redirects"] = redirects
    info["redirects_ok"] = True
    info["redirect_violations"] = []
    sandbox_dir_abs = os.path.realpath(sandbox_dir)
    for target in redirects:
        if not target:
            continue
        candidate = target if os.path.isabs(target) else os.path.join(sandbox_dir_abs, target)
        abs_target = os.path.realpath(candidate)
        if os.path.commonpath([abs_target, sandbox_dir_abs]) != sandbox_dir_abs:
            info["redirects_ok"] = False
            info["redirect_violations"].append(target)

    info["analysis_ok"] = (
        not info["has_sequence"]
        and not info["has_subshell"]
        and info["pipe_ok"]
        and info["redirects_ok"]
    )
    info["control_ops_blocked"] = False
    info["sandbox_dir"] = sandbox_dir
    return info


def command_signature(cmd: str) -> str:
    try:
        parts = shlex.split(cmd)
    except Exception:
        return cmd.strip()
    if not parts:
        return cmd.strip()
    tool = parts[0]
    args = " ".join(sorted(parts[1:]))
    return f"{tool}::{args}"


# ----------------------------------------------------------------------------
# Agent implementation
# ----------------------------------------------------------------------------

DECISION_PROMPT = """You are an autonomous penetration tester.
Reply ONLY with a JSON object matching:
{{
  "stop": false,
  "reason": "<why this step>",
  "command": "<single non-interactive shell command>"
}}

Context - mission and evidence:
- Objective: {user_intent}
- Target hints: {target_hints}
- Recent activity (newest first): {history_excerpt}
- Available tools detected: {tools_hint}

Engagement doctrine:
1. Start with lightweight reconnaissance (e.g., curl/httpie/banner grabs) before launching intrusive scans.
2. Progress through phases: recon -> enumerate surface -> probe for vulns -> verify/exploit -> report. Reference prior evidence before escalating.
3. Never repeat the same command signature unless parameters meaningfully change.
4. One shell command only; no control operators (; && ||), no subshells (`...` or $(...)). At most one pipe to grep/awk/sed/cut/head/tail/tee.
5. Prefer read-only techniques unless evidence justifies deeper testing. Note justification in "reason".
6. Tools must operate on in-scope hosts/URLs derived from the context above; use actual hostnames from scope/intent (no placeholders like example.com or <target>).
7. Move beyond repeated curl header checks after initial recon; use appropriate tools from the available list for DNS/TLS/service profiling (e.g., nslookup/host, openssl s_client, nmap ssl-enum-ciphers, whatweb/nikto if present).
8. If you intend to stop, respond with {{"stop": true, "reason": "<summary>"}} and omit "command".

Return valid JSON only."""

REPORT_PROMPT = """Create a brief, plain-text penetration test summary with findings, notable evidence, and next steps.
Tone: professional, actionable, 3-5 sentences."""


class Agent:
    def __init__(self, policy: Policy, provider: str = DEFAULT_PROVIDER):
        self.policy = policy
        self.provider = provider
        self.memory = Memory()
        self.tool_cache: Dict[str, Dict[str, Any]] = {}

    def _push_event(
        self,
        callback: Optional[Callable[[Dict[str, Any]], None]],
        payload: Dict[str, Any],
    ) -> None:
        if callback is None:
            return
        try:
            callback(payload)
        except Exception:
            pass

    # ------------------------------------------------------------------
    def _resolve_timeout(self, command: str, timeout_hint: Optional[int]) -> tuple[Optional[int], str]:
        if self.policy.no_command_timeouts:
            return None, "⏱ Per-command timeout: disabled (idle & wall-clock still apply)."
        hint = _clamp_timeout(timeout_hint) if timeout_hint is not None else None
        floor = _suggest_timeout_for(command)
        effective = _clamp_timeout(max(floor, hint or 0))
        return effective, f"⏱ Timeout for this command: {effective}s"

    def _execute_command(
        self,
        command: str,
        analysis: str,
        *,
        effective_timeout: Optional[int],
        workdir: str,
        use_stdbuf: bool,
        emit_console: bool,
        line_callback: Optional[Callable[[str], None]] = None,
    ) -> Dict[str, Any]:
        idle_timeout = self.policy.idle_timeout_s or None

        if self.policy.dry_run:
            if emit_console:
                print(f"\ncmd> {command}")
            return {
                "command": command,
                "original_command": command,
                "purpose": analysis,
                "returncode": 0,
                "output": f"[DRY-RUN] Would execute: {command}",
                "duration": 0.0,
                "timeout_used": effective_timeout,
                "termination_reason": "dry-run",
            }

        result = stream_command_execution(
            command,
            timeout=effective_timeout,
            idle_timeout=idle_timeout,
            workdir=workdir,
            use_stdbuf=use_stdbuf,
            emit_console=emit_console,
            line_callback=line_callback,
        )
        result.update(
            {
                "command": command,
                "original_command": command,
                "purpose": analysis,
                "timeout_used": effective_timeout,
            }
        )
        return result

    # ------------------------------------------------------------------
    def _request_decision_freeform(
        self, user_intent: str, target_hints: str, tools_hint: str
    ) -> Dict[str, Any]:
        prompt = DECISION_PROMPT.format(
            user_intent=user_intent.strip(),
            target_hints=target_hints.strip() or "(none)",
            history_excerpt=_history_excerpt(self.memory.history),
            tools_hint=tools_hint or "none detected",
        )
        return chat_json(prompt, {}, self.provider)

    def _ensure_tool_info(self, tool: str) -> Dict[str, Any]:
        if not tool:
            return {}
        if tool not in self.tool_cache:
            info: Dict[str, Any] = {"present": False}
            path = shutil.which(tool)
            if path:
                info["present"] = True
                info["path"] = path
                try:
                    proc = subprocess.run(
                        [tool, "--version"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        timeout=2,
                    )
                    version_output = (proc.stdout or "").strip()
                    if version_output:
                        info["version"] = version_output.splitlines()[0][:200]
                except Exception:
                    pass
            self.tool_cache[tool] = info
        return self.tool_cache[tool]

    # ------------------------------------------------------------------
    def _generate_report(self, intent_paragraph: str, execution_mode: str) -> str:
        evidence_lines: List[str] = []
        for entry in self.memory.history:
            obs = entry.get("observation", {})
            phase = entry.get("phase", "").upper() or "PHASE"
            for line in obs.get("evidence", []):
                formatted = f"{phase}: {line}" if line else None
                if formatted and formatted not in evidence_lines:
                    evidence_lines.append(formatted)
                if len(evidence_lines) >= 10:
                    break
            if len(evidence_lines) >= 10:
                break

        payload = {
            "intent": intent_paragraph,
            "findings": self.memory.discovered_vulns,
            "history": summarize_for_report(self.memory.history),
            "evidence": evidence_lines,
            "execution_mode": execution_mode,
        }
        report_text = chat_text(REPORT_PROMPT, payload, self.provider)
        if not report_text:
            raise RuntimeError("Report generation returned an empty response.")
        return report_text.strip()

    # ------------------------------------------------------------------
    def run(
        self,
        user_prompt: str,
        *,
        max_commands: Optional[int] = None,
        scope_hosts: Optional[Set[str]] = None,
        allow_tools: Optional[Set[str]] = None,
        deny_tools: Optional[Set[str]] = None,
        scope_cidrs: Optional[List[ipaddress._BaseNetwork]] = None,
        exit_on_first_finding: bool = False,
        report_out_path: Optional[str] = None,
        validate: bool = True,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> Dict[str, Any]:
        run_id = uuid.uuid4().hex
        self.run_id = run_id
        alignment = align_intent_paragraph(user_prompt, self.provider)
        intent_paragraph = alignment.get("intent_paragraph") or user_prompt.strip()
        emit_console = event_callback is None
        if emit_console:
            print(f"\n🎯 Intent: {intent_paragraph}\n")
        self._push_event(
            event_callback,
            {
                "type": "intent",
                "run_id": run_id,
                "intent": intent_paragraph,
                "assumptions": alignment.get("assumptions", []),
                "derived_targets": alignment.get("derived_targets", []),
            },
        )

        target_hints_list = alignment.get("derived_targets", [])

        start_time = time.time()
        step = 0
        hard_cap = max_commands if max_commands is not None else parse_max_commands(user_prompt)
        executed = 0
        stop_reason = "completed"
        artifacts_root = os.environ.get("ZEVIONX_ARTIFACT_DIR") or os.environ.get("POWN_ARTIFACT_DIR")
        if artifacts_root:
            run_dir = os.path.abspath(os.path.join(artifacts_root, run_id))
        else:
            run_dir = os.path.abspath(os.path.join(os.getcwd(), ".zevionx_runs", run_id))
        os.makedirs(run_dir, exist_ok=True)
        execution_cwd = os.getcwd()

        MAX_PLANNER_RETRIES = 3

        if scope_hosts:
            scope_set = {host.strip() for host in scope_hosts if host.strip()}
        else:
            scope_set = set()
        scope_cidrs_list = scope_cidrs or []

        allowed_tools: Optional[Set[str]] = None
        if allow_tools:
            extras = {tool.strip() for tool in allow_tools if tool.strip()}
            allowed_tools = extras or None

        denied_tools = {tool.strip() for tool in deny_tools or set() if tool.strip()}
        validate_commands = validate

        has_stdbuf = shutil.which("stdbuf") is not None

        attempted_commands: Set[str] = set()
        planner_retries = 0
        rejected_count = 0
        duplicate_count = 0
        user_intent_text = user_prompt.strip()
        target_hint_text = "\n".join(str(t) for t in target_hints_list) if target_hints_list else "(none)"

        common_tools = [
            "curl",
            "wget",
            "httpie",
            "nmap",
            "openssl",
            "sslyze",
            "sslscan",
            "whatweb",
            "nikto",
            "gobuster",
            "ffuf",
            "nslookup",
            "host",
            "dig",
            "testssl.sh",
        ]
        available_tools = [tool for tool in common_tools if shutil.which(tool)]
        tools_hint = ", ".join(available_tools) if available_tools else "none detected"

        while True:
            if WALL_CLOCK_LIMIT_S and time.time() - start_time > WALL_CLOCK_LIMIT_S:
                if emit_console:
                    print("⏳ Wall clock limit reached, wrapping up.")
                stop_reason = f"wall-clock limit ({WALL_CLOCK_LIMIT_S}s) reached"
                break

            step += 1

            try:
                decision = self._request_decision_freeform(user_intent_text, target_hint_text, tools_hint)
            except Exception as exc:
                if emit_console:
                    print(f"error: decision request failed ({exc})")
                stop_reason = "planner_failure"
                break

            if "error" in decision:
                if emit_console:
                    print(f"error: planner response contained error ({decision['error']})")
                stop_reason = "planner_error"
                break

            schema_ok, schema_reason = validate_decision_schema(decision)
            if not schema_ok:
                planner_retries += 1
                if planner_retries > MAX_PLANNER_RETRIES:
                    if emit_console:
                        print("error: planner retries exhausted")
                    stop_reason = "planner_retry_exhausted"
                    break
                if planner_retries > 1:
                    if emit_console:
                        print(f"error: invalid planner response ({schema_reason})")
                    stop_reason = "planner_invalid_json"
                    break
                if emit_console:
                    print("error: invalid planner response; retrying")
                continue

            if bool(decision.get("stop")):
                stop_reason = decision.get("reason") or "planner_stop"
                break

            reason_text = (decision.get("reason") or "AI-generated command").strip()
            command = (decision.get("command") or "").strip()
            timeout_hint = decision.get("timeout_hint")

            if not command:
                if emit_console:
                    print("error: planner returned empty command; retrying")
                planner_retries += 1
                if planner_retries > MAX_PLANNER_RETRIES:
                    if emit_console:
                        print("error: planner retries exhausted")
                    stop_reason = "planner_retry_exhausted"
                    break
                if planner_retries > 1:
                    stop_reason = "planner_empty"
                    break
                continue

            if command in attempted_commands:
                duplicate_count += 1
                planner_retries += 1
                if emit_console:
                    print("thinking: trying alternative (duplicate)")
                if planner_retries > MAX_PLANNER_RETRIES:
                    if emit_console:
                        print("error: planner retries exhausted")
                    stop_reason = "planner_retry_exhausted"
                    break
                continue

            self._push_event(
                event_callback,
                {
                    "type": "decision",
                    "run_id": run_id,
                    "step": step,
                    "reason": reason_text,
                    "command": command,
                    "decision": decision,
                },
            )

            validator_record = {"ok": True, "reason": "validation disabled", "risk": 0.0}
            if validate_commands:
                ok, why, meta = validate_freeform_command(
                    command,
                    scope_hosts=scope_set,
                    allow_tools=allowed_tools,
                    deny_tools=denied_tools,
                )
                validator_record = {"ok": ok, "reason": why, **meta}
                if not ok:
                    rejected_count += 1
                    planner_retries += 1
                    attempted_commands.add(command)
                    rejection_entry = {
                        "step": step,
                        "phase": decision.get("phase", "free_form"),
                        "analysis": reason_text,
                        "decision": {"command": command, "reason": reason_text, "stop": False},
                        "observation": {
                            "command": command,
                            "original_command": command,
                            "returncode": None,
                            "output": "",
                            "termination_reason": "rejected",
                        },
                        "validator": validator_record,
                        "source": "free_form",
                    }
                    self.memory.history.append(rejection_entry)
                    self._push_event(
                        event_callback,
                        {
                            "type": "rejected",
                            "run_id": run_id,
                            "step": step,
                            "command": command,
                            "reason": why,
                            "validator": validator_record,
                        },
                    )
                    if emit_console:
                        print(f"rejected: {why}")
                    reason_lower = why.lower()
                    if "dangerous pattern" in reason_lower:
                        if emit_console:
                            print("thinking: trying alternative (unsafe shell)")
                    else:
                        if emit_console:
                            print("thinking: trying alternative (invalid command)")
                    if validator_record.get("missing_tool"):
                        if emit_console:
                            print(f"error: tool not found ({validator_record['missing_tool']})")
                    if planner_retries > MAX_PLANNER_RETRIES:
                        if emit_console:
                            print("error: planner retries exhausted")
                        stop_reason = "planner_retry_exhausted"
                        break
                    continue
            else:
                validator_record["reason"] = "validation disabled"

            tool_name = validator_record.get("tool") or first_tool(command)
            if tool_name:
                validator_record["tool"] = tool_name

            effective_timeout, timeout_msg = self._resolve_timeout(command, timeout_hint)

            thought_line = reason_text.splitlines()[0] if reason_text else "continuing"
            if len(thought_line) > 160:
                thought_line = thought_line[:157] + "…"
            if emit_console:
                print(f"thinking: {thought_line}")
                print(f"→ {command}")

            def _line_event(line: str) -> None:
                self._push_event(
                    event_callback,
                    {
                        "type": "output",
                        "run_id": run_id,
                        "step": step,
                        "command": command,
                        "line": line,
                    },
                )

            observation = self._execute_command(
                command,
                reason_text,
                effective_timeout=effective_timeout,
                workdir=execution_cwd,
                use_stdbuf=has_stdbuf,
                emit_console=emit_console,
                line_callback=_line_event if event_callback else None,
            )
            executed += 1
            planner_retries = 0
            attempted_commands.add(command)

            observation.setdefault("termination_reason", "completed")
            observation["phase"] = decision.get("phase", "free_form")
            observation["decision_id"] = decision.get("decision_id")
            observation["analysis"] = reason_text
            observation["timeout_message"] = timeout_msg
            observation["step_index"] = step
            observation["run_id"] = run_id
            observation["source"] = "free_form"
            observation["tool"] = validator_record.get("tool") or first_tool(command)
            observation["validator"] = validator_record

            is_live_obs = observation.get("termination_reason") not in {"dry-run", "error"}
            if is_live_obs:
                cmd_text = observation.get("command", "") or ""
                scheme_hint = "https" if "https://" in cmd_text else "http"
                header_issues = detect_header_vulns(
                    cmd_text,
                    observation.get("output", ""),
                    scheme=scheme_hint,
                )
                if header_issues:
                    issue_text = ", ".join(header_issues)
                    if emit_console:
                        print(f" HEADER VULNERABILITY DETECTED! Missing Security Headers: {issue_text}")
                    finding = f"Missing security headers ({issue_text}) identified via {observation.get('command')}"
                    if finding not in self.memory.discovered_vulns:
                        self.memory.discovered_vulns.append(finding)
                observation["evidence"] = extract_evidence(observation.get("output", ""))
            else:
                observation["evidence"] = []

            entry = {
                "step": step,
                "phase": decision.get("phase", "free_form"),
                "analysis": reason_text,
                "decision": decision,
                "observation": observation,
                "validator": validator_record,
                "timeout_message": timeout_msg,
                "run_id": run_id,
                "source": "free_form",
            }
            self.memory.history.append(entry)
            self._push_event(
                event_callback,
                {
                    "type": "observation",
                    "run_id": run_id,
                    "step": step,
                    "observation": observation,
                },
            )

            if self.policy.jsonl_path:
                try:
                    jsonl_entry = entry.copy()
                    jsonl_entry.update(
                        {
                            "schema_version": SCHEMA_VERSION,
                            "provider": self.provider,
                            "execution_mode": "dry-run"
                            if observation.get("termination_reason") == "dry-run"
                            else "live",
                            "targets": target_hints_list,
                            "run_id": run_id,
                        }
                    )
                    with open(self.policy.jsonl_path, "a", encoding="utf-8") as jf:
                        jf.write(json.dumps(jsonl_entry, ensure_ascii=False) + "\n")
                except Exception as exc:
                    if emit_console:
                        print(f"⚠️ JSONL write failed: {exc}")

            if should_finish(decision, observation):
                stop_reason = decision.get("reason") or "planner_stop"
                break
            if hard_cap is not None and executed >= hard_cap:
                if emit_console:
                    print(f"🏁 Command budget reached (executed {executed}/{hard_cap}).")
                stop_reason = f"command budget used ({executed}/{hard_cap})"
                break

        live_seen = any(
            entry.get("observation", {}).get("termination_reason") not in {"dry-run", "error"}
            for entry in self.memory.history
        )
        execution_mode = "live" if live_seen else "dry-run"

        report = self._generate_report(intent_paragraph, execution_mode)
        self._push_event(
            event_callback,
            {
                "type": "report",
                "run_id": run_id,
                "execution_mode": execution_mode,
                "report": report,
            },
        )
        report_path = os.path.join(run_dir, "report.md")
        saved_paths: List[str] = []
        try:
            with open(report_path, "w", encoding="utf-8") as handle:
                handle.write(report + "\n")
            saved_paths.append(os.path.abspath(report_path))
        except Exception as exc:
            if emit_console:
                print(f"error: failed to write report ({exc})")

        run_result_path_session = os.path.join(run_dir, "run_result.json")

        result = {
            "history": self.memory.history,
            "discovered_vulnerabilities": self.memory.discovered_vulns,
            "report": report,
            "stop_reason": stop_reason,
            "schema_version": SCHEMA_VERSION,
            "provider": self.provider,
            "execution_mode": execution_mode,
            "targets": target_hints_list,
            "verbosity": self.policy.verbosity,
            "run_id": run_id,
            "report_path": os.path.abspath(report_path),
            "run_result_path": os.path.abspath(run_result_path_session),
        }
        saved_result_path: Optional[str] = None
        try:
            with open("run_result.json", "w", encoding="utf-8") as handle:
                json.dump(result, handle, indent=2)
            saved_result_path = os.path.abspath("run_result.json")
        except Exception as exc:
            if emit_console:
                print(f"error: failed to write run_result.json ({exc})")

        try:
            with open(run_result_path_session, "w", encoding="utf-8") as handle:
                json.dump(result, handle, indent=2)
        except Exception as exc:
            if emit_console:
                print(f"error: failed to write session run_result ({exc})")

        if not saved_paths and saved_result_path:
            saved_paths.append(saved_result_path)
        if saved_paths and emit_console:
            print(f"💾 saved: {saved_paths[0]}")
        self._push_event(
            event_callback,
            {
                "type": "completed",
                "run_id": run_id,
                "stop_reason": stop_reason,
                "result": result,
            },
        )
        return result


# ----------------------------------------------------------------------------
# CLI helpers
# ----------------------------------------------------------------------------


class CLIEventPrinter:
    def __init__(self) -> None:
        self.console = Console() if RICH_AVAILABLE else None
        self.sep = "─" * 80

    def _console_print(self, text: str) -> None:
        if self.console:
            self.console.print(text)
        else:
            print(text)

    def __call__(self, event: Dict[str, Any]) -> None:
        etype = event.get("type")
        if etype == "status":
            message = event.get("message", "")
            if message:
                self._console_print(f"[dim]{message}[/dim]" if self.console else _color(message, DIM))
        elif etype == "intent":
            self._console_print(f"[magenta]{self.sep}[/magenta]" if self.console else self.sep)
            intent = event.get("intent", "")
            if intent:
                if self.console:
                    self.console.print(f"[cyan]🎯 Intent:[/] {intent}")
                else:
                    print(_color("🎯 Intent:", Fore.CYAN) + f" {intent}")
            assumptions = event.get("assumptions") or []
            if assumptions:
                if self.console:
                    self.console.print("[dim]Assumptions:[/dim]")
                    for item in assumptions:
                        self.console.print(f"  [dim]- {item}[/dim]")
                else:
                    print(_color("Assumptions:", DIM))
                    for item in assumptions:
                        print(_color(f"  - {item}", DIM))
            derived = event.get("derived_targets") or []
            if derived:
                if self.console:
                    self.console.print(f"[cyan]Targets:[/] {', '.join(derived)}")
                else:
                    print(_color("Targets:", Fore.CYAN) + f" {', '.join(derived)}")
        elif etype == "decision":
            reason = (event.get("reason") or "").splitlines()[0]
            if reason:
                if self.console:
                    self.console.print(f"[dim]thinking: {reason}[/dim]")
                else:
                    print(_color(f"thinking: {reason}", DIM))
            command = event.get("command")
            if command:
                if self.console:
                    self.console.print(f"[yellow]→ {command}[/yellow]")
                else:
                    print(_color(f"→ {command}", Fore.YELLOW))
        elif etype == "output":
            line = (event.get("line") or "").strip()
            if line:
                if self.console:
                    self.console.print(f"[dim]{line}[/dim]")
                else:
                    print(_color(line, DIM))
        elif etype == "observation":
            obs = event.get("observation", {})
            command = obs.get("command", "")
            rc = obs.get("returncode")
            duration = obs.get("duration")
            self._console_print(f"[magenta]{self.sep}[/magenta]" if self.console else self.sep)
            summary = f"rc={rc}" if rc is not None else ""
            if duration not in (None, ""):
                summary = f"{summary} | {duration}s" if summary else f"{duration}s"
            info = f" ({summary})" if summary else ""
            if self.console:
                self.console.print(f"[green]✓ {command}{info}[/green]")
            else:
                print(_color(f"✓ {command}{info}", Fore.GREEN))
            output = obs.get("output") or ""
            first_line = next((line for line in output.splitlines() if line.strip()), "")
            if first_line:
                if self.console:
                    self.console.print(f"[blue]{first_line[:160]}[/blue]")
                else:
                    print(_color(first_line[:160], Fore.BLUE))
            evidence = obs.get("evidence") or []
            if evidence:
                if self.console:
                    self.console.print(f"[magenta]evidence:[/] {', '.join(evidence)}")
                else:
                    print(_color("evidence:", Fore.MAGENTA) + f" {', '.join(evidence)}")
        elif etype == "report":
            report = event.get("report", "")
            if report:
                self._console_print(f"[magenta]{self.sep}[/magenta]" if self.console else self.sep)
                if self.console:
                    self.console.print("[green]🧾 Report:[/green]")
                    self.console.print(report)
                else:
                    print(_color("🧾 Report:", Fore.GREEN))
                    print(report)
        elif etype == "completed":
            reason = event.get("stop_reason") or event.get("result", {}).get("stop_reason", "")
            if reason:
                if self.console:
                    self.console.print(f"[cyan]Mission complete:[/] {reason}")
                else:
                    print(_color(f"Mission complete: {reason}", Fore.CYAN))
        elif etype == "error":
            if self.console:
                self.console.print(f"[red]error:[/] {event.get('error', 'unknown error')}")
            else:
                print(_color(f"error: {event.get('error', 'unknown error')}", Fore.RED))


def print_banner() -> None:
    banner_lines = [
        "                     Zevionx CLI",
        "",
    ]
    builder_line = "I would be happy for you to connect, collaborate, fix a bug or add a feature to the tool 😊"
    contacts_line = "X.com > @Rachid_LLLL    Gmail > rachidshade@gmail.com    GitHub > https://github.com/rachidlaad"
    mission_line = "Zevionx is an AI pentesting copilot, open-source for the pentesting community."
    quick_actions_line = "Tip: press '/' in chat to update API keys via the quick actions menu."
    website_line = "Official site: https://zevionx.com/"

    console = Console() if RICH_AVAILABLE else None

    if console:
        for line in banner_lines:
            console.print(line, style="cyan")
        console.print(builder_line, style="magenta")
        console.print(contacts_line, style="green")
        console.print()
        console.print(mission_line, style="cyan")
        console.print(website_line, style="cyan")
        console.print(quick_actions_line, style="cyan")
        console.print()
    else:
        for line in banner_lines:
            print(_color(line, getattr(Fore, "CYAN", "")))
        print(_color(builder_line, getattr(Fore, "MAGENTA", "")))
        print(_color(contacts_line, getattr(Fore, "GREEN", "")))
        print()
        print(_color(mission_line, getattr(Fore, "CYAN", "")))
        print(_color(website_line, getattr(Fore, "CYAN", "")))
        print(_color(quick_actions_line, getattr(Fore, "CYAN", "")))
        print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Zevionx AI Pentesting Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python zevionx_cli.py --prompt "Scan http://localhost:8080 with nmap"
  python zevionx_cli.py --prompt "Enumerate directories on https://target.example"
        """,
    )
    parser.add_argument("--prompt", required=True, help="Pentesting objective or instructions")
    parser.add_argument("--dry-run", action="store_true", help="Print actions without executing shells")
    parser.add_argument("--provider", choices=["gemini", "openai"], default=DEFAULT_PROVIDER)
    parser.add_argument("--max-commands", type=int, help="Stop after N executed commands")
    parser.add_argument(
        "--no-command-timeouts",
        action="store_true",
        help="Let tools run to completion (still subject to idle & wall-clock)",
    )
    parser.add_argument(
        "--idle-timeout",
        type=int,
        default=IDLE_TIMEOUT_S,
        help="Idle-output watchdog in seconds (0 disables)",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Hide the ASCII banner",
    )
    parser.add_argument(
        "--jsonl",
        dest="jsonl_path",
        help="Append each observation as JSONL to the given file",
    )
    parser.add_argument(
        "--verbosity",
        choices=["quiet", "normal", "verbose"],
        default="normal",
        help="Output detail level",
    )
    parser.add_argument(
        "--scope",
        help="Comma-separated list of in-scope hosts (defaults to target host, localhost, 127.0.0.1)",
    )
    parser.add_argument(
        "--allow-tools",
        help="Comma-separated tools to add to the allow-list",
    )
    parser.add_argument(
        "--deny-tools",
        help="Comma-separated tools to explicitly deny",
    )
    parser.add_argument(
        "--no-validate",
        action="store_true",
        help="Skip command validation (power users only)",
    )
    parser.add_argument(
        "--scope-cidr",
        help="Comma-separated CIDR ranges host IPs must stay within (e.g. 10.0.0.0/8,192.168.0.0/16)",
    )
    parser.add_argument(
        "--exit-on-first-finding",
        action="store_true",
        help="Stop immediately after the first confirmed finding",
    )
    parser.add_argument(
        "--out",
        help="Write final report to this path and JSON to <path>.run_result.json",
    )
    args = parser.parse_args()

    idle_timeout = args.idle_timeout if args.idle_timeout is not None else IDLE_TIMEOUT_S
    if idle_timeout < 0:
        idle_timeout = 0

    policy = Policy(
        dry_run=args.dry_run,
        no_command_timeouts=args.no_command_timeouts,
        idle_timeout_s=idle_timeout,
        show_banner=not args.no_banner,
        jsonl_path=args.jsonl_path,
        verbosity=args.verbosity,
    )

    if policy.show_banner:
        print_banner()
    print(_color("🎯 Objective:", Fore.CYAN) + f" {args.prompt}")
    if policy.dry_run:
        print(_color("🧪 DRY-RUN MODE – commands will not execute", DIM))

    agent = Agent(policy=policy, provider=args.provider)
    scope_hosts = (
        {host.strip() for host in args.scope.split(",") if host.strip()}
        if args.scope
        else None
    )
    allow_tools = (
        {tool.strip() for tool in args.allow_tools.split(",") if tool.strip()}
        if args.allow_tools
        else None
    )
    deny_tools = (
        {tool.strip() for tool in args.deny_tools.split(",") if tool.strip()}
        if args.deny_tools
        else None
    )
    scope_cidrs = None
    if args.scope_cidr:
        cidr_values: List[ipaddress._BaseNetwork] = []
        for cidr in args.scope_cidr.split(","):
            cidr = cidr.strip()
            if not cidr:
                continue
            try:
                cidr_values.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                print(f"⚠️ Ignoring invalid CIDR: {cidr}")
        if cidr_values:
            scope_cidrs = cidr_values

    report_out_path = args.out
    event_printer = CLIEventPrinter()
    agent.run(
        args.prompt,
        max_commands=args.max_commands,
        scope_hosts=scope_hosts,
        allow_tools=allow_tools,
        deny_tools=deny_tools,
        scope_cidrs=scope_cidrs,
        exit_on_first_finding=args.exit_on_first_finding,
        report_out_path=report_out_path,
        validate=not args.no_validate,
        event_callback=event_printer,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
