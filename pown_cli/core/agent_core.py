"""
4myPown Autonomous Pentesting Agent
Modern architecture inspired by SWE-agent and successful coding agents
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

# Import ai_providers with fallback
try:
    from .ai_providers import resolve_default_provider
except ImportError:
    try:
        from ai_providers import resolve_default_provider
    except ImportError:
        def resolve_default_provider(provider=None):
            return None


@dataclass
class VulnerabilityFinding:
    """Represents an actual discovered vulnerability"""
    vuln_type: str  # sqli, auth_bypass, info_disclosure, etc.
    severity: str   # critical, high, medium, low
    target: str     # URL or endpoint
    evidence: str   # Proof of vulnerability
    payload: str    # What worked
    timestamp: str
    confidence: float  # 0.0 to 1.0


@dataclass
class ExecutionResult:
    """Results from tool execution with vulnerability analysis"""
    command: str
    stdout: str
    stderr: str
    exit_code: int
    duration: float
    vulnerabilities: List[VulnerabilityFinding] = field(default_factory=list)
    attack_surface: Dict[str, any] = field(default_factory=dict)
    next_actions: List[str] = field(default_factory=list)


class VulnerabilityAnalyzer:
    """Analyzes tool outputs for actual vulnerabilities"""

    @staticmethod
    def analyze_output(command: str, stdout: str, stderr: str) -> List[VulnerabilityFinding]:
        """Extract real vulnerabilities from tool output"""
        vulns = []

        # SQL Injection Detection
        vulns.extend(VulnerabilityAnalyzer._detect_sqli(command, stdout, stderr))

        # Authentication Bypass Detection
        vulns.extend(VulnerabilityAnalyzer._detect_auth_bypass(command, stdout, stderr))

        # Information Disclosure Detection
        vulns.extend(VulnerabilityAnalyzer._detect_info_disclosure(command, stdout, stderr))

        # API SQL Injection Detection
        vulns.extend(VulnerabilityAnalyzer._detect_api_sqli(command, stdout, stderr))

        # Debug Information Disclosure
        vulns.extend(VulnerabilityAnalyzer._detect_debug_disclosure(command, stdout, stderr))

        # Admin Panel SQL Injection
        vulns.extend(VulnerabilityAnalyzer._detect_admin_sqli(command, stdout, stderr))

        return vulns

    @staticmethod
    def _detect_sqli(command: str, stdout: str, stderr: str) -> List[VulnerabilityFinding]:
        """Detect SQL injection vulnerabilities"""
        vulns = []

        # SQLMap specific patterns
        if "sqlmap" in command.lower():
            if re.search(r"parameter.*is vulnerable", stdout, re.IGNORECASE):
                param_match = re.search(r"parameter '([^']+)' is vulnerable", stdout, re.IGNORECASE)
                param = param_match.group(1) if param_match else "unknown"

                vulns.append(VulnerabilityFinding(
                    vuln_type="sql_injection",
                    severity="critical",
                    target=VulnerabilityAnalyzer._extract_target(command),
                    evidence=stdout,
                    payload=command,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
                    confidence=0.9
                ))

        # Direct injection patterns in curl/http responses
        if "curl" in command.lower() and ("OR" in command or "UNION" in command or "'" in command):
            # Check for redirect to admin/dashboard (auth bypass)
            if "location:" in stdout.lower() and ("admin" in stdout.lower() or "dashboard" in stdout.lower()):
                vulns.append(VulnerabilityFinding(
                    vuln_type="sql_injection_auth_bypass",
                    severity="critical",
                    target=VulnerabilityAnalyzer._extract_target(command),
                    evidence=f"SQL injection payload resulted in redirect: {stdout}",
                    payload=command,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
                    confidence=0.95
                ))

            # Check for 302 redirect response (common auth bypass indicator)
            elif "302" in stdout and "Found" in stdout:
                vulns.append(VulnerabilityFinding(
                    vuln_type="sql_injection_auth_bypass",
                    severity="critical",
                    target=VulnerabilityAnalyzer._extract_target(command),
                    evidence=f"SQL injection payload resulted in 302 redirect: {stdout[:200]}...",
                    payload=command,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
                    confidence=0.90
                ))

            # Check for session cookie being set (indicates successful auth)
            elif "set-cookie:" in stdout.lower() and "session=" in stdout.lower():
                vulns.append(VulnerabilityFinding(
                    vuln_type="sql_injection_auth_bypass",
                    severity="critical",
                    target=VulnerabilityAnalyzer._extract_target(command),
                    evidence=f"SQL injection payload resulted in session cookie: {stdout[:200]}...",
                    payload=command,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
                    confidence=0.85
                ))

        return vulns

    @staticmethod
    def _detect_auth_bypass(command: str, stdout: str, stderr: str) -> List[VulnerabilityFinding]:
        """Detect authentication bypass vulnerabilities"""
        vulns = []

        # HTTP status code analysis
        if "curl" in command.lower():
            # 302 redirect with admin/dashboard indicates bypass
            if "302" in stdout and ("admin" in stdout.lower() or "dashboard" in stdout.lower()):
                vulns.append(VulnerabilityFinding(
                    vuln_type="authentication_bypass",
                    severity="critical",
                    target=VulnerabilityAnalyzer._extract_target(command),
                    evidence=f"Authentication bypass via redirect: {stdout}",
                    payload=command,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
                    confidence=0.9
                ))

        return vulns

    @staticmethod
    def _detect_info_disclosure(command: str, stdout: str, stderr: str) -> List[VulnerabilityFinding]:
        """Detect information disclosure vulnerabilities"""
        vulns = []

        # Debug endpoints
        if "/debug" in stdout or "debug" in stderr.lower():
            vulns.append(VulnerabilityFinding(
                vuln_type="information_disclosure",
                severity="medium",
                target=VulnerabilityAnalyzer._extract_target(command),
                evidence=f"Debug information exposed: {stdout[:200]}",
                payload=command,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
                confidence=0.7
            ))

        # Error traces with sensitive info
        if "traceback" in stdout.lower() or "stack trace" in stdout.lower():
            vulns.append(VulnerabilityFinding(
                vuln_type="error_disclosure",
                severity="low",
                target=VulnerabilityAnalyzer._extract_target(command),
                evidence=f"Error trace disclosure: {stdout[:200]}",
                payload=command,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
                confidence=0.6
            ))

        return vulns

    @staticmethod
    def _detect_api_sqli(command: str, stdout: str, stderr: str) -> List[VulnerabilityFinding]:
        """Detect API SQL injection vulnerabilities"""
        vulns = []

        # API endpoint SQL injection
        if "api/balance" in command and ("UNION" in command or "OR" in command):
            # Check for successful SQL injection indicators
            if '"balance":' in stdout and ("hacked" in stdout or
                                         "error" not in stdout.lower() and
                                         "not found" not in stdout.lower()):
                vulns.append(VulnerabilityFinding(
                    vuln_type="api_sql_injection",
                    severity="critical",
                    target=VulnerabilityAnalyzer._extract_target(command),
                    evidence=f"API SQL injection successful: {stdout}",
                    payload=command,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
                    confidence=0.95
                ))
            # Check for data exposure via SQL injection
            elif '"balance":' in stdout and len(stdout) > 50:
                vulns.append(VulnerabilityFinding(
                    vuln_type="api_data_exposure",
                    severity="high",
                    target=VulnerabilityAnalyzer._extract_target(command),
                    evidence=f"API returns data for injected query: {stdout}",
                    payload=command,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
                    confidence=0.8
                ))

        return vulns

    @staticmethod
    def _detect_debug_disclosure(command: str, stdout: str, stderr: str) -> List[VulnerabilityFinding]:
        """Detect debug information disclosure vulnerabilities"""
        vulns = []

        # Debug endpoint with secret exposure
        if "/debug/info" in command and "secret_key" in stdout:
            vulns.append(VulnerabilityFinding(
                vuln_type="debug_information_disclosure",
                severity="high",
                target=VulnerabilityAnalyzer._extract_target(command),
                evidence=f"Debug endpoint exposes secrets: {stdout}",
                payload=command,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
                confidence=0.9
            ))

        # Application config exposure
        if "app_config" in stdout and "debug" in stdout:
            vulns.append(VulnerabilityFinding(
                vuln_type="configuration_disclosure",
                severity="medium",
                target=VulnerabilityAnalyzer._extract_target(command),
                evidence=f"Application configuration exposed: {stdout[:200]}",
                payload=command,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
                confidence=0.8
            ))

        return vulns

    @staticmethod
    def _detect_admin_sqli(command: str, stdout: str, stderr: str) -> List[VulnerabilityFinding]:
        """Detect admin panel SQL injection vulnerabilities"""
        vulns = []

        # Admin panel SQL injection - look for error patterns or data exposure
        if "/admin/user/" in command and ("UNION SELECT" in command or "'" in command):
            # Flask debug error indicates SQL injection vulnerability
            if "TypeError:" in stdout and "admin_user_details" in stdout:
                vulns.append(VulnerabilityFinding(
                    vuln_type="admin_panel_sql_injection",
                    severity="critical",
                    target=VulnerabilityAnalyzer._extract_target(command),
                    evidence=f"Admin panel SQL injection confirmed via error: {stdout[:200]}",
                    payload=command,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
                    confidence=0.9
                ))
            # Data exposure via SQL injection
            elif len(stdout) > 100 and ("username" in stdout or "email" in stdout):
                vulns.append(VulnerabilityFinding(
                    vuln_type="admin_panel_sql_injection",
                    severity="critical",
                    target=VulnerabilityAnalyzer._extract_target(command),
                    evidence=f"Admin panel SQL injection exposes data: {stdout[:200]}",
                    payload=command,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
                    confidence=0.85
                ))

        return vulns

    @staticmethod
    def _extract_target(command: str) -> str:
        """Extract target URL from command"""
        # Look for URLs in command
        url_match = re.search(r'https?://[^\s]+', command)
        if url_match:
            return url_match.group(0)

        # Look for localhost references
        if "localhost" in command:
            port_match = re.search(r'localhost:(\d+)', command)
            if port_match:
                return f"http://localhost:{port_match.group(1)}"
            return "http://localhost"

        return "unknown"


class AttackSurfaceMapper:
    """Maps and summarizes newly discovered surface areas for AI planning"""

    def __init__(self):
        self.discovered_endpoints: Set[str] = set()
        self.discovered_parameters: Set[str] = set()
        self.discovered_technologies: Set[str] = set()

    def update_from_result(self, result: ExecutionResult) -> Dict[str, List[str]]:
        """Update internal state and return discovery deltas"""
        endpoints = self._extract_endpoints(result.stdout)
        new_endpoints = endpoints - self.discovered_endpoints
        self.discovered_endpoints.update(endpoints)

        parameters = self._extract_parameters(result.stdout)
        new_parameters = parameters - self.discovered_parameters
        self.discovered_parameters.update(parameters)

        technologies = self._extract_technologies(result.stdout)
        self.discovered_technologies.update(technologies)

        return {
            "new_endpoints": sorted(new_endpoints),
            "new_parameters": sorted(new_parameters),
            "technologies": sorted(self.discovered_technologies),
        }

    def summary(self) -> Dict[str, List[str]]:
        return {
            "endpoints": sorted(self.discovered_endpoints),
            "parameters": sorted(self.discovered_parameters),
            "technologies": sorted(self.discovered_technologies),
        }

    def _extract_endpoints(self, output: str) -> Set[str]:
        """Extract URLs/endpoints from output"""
        endpoints = set()

        # Look for hrefs in HTML
        href_matches = re.findall(r'href=["\']([^"\']+)["\']', output, re.IGNORECASE)
        endpoints.update(href_matches)

        # Look for action attributes in forms
        action_matches = re.findall(r'action=["\']([^"\']+)["\']', output, re.IGNORECASE)
        endpoints.update(action_matches)

        return {ep for ep in endpoints if ep and not ep.startswith('#')}

    def _extract_parameters(self, output: str) -> Set[str]:
        """Extract form parameters from output"""
        parameters = set()

        # Look for input names
        input_matches = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', output, re.IGNORECASE)
        parameters.update(input_matches)

        return parameters

    def _extract_technologies(self, output: str) -> Set[str]:
        """Extract technology stack info"""
        technologies = set()

        # Server headers
        server_match = re.search(r'server:\s*([^\r\n]+)', output, re.IGNORECASE)
        if server_match:
            technologies.add(server_match.group(1).strip())

        return technologies

    def _get_target_from_command(self, command: str) -> Optional[str]:
        """Extract target URL from command"""
        url_match = re.search(r'https?://[^\s]+', command)
        if url_match:
            return url_match.group(0)

        if "localhost" in command:
            port_match = re.search(r'localhost:(\d+)', command)
            if port_match:
                return f"http://localhost:{port_match.group(1)}"
            return "http://localhost"

        return None


class AutonomousPentestAgent:
    """Modern autonomous pentesting agent driven entirely by AI planning"""

    def __init__(self, model_provider: Optional[object] = None):
        if model_provider and hasattr(model_provider, "generate"):
            self.model = model_provider
        else:
            self.model = resolve_default_provider(model_provider)
        if not self.model:
            raise RuntimeError("No AI provider available; configure an AI backend before running the agent.")

        self.vulnerabilities: List[VulnerabilityFinding] = []
        self.attack_surface = AttackSurfaceMapper()
        self.executed_commands: Set[str] = set()
        self.current_target: Optional[str] = None
        self.objective: str = ""
        self.session_cookies: Dict[str, str] = {}
        self.authenticated: bool = False
        self.history: List[Dict[str, object]] = []

    async def pentest(self, objective: str, target: Optional[str] = None) -> List[VulnerabilityFinding]:
        """Autonomous pentesting loop using AI-generated actions only"""
        self.objective = objective
        self.current_target = target
        self.vulnerabilities = []
        self.attack_surface = AttackSurfaceMapper()
        self.executed_commands.clear()
        self.history = []
        self.session_cookies.clear()
        self.authenticated = False

        print(f"🎯 Starting autonomous pentest: {objective}")
        if target:
            print(f"🔍 Target: {target}")

        max_iterations = 20
        iteration = 0
        discoveries: Dict[str, List[str]] = {"new_endpoints": [], "new_parameters": [], "technologies": []}

        analysis, pending_actions, should_stop = await self._request_ai_actions(discoveries, iteration)
        if analysis:
            print(f"\n🤖 AI Analysis:\n{analysis}")

        while iteration < max_iterations and not should_stop:
            if not pending_actions:
                break

            action = pending_actions.pop(0)
            command = (action.get("command") or "").strip()
            if not command or command in self.executed_commands:
                continue

            iteration += 1
            print(f"\n[{iteration}] Executing: {command}")

            result = await self._execute_command(command)
            self.executed_commands.add(command)

            self._extract_session_info(command, result.stdout, result.stderr)

            vulnerabilities = VulnerabilityAnalyzer.analyze_output(
                command, result.stdout, result.stderr
            )

            if vulnerabilities:
                self.vulnerabilities.extend(vulnerabilities)
                for vuln in vulnerabilities:
                    print(f"🚨 VULNERABILITY FOUND: {vuln.vuln_type} - {vuln.severity}")
                    print(f"   Target: {vuln.target}")
                    print(f"   Confidence: {vuln.confidence:.1%}")
                if any(v.severity == "critical" for v in vulnerabilities):
                    print("‼️ Critical finding detected. AI will reprioritize next steps.")

            discoveries = self.attack_surface.update_from_result(result)
            self._record_history_entry(command, result, vulnerabilities, discoveries)

            analysis, pending_actions, should_stop = await self._request_ai_actions(discoveries, iteration)
            if analysis:
                print(f"\n🤖 AI Analysis:\n{analysis}")

        print(f"\n✅ Pentesting complete. Found {len(self.vulnerabilities)} vulnerabilities.")
        return self.vulnerabilities

    async def _execute_command(self, command: str) -> ExecutionResult:
        """Execute command and capture results"""
        start_time = time.time()

        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={"PYTHONUNBUFFERED": "1", **dict(os.environ)}
            )

            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(), timeout=30.0
            )

            stdout = stdout_bytes.decode('utf-8', errors='ignore')
            stderr = stderr_bytes.decode('utf-8', errors='ignore')
            exit_code = process.returncode

        except asyncio.TimeoutError:
            stdout = ""
            stderr = "Command timed out after 30 seconds"
            exit_code = 124
        except Exception as e:
            stdout = ""
            stderr = f"Execution error: {str(e)}"
            exit_code = 1

        duration = time.time() - start_time

        return ExecutionResult(
            command=command,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            duration=duration
        )

    def _record_history_entry(
        self,
        command: str,
        result: ExecutionResult,
        vulnerabilities: List[VulnerabilityFinding],
        discoveries: Dict[str, List[str]],
    ) -> None:
        summary = {
            "command": command,
            "exit_code": result.exit_code,
            "duration": round(result.duration, 2),
            "stdout": result.stdout[:500],
            "stderr": result.stderr[:500],
            "vulnerabilities": [v.vuln_type for v in vulnerabilities],
            "discoveries": discoveries,
        }
        self.history.append(summary)
        if len(self.history) > 10:
            self.history = self.history[-10:]

    async def _request_ai_actions(
        self,
        discoveries: Dict[str, List[str]],
        iteration: int,
    ) -> Tuple[str, List[Dict[str, str]], bool]:
        context = {
            "objective": self.objective,
            "target": self.current_target,
            "iteration": iteration,
            "history": self._history_snapshot(),
            "vulnerabilities": self._vulnerability_snapshot(),
            "attack_surface": self.attack_surface.summary(),
            "recent_discoveries": discoveries,
            "session": {
                "authenticated": self.authenticated,
                "cookies": list(self.session_cookies.keys()),
            },
        }

        prompt = (
            "You are an autonomous penetration tester operating through shell commands.\n"
            "Decide the next safe and effective actions based on the context provided.\n"
            "Respond with JSON using this exact schema:\n"
            "{\n"
            '  "analysis": "<succinct situational analysis>",\n'
            '  "actions": [\n'
            '    {"command": "<shell command>", "reason": "<justification>"}\n'
            "  ],\n"
            '  "stop": false\n'
            "}\n"
            "Rules:\n"
            "- Commands must be fully specified (no placeholders like TARGET).\n"
            "- Return at most 3 commands per response.\n"
            "- Set stop=true when no further autonomous action is appropriate.\n"
            "- Keep analysis under 6 sentences.\n"
            f"Context:\n{json.dumps(context, indent=2)}\n"
        )

        raw = self.model.generate(prompt)
        data = self._parse_ai_json(raw)

        analysis = data.get("analysis", "") if isinstance(data, dict) else ""
        actions: List[Dict[str, str]] = []
        for item in data.get("actions", []) if isinstance(data, dict) else []:
            cmd = (item.get("command") or "").strip()
            if not cmd:
                continue
            actions.append({
                "command": cmd,
                "reason": item.get("reason", ""),
            })

        stop = bool(data.get("stop")) if isinstance(data, dict) else False
        return analysis, actions, stop

    def _parse_ai_json(self, raw: str) -> Dict[str, object]:
        if not raw:
            raise RuntimeError("AI provider returned an empty response")

        cleaned = raw.strip()
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```[a-zA-Z0-9]*\s*", "", cleaned)
            cleaned = re.sub(r"```$", "", cleaned).strip()

        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(0))
                except json.JSONDecodeError:
                    pass
        raise RuntimeError("AI response could not be parsed as valid JSON")

    def _history_snapshot(self, limit: int = 5) -> List[Dict[str, object]]:
        return self.history[-limit:]

    def _vulnerability_snapshot(self, limit: int = 10) -> List[Dict[str, object]]:
        snapshot = []
        for vuln in self.vulnerabilities[-limit:]:
            snapshot.append({
                "type": vuln.vuln_type,
                "severity": vuln.severity,
                "target": vuln.target,
                "confidence": vuln.confidence,
            })
        return snapshot

    def _extract_session_info(self, command: str, stdout: str, stderr: str) -> None:
        """Extract session cookies and authentication info from responses"""
        # Extract session cookies from Set-Cookie headers
        if "set-cookie:" in stdout.lower():
            import re
            cookie_matches = re.findall(r'set-cookie:\s*([^=]+)=([^;]+)', stdout, re.IGNORECASE)
            for name, value in cookie_matches:
                self.session_cookies[name.strip()] = value.strip()

        # Look for redirect to admin areas
        if "location:" in stdout.lower() and "admin" in stdout.lower():
            self.authenticated = True

    def generate_report(self) -> str:
        """Generate final vulnerability report"""
        if not self.vulnerabilities:
            return "No vulnerabilities found during testing."

        critical = [v for v in self.vulnerabilities if v.severity == "critical"]
        high = [v for v in self.vulnerabilities if v.severity == "high"]
        medium = [v for v in self.vulnerabilities if v.severity == "medium"]
        low = [v for v in self.vulnerabilities if v.severity == "low"]

        report = f"""
🔍 PENETRATION TEST REPORT

📊 SUMMARY:
- Critical: {len(critical)}
- High: {len(high)}
- Medium: {len(medium)}
- Low: {len(low)}
- Total: {len(self.vulnerabilities)}

🚨 CRITICAL VULNERABILITIES:
"""

        for vuln in critical:
            report += f"""
- {vuln.vuln_type.upper()}
  Target: {vuln.target}
  Evidence: {vuln.evidence[:100]}...
  Payload: {vuln.payload}
  Confidence: {vuln.confidence:.1%}
"""

        if high:
            report += "\n⚠️  HIGH SEVERITY VULNERABILITIES:\n"
            for vuln in high:
                report += f"- {vuln.vuln_type} at {vuln.target}\n"

        return report
