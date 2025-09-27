from __future__ import annotations

import asyncio
import re
import shlex
import time
from typing import AsyncGenerator, Dict, List, Optional, Tuple
from urllib.parse import quote

from .core import (
    EvidenceStore,
    ExecutionService,
    GoalManager,
    MemoryManager,
    PlannerService,
    ReportService,
    SafetyManager,
    SessionRepository,
    ToolRegistry,
    default_registry,
)
from .models import Action, AgentSession, Insight, Todo, now_iso
from .sandbox import CommandBlocked
from .utils import ensure_dirs


class AutonomousOrchestrator:
    def __init__(
        self,
        gemini_api_key: Optional[str] = None,
        model_provider: Optional[str] = None,
        approval_mode: Optional[str] = None,
    ) -> None:
        ensure_dirs()
        self._gemini_api_key = gemini_api_key  # Reserved for future provider-specific hooks
        self.goal_manager = GoalManager(model_provider)
        self.planner_service = PlannerService(self.goal_manager.model)
        self.execution_service = ExecutionService()
        self.evidence_store = EvidenceStore()
        self.safety_manager = SafetyManager()
        if approval_mode:
            self.safety_manager.set_mode(approval_mode)
        self.report_service = ReportService(self.goal_manager)
        self.session_repo = SessionRepository()
        self.memory_manager: Optional[MemoryManager] = None
        self.tool_registry: ToolRegistry = default_registry()

        self.session: Optional[AgentSession] = None
        self.interactive_session_manager = None
        self.max_loops = 20
        self.max_errors = 15
        self.think_delay = 0.1
        self._stop = False

    # ------------------------------------------------------------------
    # Provider info -----------------------------------------------------
    # ------------------------------------------------------------------
    def switch_provider(self, provider_name: str) -> bool:
        changed = self.goal_manager.switch_provider(provider_name)
        if changed:
            self.planner_service.update_provider(self.goal_manager.model)
        return changed

    def get_provider_info(self) -> Dict:
        return self.goal_manager.get_provider_info()

    # ------------------------------------------------------------------
    # Session lifecycle -------------------------------------------------
    # ------------------------------------------------------------------
    def create_session(self, objective: str, target: Optional[str]) -> str:
        self.session = self.evidence_store.create_session(objective, target)
        self.execution_service.bind_session(self.session.id)
        self.memory_manager = MemoryManager(self.session)
        # Maintain compatibility with existing code paths expecting sandbox attr
        self.sandbox = self.execution_service.sandbox
        self._persist_session()
        return self.session.id

    async def start_autonomous_loop(self) -> AsyncGenerator[Dict, None]:
        if not self.session:
            raise RuntimeError("No session. Call create_session first.")

        # Phase 1: Think
        self.session.state = "thinking"
        analysis = await self._think_phase()
        yield self._update("thinking", analysis, {"analysis": analysis})
        await asyncio.sleep(self.think_delay)

        # Phase 1b: Plan
        self.session.state = "planning"
        plan = await self._plan_phase()
        planning_msg = self.session.plan_text or "Generated initial plan"
        plan_payload = self.session.plan_struct or {
            "plan_summary": self.session.plan_text,
            "steps": [
                {
                    "description": t.get("description", ""),
                    "command": t.get("command", ""),
                    "status": t.get("status", "pending"),
                }
                for t in plan
            ],
        }
        yield self._update("planning", planning_msg, {"plan": plan_payload, "todos": plan})

        # Phase 2: Action loop
        while True:
            if not self.session:
                break
            if self._stop:
                self.session.state = "completed"
                yield self._update("completed", "Stopped by user")
                self._stop = False
                break
            if self.session.error_count >= self.max_errors:
                self.session.state = "error"
                yield self._update("error", "Too many errors; aborting")
                break

            self.session.state = "reflecting"
            micro = await self._ai_micro_analysis()
            yield self._update("analysis", micro, {"analysis": micro})

            ai_decision = await self._ai_reflection_phase()
            if "askUser" in ai_decision:
                message = ai_decision.get("askUser", "") or "AI requested user input"
                self.session.state = "completed"
                yield self._update("completed", message)
                break

            action_type = ai_decision.get("action")
            if action_type in {"exit_assessment", "break"}:
                self.session.state = "completed"
                final_report = self._generate_final_report()
                if action_type == "break":
                    yield self._update("completed", f"4myPown: Task completed. {final_report}")
                else:
                    yield self._update("completed", f"4myPown: {final_report}")
                break

            if self.max_loops >= 0 and self.session.loop_count >= self.max_loops:
                self.session.state = "completed"
                final_report = self._generate_final_report()
                yield self._update(
                    "completed",
                    f"4myPown: {final_report} [Emergency exit: max loops reached]",
                )
                break

            if action_type == "execute":
                insight_msg = ""
                if self.session.insights and self.session.insights[-1].tags == ["ai_insight"]:
                    insight_msg = self.session.insights[-1].content

                decision_msg = f"Decision: execute {ai_decision.get('command', '')}".strip()
                if ai_decision.get("reason"):
                    decision_msg += f" ({ai_decision['reason']})"

                full_msg = f"{insight_msg}\n> {decision_msg}" if insight_msg else f"> {decision_msg}"
                yield self._update("reflecting", full_msg, {"decision": ai_decision})

                self.session.state = "acting"
                act_msg, act_details = await self._execute_ai_command(ai_decision["command"])
                yield self._update("acting", act_msg, act_details)
            elif action_type in ["complete_todo", "update_todo", "add_todo"]:
                self._handle_todo_action(ai_decision)
                yield self._update("reflecting", f"Updated todos: {action_type}")

            self.session.loop_count += 1

    # ------------------------------------------------------------------
    # Phase helpers ----------------------------------------------------
    # ------------------------------------------------------------------
    async def _think_phase(self) -> str:
        assert self.session
        if self.goal_manager.model:
            prompt = self.goal_manager.build_think_prompt(self.session)
            try:
                ai_analysis = self.goal_manager.model.generate(prompt)
                content = f"● AI Analysis:\n{ai_analysis}"
            except Exception as exc:
                content = (
                    f"● Analysis: {self.session.objective}\n"
                    f"● Note: AI analysis failed ({exc}), using basic reasoning."
                )
        else:
            content = (
                f"● Analysis: {self.session.objective}\n"
                "● Approach: Focus on defensive recon, gather evidence, and avoid destructive actions."
            )

        self.session.insights.append(Insight(content=content, tags=["think"], timestamp=now_iso()))
        self.session.touch()
        self._persist_session()
        return content

    async def _plan_phase(self):
        assert self.session
        raw_tasks = self.planner_service.generate_plan(
            self.session,
            base_prompt=self.goal_manager.build_prompt_header(),
        )

        self.session.plan_text = self.planner_service.plan_text
        self.session.plan_struct = self.planner_service.plan_struct

        for task in raw_tasks:
            task["command"] = self._personalize_command(task.get("command", ""))

        from .core.plan import StrategicPlan  # Local import to avoid cycles at module load

        strategic_plan = StrategicPlan.from_todo_payload(
            self.session.plan_text or "",
            raw_tasks,
        )
        self.session.plan_struct["strategic_plan"] = {
            "summary": strategic_plan.summary,
            "steps": [
                {
                    "description": step.description,
                    "command": step.command,
                    "status": step.status,
                    "priority": step.priority,
                    "context": step.context,
                }
                for step in strategic_plan.steps
            ],
        }

        todos = [Todo(**task) for task in raw_tasks]
        existing_desc = {t.description for t in self.session.todos}
        for todo in todos:
            if todo.description not in existing_desc:
                self.session.todos.append(todo)
        self.session.touch()
        self._persist_session()

        todos_dict: List[Dict] = []
        for todo in self.session.todos:
            todos_dict.append(
                {
                    "id": getattr(todo, "id", ""),
                    "description": getattr(todo, "description", ""),
                    "command": getattr(todo, "command", ""),
                    "priority": getattr(todo, "priority", "medium"),
                    "status": getattr(todo, "status", "pending"),
                    "context": getattr(todo, "context", {}),
                }
            )
        return todos_dict

    async def _execute_ai_command(self, command: str) -> Tuple[str, Dict]:
        adapter = self.tool_registry.find(command)
        policy_decision, needs_confirmation = self.safety_manager.evaluate(command)
        if self.safety_manager.is_denied(policy_decision):
            raise CommandBlocked(policy_decision.reason)
        if needs_confirmation:
            approved = self._request_user_confirmation(command, policy_decision.reason)
            if not approved:
                assert self.session
                action = Action(
                    id=f"act-{self.session.loop_count}",
                    command=command,
                    started_at=now_iso(),
                    status="failed",
                    exit_code=3,
                    stdout="",
                    stderr="",
                    duration=0.0,
                    observations=[f"Command rejected: {policy_decision.reason}"],
                    summary="Command rejected by operator",
                )
                self.session.actions.append(action)
                self.session.touch()
                self._persist_session()
                return (
                    f"Rejected: {command}",
                    {
                        "rc": 3,
                        "action_id": action.id,
                        "stdout": "",
                        "stderr": "",
                        "summary": action.summary,
                        "observations": action.observations,
                        "duration": 0.0,
                    },
                )
            warnings.append(f"Approved manually: {policy_decision.reason}")

        prepared_cmd, warnings = self._prepare_command(command, adapter, policy_decision)
        if prepared_cmd is None:
            assert self.session
            action = Action(
                id=f"act-{self.session.loop_count}",
                command=command,
                started_at=now_iso(),
                status="failed",
                exit_code=3,
                stdout="",
                stderr="",
                duration=0.0,
                observations=warnings,
                summary=warnings[0] if warnings else "command skipped",
            )
            self.session.actions.append(action)
            self.session.error_count += 1
            self.session.touch()
            display_cmd = command if len(command) <= 120 else f"{command[:117]}..."
            return f"Skipped: {display_cmd}", {
                "rc": 3,
                "action_id": action.id,
                "stdout": "",
                "stderr": "",
                "summary": action.summary,
                "observations": action.observations,
                "duration": 0.0,
            }

        assert self.session
        action = Action(
            id=f"act-{self.session.loop_count}",
            command=prepared_cmd,
            started_at=now_iso(),
        )
        self.session.actions.append(action)

        rc, full_stdout, full_stderr, preview_stdout, preview_stderr, duration = await self._capture_command_output(
            prepared_cmd,
            action.id,
        )
        action.exit_code = rc
        action.ended_at = now_iso()
        action.status = "completed" if rc == 0 else "failed"
        action.stdout = "\n".join(full_stdout)
        action.stderr = "\n".join(full_stderr)
        action.duration = duration
        action.observations, action.summary = self._analyze_action(action, preview_stdout, preview_stderr, warnings)

        if self.memory_manager:
            snippet = preview_stdout if preview_stdout else full_stdout[:3]
            self.memory_manager.record_action(action, snippet)
            if adapter:
                findings = adapter.parse(action)
                self.memory_manager.record_findings(findings)

        streak = 0
        for past in reversed(self.session.actions):
            if past.command == prepared_cmd:
                streak += 1
            else:
                break
        if streak > 1:
            repeat_obs = (
                "Command repeated {streak} times consecutively; gather new evidence before reusing it."
            )
            repeat_obs = repeat_obs.format(streak=streak)
            if repeat_obs not in action.observations:
                action.observations.append(repeat_obs)
                action.summary = action.summary or repeat_obs

        if rc != 0:
            self.session.error_count += 1
            todo_status = "failed"
        else:
            self.session.error_count = 0
            todo_status = "completed"

        # Update todo statuses
        for todo in self.session.todos:
            if todo.command == command or todo.command == prepared_cmd:
                todo.status = todo_status

        self.session.touch()
        self._persist_session()
        display_cmd = prepared_cmd if len(prepared_cmd) <= 120 else f"{prepared_cmd[:117]}..."
        details = {
            "rc": rc,
            "action_id": action.id,
            "stdout": "\n".join(preview_stdout),
            "stderr": "\n".join(preview_stderr),
            "summary": action.summary,
            "observations": action.observations,
            "duration": round(duration, 2),
        }
        return f"Executed: {display_cmd} (rc={rc})", details

    async def _ai_micro_analysis(self) -> str:
        assert self.session
        recent_actions = self.session.actions[-5:]
        lines: List[str] = []
        for act in recent_actions:
            summary = act.summary or ""
            lines.append(f"- {act.command} → rc={act.exit_code} :: {summary}".strip())
        recent_summary = "\n".join(lines) or "- (no prior actions)"
        todo_stats = {
            "pending": sum(1 for t in self.session.todos if t.status == "pending"),
            "completed": sum(1 for t in self.session.todos if t.status == "completed"),
            "failed": sum(1 for t in self.session.todos if t.status == "failed"),
        }
        findings_summary = (
            self.memory_manager.summarize_recent_findings()
            if self.memory_manager
            else "(memory manager inactive)"
        )
        prompt = self.goal_manager.build_analysis_prompt(
            self.session,
            self.session.plan_text or "(no plan recorded)",
            recent_summary,
            todo_stats,
            findings_summary,
        )
        analysis = ""
        if self.goal_manager.model:
            try:
                analysis = (self.goal_manager.model.generate(prompt) or "").strip()
            except Exception:
                analysis = ""

        raw_lines = [line.strip() for line in analysis.splitlines() if line.strip()]
        if len(raw_lines) < 4:
            raw_lines = [
                "1. Minimal evidence so far; continue with safe recon.",
                "2. Outputs show limited confirmation; expand probe surface.",
                "3. Hypothesis: login needs POST-focused SQL testing.",
                "4. Next: prioritize sqlmap --method=POST --data with low risk flags.",
            ]
        if len(raw_lines) > 7:
            raw_lines = raw_lines[:7]
        analysis_text = "\n".join(raw_lines)

        self.session.insights.append(Insight(content=analysis_text, tags=["analysis"], timestamp=now_iso()))
        self.session.touch()
        self._persist_session()
        return analysis_text

    async def _ai_reflection_phase(self) -> Dict:
        assert self.session
        if not self.goal_manager.model:
            pending_todo = next((t for t in self.session.todos if t.status == "pending"), None)
            if pending_todo:
                return {"action": "execute", "command": pending_todo.command}
            return {"action": "exit_assessment", "reason": "No more tasks"}

        todos_context = ""
        for index, todo in enumerate(self.session.todos, 1):
            todos_context += f"{index}. [{todo.status}] {todo.description}\n   Command: {todo.command}\n"
            if getattr(todo, "context", None):
                todos_context += f"   Context: {dict(todo.context)}\n"

        recent_actions = self.session.actions[-5:]
        actions_context = ""
        for idx, action in enumerate(recent_actions, 1):
            actions_context += f"\nAction {idx}: {action.command}\n"
            actions_context += (
                f"Status: {action.status} (exit code: {action.exit_code}) duration={action.duration:.2f}s\n"
            )
            if action.summary:
                actions_context += f"Summary: {action.summary}\n"
            if action.observations:
                for obs in action.observations[:3]:
                    actions_context += f" - {obs}\n"
            if action.stdout:
                stdout_lines = action.stdout.split("\n")
                snippet = stdout_lines[:2]
                if len(stdout_lines) > 5:
                    snippet += ["..."] + stdout_lines[-2:]
                if snippet:
                    actions_context += "Stdout snippet:\n"
                    for line in snippet:
                        actions_context += f"   {line}\n"
            if action.stderr:
                stderr_lines = action.stderr.split("\n")
                snippet = stderr_lines[:2]
                if len(stderr_lines) > 5:
                    snippet += ["..."] + stderr_lines[-2:]
                if snippet:
                    actions_context += "Stderr snippet:\n"
                    for line in snippet:
                        actions_context += f"   {line}\n"
        if len(self.session.actions) > len(recent_actions):
            actions_context += "\n(Additional actions omitted for brevity.)\n"

        repeat_note = ""
        if self.session.actions:
            last_cmd = self.session.actions[-1].command
            streak = 0
            for action in reversed(self.session.actions):
                if action.command == last_cmd:
                    streak += 1
                else:
                    break
            if streak > 1:
                repeat_note = (
                    f"Last command `{last_cmd}` executed {streak} times consecutively; switch tools or adjust parameters before repeating."
                )

        analyst = ""
        for insight in reversed(self.session.insights):
            if "analysis" in insight.tags:
                analyst = insight.content
                break

        prompt = self.goal_manager.build_reflection_prompt(
            self.session,
            self.session.plan_text or "",
            todos_context,
            actions_context,
            analyst,
            self.session.loop_count,
            len([a for a in self.session.actions if a.status == "completed"]),
            len([a for a in self.session.actions if a.status == "failed"]),
            self.session.error_count,
            repeat_note,
        )

        decision_raw = self.goal_manager.model.generate(prompt) or ""
        cleaned = decision_raw.strip()
        if "```" in cleaned:
            cleaned = re.sub(r"```[a-zA-Z0-9]*\n?", "", cleaned)
            cleaned = re.sub(r"\n```", "", cleaned)
        json_candidates = [line.strip() for line in cleaned.splitlines() if line.strip().startswith("{")]
        payload = json_candidates[0] if json_candidates else cleaned
        try:
            import json

            parsed = json.loads(payload)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
        return {"action": "exit_assessment", "reason": "Failed to parse AI decision"}

    def _update(self, phase: str, message: str, details: Optional[Dict] = None) -> Dict:
        assert self.session
        return {
            "phase": phase,
            "message": message,
            "details": details or {},
            "session_state": {
                "id": self.session.id,
                "loop_count": self.session.loop_count,
                "state": self.session.state,
            },
        }

    def _generate_final_report(self) -> str:
        assert self.session
        if not self.goal_manager.model:
            return self._generate_fallback_report()

        commands_section = "COMPLETE COMMAND EXECUTION MATRIX:\n"
        for i, action in enumerate(self.session.actions, 1):
            commands_section += f"\n{'='*60}\n"
            commands_section += f"Command {i}: {action.command}\n"
            commands_section += (
                f"Status: {action.status} | Exit Code: {action.exit_code} | Duration: {action.duration:.2f}s\n"
            )
            if action.stdout:
                commands_section += f"\nSTDOUT:\n{action.stdout}\n"
            if action.stderr:
                commands_section += f"\nSTDERR:\n{action.stderr}\n"
            if action.observations:
                commands_section += "\nOBSERVATIONS:\n"
                for obs in action.observations:
                    commands_section += f"- {obs}\n"
            if action.summary:
                commands_section += f"\nSUMMARY: {action.summary}\n"

        insights_section = ""
        if self.session.insights:
            insights_section = (
                f"\nCOMPLETE AI ANALYSIS HISTORY ({len(self.session.insights)} insights):\n"
            )
            for idx, insight in enumerate(self.session.insights, 1):
                insights_section += (
                    f"\nInsight {idx} ({', '.join(insight.tags)}) - {insight.timestamp}:\n{insight.content}\n"
                )

        todos_section = f"\nCOMPLETE TODO MATRIX ({len(self.session.todos)} tasks):\n"
        for index, todo in enumerate(self.session.todos, 1):
            todos_section += f"{index}. [{todo.status}] {todo.description}\n"
            todos_section += f"   Command: {todo.command}\n"
            if getattr(todo, "context", None):
                todos_section += f"   Context: {todo.context}\n"

        prompt = self.report_service.build_report_prompt(
            self.session,
            commands_section,
            insights_section,
            todos_section,
        )

        try:
            ai_report = self.goal_manager.model.generate(prompt)
            if not isinstance(ai_report, str):
                ai_report = str(ai_report)
            report_text = self._clean_report_response(ai_report)
            self.session.final_report = report_text
            self._persist_session()
            self._export_reports()
            return report_text
        except Exception as exc:
            fallback = self._generate_fallback_report()
            report_text = f"<report>AI report generation failed: {exc}\n\n{fallback}</report>"
            self.session.final_report = report_text
            self._persist_session()
            self._export_reports()
            return report_text

    async def _capture_command_output(
        self,
        command: str,
        action_id: str,
    ) -> Tuple[int, List[str], List[str], List[str], List[str], float]:
        full_stdout: List[str] = []
        full_stderr: List[str] = []
        preview_stdout: List[str] = []
        preview_stderr: List[str] = []
        max_preview = 20
        rc: int = -1
        start = time.monotonic()
        try:
            async for evt in self.execution_service.execute_stream(command, action_id=action_id):
                if evt.get("type") == "output":
                    line = evt.get("line", "")
                    stream = evt.get("stream", "stdout")
                    if stream == "stderr":
                        full_stderr.append(line)
                        if len(preview_stderr) < max_preview:
                            preview_stderr.append(line)
                    else:
                        full_stdout.append(line)
                        if len(preview_stdout) < max_preview:
                            preview_stdout.append(line)
                elif evt.get("type") == "complete":
                    rc = int(evt.get("rc", -1))
        except CommandBlocked as exc:
            msg = f"[blocked] {exc}"
            full_stderr.append(msg)
            if len(preview_stderr) < max_preview:
                preview_stderr.append(msg)
            rc = 3
        except Exception as exc:
            msg = f"[error] {exc}"
            full_stderr.append(msg)
            if len(preview_stderr) < max_preview:
                preview_stderr.append(msg)
            rc = 3
        if not preview_stdout and full_stdout:
            preview_stdout = full_stdout[:max_preview]
        if not preview_stderr and full_stderr:
            preview_stderr = full_stderr[:max_preview]
        duration = time.monotonic() - start
        return rc, full_stdout, full_stderr, preview_stdout, preview_stderr, duration

    def _analyze_action(
        self,
        action: Action,
        preview_stdout: List[str],
        preview_stderr: List[str],
        initial_notes: Optional[List[str]] = None,
    ) -> Tuple[List[str], str]:
        observations: List[str] = []
        extra_notes = list(initial_notes or [])

        if action.exit_code is not None and action.exit_code != 0:
            observations.append(f"Command exited with code {action.exit_code}")
        if action.exit_code == 0 and not (preview_stdout or preview_stderr):
            observations.append("Command produced no visible output")

        for note in extra_notes:
            if note and note not in observations:
                observations.append(note)

        summary = observations[0] if observations else "Command executed"
        return observations, summary

    def _prepare_command(self, command: str) -> Tuple[Optional[str], List[str]]:
        warnings: List[str] = []
        adapter = self.tool_registry.find(command)
    def _prepare_command(self, command: str, adapter=None, policy_decision=None) -> Tuple[Optional[str], List[str]]:
        warnings: List[str] = []
        if policy_decision and policy_decision.action == "review":
            warnings.append(f"Policy review: {policy_decision.reason}")
        if adapter is None:
            adapter = self.tool_registry.find(command)

        if adapter and self.session:
            cmd, adapter_warnings = adapter.prepare(command, self.session)
            warnings.extend(adapter_warnings)
        else:
            cmd = command.strip()

        if not cmd:
            return None, ["Empty command provided; skipping execution."]

        if re.search(r"<[\w:-]+>", cmd):
            return None, ["Command contains unresolved placeholder tokens; skipping execution."]

        if cmd.lower().startswith("manually"):
            return None, ["Manual task noted; requires human execution outside sandbox."]

        if cmd.startswith("sqlmap ") and not adapter:
            cmd, sqlmap_notes = self._sanitize_sqlmap_command(cmd)
            warnings.extend(sqlmap_notes)

        try:
            shlex.split(cmd, posix=True)
        except ValueError as exc:
            if cmd.startswith("sqlmap ") and "--data=" in cmd:
                cmd, repaired_note = self._repair_sqlmap_data(cmd)
                if repaired_note:
                    warnings.append(repaired_note)
                try:
                    shlex.split(cmd, posix=True)
                except ValueError as exc2:
                    warnings.append(f"Unable to repair sqlmap --data payload ({exc2}).")
                    return None, warnings
            else:
                warnings.append(f"Command has quoting issues ({exc}).")
                return None, warnings

        return cmd, warnings

    def _sanitize_sqlmap_command(self, cmd: str) -> Tuple[str, List[str]]:
        notes: List[str] = []
        if " --batch" not in cmd:
            cmd += " --batch"
            notes.append("Added --batch to sqlmap command for non-interactive execution.")
        return cmd, notes

    def _repair_sqlmap_data(self, cmd: str) -> Tuple[str, Optional[str]]:
        if "--data=" not in cmd:
            return cmd, None

        data_index = cmd.find("--data=")
        prefix = cmd[:data_index]
        rest = cmd[data_index + len("--data="):]

        match = re.search(r"\s-", rest)
        if match:
            data_section = rest[:match.start()].strip()
            suffix = rest[match.start():]
        else:
            data_section = rest.strip()
            suffix = ""

        if not data_section:
            return cmd, None

        if data_section[0] in {'"', "'"}:
            quote_char = data_section[0]
            if data_section.endswith(quote_char):
                data_section = data_section[1:-1]
            else:
                data_section = data_section[1:]

        sanitized = quote(data_section, safe="=&%")
        if suffix and not suffix.startswith(" "):
            suffix = " " + suffix
        rebuilt = f"{prefix}--data='{sanitized}'{suffix}"
        return rebuilt, "Normalized sqlmap --data payload for safe execution."

    def _handle_todo_action(self, ai_decision: Dict):
        assert self.session
        action_type = ai_decision["action"]
        if action_type == "complete_todo":
            todo_desc = ai_decision.get("todo_description", "")
            for todo in self.session.todos:
                if todo_desc in todo.description:
                    todo.status = "completed"
                    break
        elif action_type == "update_todo":
            description_data = ai_decision.get("description", {})
            if isinstance(description_data, dict):
                old_desc = description_data.get("description", "")
                new_desc = description_data.get("new_description", "")
            else:
                old_desc = str(description_data)
                new_desc = ai_decision.get("new_description", "")
            for todo in self.session.todos:
                if old_desc and old_desc in todo.description:
                    todo.description = new_desc
                    break
        elif action_type == "add_todo":
            new_todo = Todo(
                id=f"ai-todo-{len(self.session.todos)+1}",
                description=ai_decision.get("description", ""),
                command=ai_decision.get("command", ""),
                priority="medium",
                status="pending",
            )
            self.session.todos.append(new_todo)
        self.session.touch()
        self._persist_session()

    def _personalize_command(self, cmd: str) -> str:
        if not self.session or not self.session.target:
            return cmd
        target = str(self.session.target)
        if cmd.startswith("zap-scan "):
            return f"zap-scan {target}"
        if cmd.startswith("nmap ") and target.startswith("http"):
            try:
                from urllib.parse import urlparse

                host = urlparse(target).hostname or target
            except Exception:
                host = target
            return cmd.replace("example.com", host)
        return cmd.replace("example.com", target)

    def _generate_fallback_report(self) -> str:
        assert self.session
        lines = ["PENETRATION TESTING SESSION REPORT"]
        lines.append(f"Objective: {self.session.objective}")
        lines.append(f"Target: {self.session.target or 'Not specified'}")
        lines.append(f"Commands executed: {len(self.session.actions)}")
        if self.session.actions:
            lines.append("\nExecuted Commands:")
            for action in self.session.actions:
                status_symbol = "✓" if action.status == "completed" else "✗"
                lines.append(
                    f"  {status_symbol} {action.command} (exit code: {action.exit_code})"
                )
        lines.append(f"\nSession completed with {self.session.loop_count} analysis loops.")
        return "\n".join(lines)

    def _clean_report_response(self, ai_response: str) -> str:
        cleaned = ai_response.strip()
        if "```" in cleaned:
            import re

            cleaned = re.sub(r"```[a-zA-Z]*\n?", "", cleaned)
            cleaned = re.sub(r"\n```", "", cleaned)
        try:
            import json

            parsed = json.loads(cleaned)
            if isinstance(parsed, dict) and "report" in parsed:
                report_content = parsed["report"]
                if not isinstance(report_content, str):
                    report_content = str(report_content)
                if not report_content.strip().startswith("<report>"):
                    report_content = f"<report>\n{report_content}\n</report>"
                elif not report_content.strip().endswith("</report>"):
                    report_content = f"{report_content}\n</report>"
                return report_content
        except (json.JSONDecodeError, KeyError, TypeError):
            pass
        if not cleaned.startswith("<report>"):
            cleaned = f"<report>\n{cleaned}\n</report>"
        elif not cleaned.endswith("</report>"):
            cleaned = f"{cleaned}\n</report>"
        return cleaned

    # ------------------------------------------------------------------
    # Control -----------------------------------------------------------
    # ------------------------------------------------------------------
    def stop(self) -> None:
        self._stop = True

    def _persist_session(self) -> None:
        if self.session:
            self.session_repo.save(self.session)

    def _request_user_confirmation(self, command: str, reason: str) -> bool:
        prompt = (
            f"Command requires approval\n"
            f"  Command: {command}\n"
            f"  Reason: {reason}\n"
            "Approve? [y/N]: "
        )
        try:
            response = input(prompt).strip().lower()
        except (EOFError, KeyboardInterrupt):
            return False
        return response in {"y", "yes"}

    def _export_reports(self) -> None:
        if not self.session:
            return
        session_dir = SESSIONS_DIR / self.session.id
        session_dir.mkdir(parents=True, exist_ok=True)
        markdown_path = session_dir / "report.md"
        json_path = session_dir / "report.json"
        self.report_service.save_markdown(self.session, markdown_path)
        self.report_service.save_json(self.session, json_path)


_orch_singleton: Optional[AutonomousOrchestrator] = None


def init_orchestrator(provider: Optional[str] = None, approval_mode: Optional[str] = None) -> AutonomousOrchestrator:
    global _orch_singleton
    _orch_singleton = AutonomousOrchestrator(model_provider=provider, approval_mode=approval_mode)
    return _orch_singleton


def get_orchestrator() -> AutonomousOrchestrator:
    return _orch_singleton or init_orchestrator()
