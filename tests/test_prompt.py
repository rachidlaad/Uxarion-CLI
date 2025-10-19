# SPDX-License-Identifier: Apache-2.0
import io
import os
import tempfile
import unittest
from unittest import mock

import importlib.util
import sys
from pathlib import Path


def _load_cli_module():
    root = Path(__file__).resolve().parents[1]
    module_path = root / "zevionx_cli.py"
    spec = importlib.util.spec_from_file_location("zevionx_cli_cli", module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)  # type: ignore[assignment]
    return module


zevionx_cli = _load_cli_module()


FORBIDDEN_TERMS = ("provider", "timeout", "budget", "verbosity", "log")


class DecisionPromptTests(unittest.TestCase):
    def test_decision_prompt_excludes_internal_terms(self) -> None:
        prompt_lower = zevionx_cli.DECISION_PROMPT.lower()
        for term in FORBIDDEN_TERMS:
            self.assertNotIn(term, prompt_lower)


class PlannerRuntimeTests(unittest.TestCase):
    def test_request_decision_payload_clean(self) -> None:
        policy = zevionx_cli.Policy()
        agent = zevionx_cli.Agent(policy=policy, provider="gemini")

        captured = {}

        def fake_chat_json(prompt: str, payload: dict, provider: str):
            captured["prompt"] = prompt
            captured["payload"] = payload
            captured["provider"] = provider
            return {"stop": True, "reason": "noop"}

        with mock.patch.object(zevionx_cli, "chat_json", side_effect=fake_chat_json):
            agent._request_decision_freeform("scan http://example.com", "http://example.com")

        self.assertEqual(captured["payload"], {})
        prompt_lower = captured["prompt"].lower()
        for term in FORBIDDEN_TERMS:
            self.assertNotIn(term, prompt_lower)

    def test_run_uses_minimal_prompt_sections(self) -> None:
        policy = zevionx_cli.Policy(dry_run=True)
        agent = zevionx_cli.Agent(policy=policy, provider="gemini")

        user_text = "test this for sql on http://localhost:8080"

        align_response = {
            "intent_paragraph": "Test target for SQL injection",
            "derived_targets": ["http://localhost:8080"],
            "assumptions": [],
        }
        first_decision = {
            "stop": False,
            "reason": "quick SQLi probe",
            "command": "sqlmap -u http://localhost/ --batch",
        }
        second_decision = {"stop": True, "reason": "done"}
        responses = [align_response, first_decision, second_decision]
        default_response = second_decision
        captured_prompts = []

        def fake_chat_json(prompt: str, payload: dict, provider: str):
            captured_prompts.append((prompt, payload))
            return responses.pop(0) if responses else default_response

        with tempfile.TemporaryDirectory() as tmp_dir:
            cwd = os.getcwd()
            os.chdir(tmp_dir)
            try:
                with mock.patch.object(zevionx_cli, "chat_json", side_effect=fake_chat_json), mock.patch.object(
                    zevionx_cli, "chat_text", return_value="Test report"
                ):
                    buf = io.StringIO()
                    original_stdout = sys.stdout
                    sys.stdout = buf
                    try:
                        agent.run(user_text, max_commands=2)
                    finally:
                        sys.stdout = original_stdout
                    output_text = buf.getvalue()
            finally:
                os.chdir(cwd)

        # ensure align call + two planner calls captured
        self.assertGreaterEqual(len(captured_prompts), 3)
        # First planner prompt (second overall) should include minimal sections
        decision_prompt, payload = captured_prompts[1]
        self.assertEqual(payload, {})
        self.assertIn("User_intent:\n" + user_text.strip(), decision_prompt)
        self.assertIn("Target_hints", decision_prompt)
        self.assertIn("Recent_activity", decision_prompt)
        prompt_lower = decision_prompt.lower()
        for term in FORBIDDEN_TERMS:
            self.assertNotIn(term, prompt_lower)

        # After dry-run execution, next planner prompt contains history excerpt with the command
        follow_up_prompt, _ = captured_prompts[2]
        self.assertIn("Recent_activity", follow_up_prompt)
        self.assertIn("sqlmap -u http://localhost/ --batch", follow_up_prompt)
        self.assertIn("thinking:", output_text)
        self.assertIn(
            "→ sqlmap -u http://localhost/ --batch",
            output_text,
        )

    def test_duplicate_feedback(self) -> None:
        policy = zevionx_cli.Policy(dry_run=True)
        agent = zevionx_cli.Agent(policy=policy, provider="gemini")

        align_response = {
            "intent_paragraph": "Recon the target",
            "derived_targets": ["http://x"],
            "assumptions": [],
        }
        decisions = [
            align_response,
            {"stop": False, "reason": "do A", "command": "curl -i http://x"},
            {"stop": False, "reason": "repeat", "command": "curl -i http://x"},
            {"stop": True, "reason": "done"},
        ]

        def fake_chat_json(prompt: str, payload: dict, provider: str):
            return decisions.pop(0)

        with tempfile.TemporaryDirectory() as tmp_dir:
            cwd = os.getcwd()
            os.chdir(tmp_dir)
            try:
                with mock.patch.object(zevionx_cli, "chat_json", side_effect=fake_chat_json), mock.patch.object(
                    zevionx_cli, "chat_text", return_value="Test report"
                ):
                    buf = io.StringIO()
                    original_stdout = sys.stdout
                    sys.stdout = buf
                    try:
                        agent.run("scan http://x", max_commands=2)
                    finally:
                        sys.stdout = original_stdout
                    output_text = buf.getvalue()
            finally:
                os.chdir(cwd)

        self.assertIn("thinking: trying alternative (duplicate)", output_text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
