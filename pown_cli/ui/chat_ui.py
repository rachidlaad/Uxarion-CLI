"""
Interactive terminal chat UI for 4myPown
Enhanced with code execution, conversation context, and streaming responses.
"""
import asyncio
import sys
import os
import subprocess
import json
import time
from datetime import datetime
from importlib import metadata
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import getpass

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.prompt import Prompt
    from rich.syntax import Syntax
    from rich.live import Live
    from rich.markdown import Markdown
    from rich import box
    from rich.align import Align
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

PROMPT_TOOLKIT_AVAILABLE = False

from ..core.orchestrator import init_orchestrator

try:  # Stay aligned with single-shot default provider
    from .. import pown_cli as legacy_agent  # type: ignore

    CHAT_DEFAULT_PROVIDER = getattr(legacy_agent, "DEFAULT_PROVIDER", "openai")
except Exception:  # pragma: no cover - defensive
    CHAT_DEFAULT_PROVIDER = os.getenv("DEFAULT_PROVIDER", "openai")


class ConversationContext:
    """Maintains conversation history and context"""

    def __init__(self):
        self.messages: List[Dict[str, Any]] = []
        self.session_start = datetime.now()
        self.command_history: List[str] = []

    def add_user_message(self, content: str):
        """Add user message to context"""
        self.messages.append({
            "role": "user",
            "content": content,
            "timestamp": datetime.now().isoformat()
        })

    def add_assistant_message(self, content: str):
        """Add assistant response to context"""
        self.messages.append({
            "role": "assistant",
            "content": content,
            "timestamp": datetime.now().isoformat()
        })

    def add_command_execution(self, command: str, output: str, returncode: int):
        """Add command execution to context"""
        self.command_history.append(command)
        self.messages.append({
            "role": "system",
            "content": f"Command: {command}\nReturn code: {returncode}\nOutput:\n{output}",
            "timestamp": datetime.now().isoformat(),
            "type": "command_execution"
        })

    def get_recent_context(self, max_messages: int = 10) -> List[Dict[str, Any]]:
        """Get recent conversation context"""
        return self.messages[-max_messages:] if self.messages else []


class ChatUI:
    """Interactive terminal chat interface"""

    def __init__(self):
        if not RICH_AVAILABLE:
            print("Error: Rich library required. Run: pip install rich")
            sys.exit(1)

        self.console = Console()
        self.context = ConversationContext()
        self.current_directory = os.getcwd()
        self.version, self.build_label = self._resolve_build_metadata()

        # Settings
        self.target = "127.0.0.1"
        self.objective = "Security assessment"
        self.provider = os.getenv("DEFAULT_PROVIDER", CHAT_DEFAULT_PROVIDER)
        self.enable_advanced = False
        self.prompt_template = "[grey50]┆[/] [cyan]cmd[/] [grey50]›[/] "

    def _resolve_build_metadata(self) -> tuple[str, str]:
        """Return package version and build identifier."""
        try:
            version = metadata.version("4mypown-cli")
        except metadata.PackageNotFoundError:
            version = "dev"
        build = (
            os.environ.get("POWN_BUILD_ID")
            or os.environ.get("GIT_COMMIT")
            or os.environ.get("BUILD_ID")
            or "local"
        )
        return version, build

    def run(self):
        """Main interactive loop"""
        self._show_welcome()

        try:
            while True:
                user_input = self._get_user_input()

                if user_input.lower() in ["quit", "exit", "/quit"]:
                    self._show_goodbye()
                    break

                self._process_user_input(user_input)

        except KeyboardInterrupt:
            self.console.print("\n[yellow]👋 Session interrupted. Goodbye![/]")

    def _show_welcome(self):
        """Render the primary header with branding and mission info."""
        banner = Text(
            "██████╗   ██╗   ██╗███╗   ██╗\n"
            "██╔══██╗  ██║   ██║████╗  ██║\n"
            "██████╔╝  ██║   ██║██╔██╗ ██║\n"
            "██╔══██╗  ██║   ██║██║╚██╗██║\n"
            "██║  ██║  ╚██████╔╝██║ ╚████║\n"
            "╚═╝  ╚═╝   ╚═════╝ ╚═╝  ╚═══╝\n"
            "\n"
            "                 4myPown CLI\n",
            style="bold cyan",
        )

        builder = Text(
            "I would be happy for you to connect, collaborate, fix a bug or add a feature to the tool 😊",
            style="magenta",
        )

        contacts = Text(
            "X.com > @Rachid_LLLL    Gmail > rachidshade@gmail.com    GitHub > https://github.com/rachidlaad",
            style="bright_green",
        )

        mission = Text(
            "4myPawn is an AI pentesting copilot, open-source for the pentesting community.",
            style="bright_cyan",
        )

        self.console.print(banner)
        self.console.print(builder)
        self.console.print(contacts)
        self.console.print()
        self.console.print(mission)
        self.console.print()

    def _get_user_input(self) -> str:
        """Get user input with the chat-style prompt"""
        try:
            return self.console.input(f"\n{self.prompt_template}").strip()
        except EOFError:
            return "quit"

    def _process_user_input(self, user_input: str):
        """Process user input and generate responses"""
        if user_input == "/":
            self._open_quick_actions_menu()
            return

        self.context.add_user_message(user_input)

        # Handle special commands
        if user_input.startswith("/"):
            self._handle_command(user_input)
        else:
            # Regular chat interaction
            self._handle_chat_message(user_input)

    def _handle_command(self, command: str):
        """Handle special commands"""
        parts = command.split(" ", 1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        if cmd == "/":
            self._open_quick_actions_menu()
        elif cmd == "/help":
            self._show_help()
        elif cmd == "/settings":
            self._show_settings()
        elif cmd == "/exec":
            if args:
                self._execute_command(args)
            else:
                self.console.print("[red]Usage: /exec <command>[/]")
        elif cmd == "/pentest":
            self._start_pentest()
        elif cmd == "/context":
            self._show_context()
        elif cmd == "/clear":
            self._clear_screen()
        elif cmd == "/pwd":
            self._show_current_directory()
        elif cmd == "/ls":
            self._execute_command("ls -la")
        elif cmd == "/cd":
            if args:
                self._change_directory(args)
            else:
                self.console.print("[red]Usage: /cd <directory>[/]")
        else:
            self.console.print(f"[red]Unknown command: {cmd}[/]")
            self.console.print("[dim]Type /help for available commands[/]")

    def _handle_chat_message(self, message: str):
        """Treat free-form input as an objective and orchestrate an agent run."""
        cleaned = message.strip()
        if not cleaned:
            return
        self.console.print(f"\n[bright_white]→ Objective:[/] {cleaned}")
        try:
            report = asyncio.run(self._run_agent_session(cleaned))
            if report:
                self.console.print(
                    Panel(
                        report,
                        border_style="green",
                        title="🧾 Final Report",
                        padding=(1, 2),
                    )
                )
                self.context.add_assistant_message(report)
            else:
                self.context.add_assistant_message("Session completed without report output.")
        except KeyboardInterrupt:
            self.console.print("[yellow]⚠ Session interrupted by user[/]")
        except Exception as exc:
            self.console.print(f"[red]❌ Session failed: {exc}[/]")
            cause = exc.__cause__
            if cause and str(cause):
                self.console.print(f"[dim]Reason: {cause}[/dim]")
            self.context.add_assistant_message(f"Session error: {exc}")

    async def _run_agent_session(self, objective: str) -> Optional[str]:
        orchestrator = init_orchestrator(provider=self.provider)
        target = self._normalized_target()
        allow_tools = {"sqlmap", "nmap", "gobuster", "nikto"} if self.enable_advanced else None
        session_id = orchestrator.create_session(
            objective,
            target,
            allow_tools=allow_tools,
        )
        final_report: Optional[str] = None
        spinner_index = 0
        spinner_text = "Running..."
        gradient = ["#6d28d9", "#8b5cf6", "#a855f7", "#c084fc", "#a855f7", "#8b5cf6"]

        def render_spinner(idx: int) -> str:
            parts = []
            for pos, char in enumerate(spinner_text):
                offset = (pos - idx) % len(gradient)
                color = gradient[offset]
                parts.append(f"[{color}]{char}[/{color}]")
            return "".join(parts)

        async def spinner_task(stop_event: asyncio.Event, live: Live) -> None:
            nonlocal spinner_index
            while not stop_event.is_set():
                live.update(render_spinner(spinner_index))
                spinner_index = (spinner_index + 1) % len(spinner_text)
                await asyncio.sleep(0.16)

        with Live(console=self.console, transient=True, refresh_per_second=10) as live:
            stop_event = asyncio.Event()
            spinner_handle = asyncio.create_task(spinner_task(stop_event, live))
            spinner_stopped = False
            async for event in orchestrator.start_autonomous_loop():
                formatted, report_candidate = self._format_event_for_display(event)

                if event.get("type") == "observation":
                    obs = event.get("observation", {})
                    self.context.add_command_execution(
                        obs.get("command", ""),
                        obs.get("output", "") or "",
                        obs.get("returncode", 0),
                    )

                if report_candidate:
                    final_report = report_candidate

                if event.get("type") in {"completed", "error"} and not spinner_stopped:
                    stop_event.set()
                    await spinner_handle
                    spinner_stopped = True
                    live.update("")

                if formatted:
                    lines = formatted if isinstance(formatted, list) else [formatted]
                    for line in lines:
                        if isinstance(line, str) and line.strip():
                            self.console.print(line)

            if not spinner_stopped:
                stop_event.set()
                await spinner_handle
                live.update("")
        return final_report

    def _format_event_for_display(self, event: Dict[str, Any]) -> tuple[Optional[Any], Optional[str]]:
        etype = event.get("type")
        if etype == "status":
            return f"[grey62]{event.get('message', '')}[/]", None
        if etype == "intent":
            intent = event.get("intent", "")
            targets = ", ".join(event.get("derived_targets", []) or [])
            lines = [
                f"[bright_magenta]🎯 Intent:[/] {intent}",
            ]
            if targets:
                lines.append(f"[bright_magenta]🎯 Targets:[/] {targets}")
            return lines, None
        if etype == "decision":
            command = event.get("command", "")
            reason = event.get("reason", "")
            return [
                f"[bright_cyan]→ Command:[/] {command}",
                f"[grey58]   {reason}[/]" if reason else "",
            ], None
        if etype == "rejected":
            reason = event.get("reason", "")
            validator = event.get("validator", {})
            detail = validator.get("tool") or ""
            return [
                f"[red]✗ Rejected[/]: {event.get('command', '')}",
                f"[red]   Reason:[/] {reason}",
                f"[red]   Detail:[/] {detail}" if detail else "",
            ], None
        if etype == "observation":
            obs = event.get("observation", {})
            command = obs.get("command", "")
            rc = obs.get("returncode", "")
            duration_value = obs.get("duration")
            if isinstance(duration_value, (int, float)):
                duration = f"{duration_value:.2f}s"
            else:
                duration = str(duration_value) if duration_value not in (None, "") else ""
            snippet = (obs.get("output", "") or "").splitlines()
            display = snippet[0][:120] if snippet else ""
            lines = [
                f"[green]✓ Executed[/]: {command}",
                f"[grey58]   rc={rc} duration={duration}[/]" if duration else f"[grey58]   rc={rc}[/]",
            ]
            if display:
                lines.append(f"[grey62]   {display}[/]")
            if obs.get("evidence"):
                lines.append(f"[yellow]   Evidence:[/] {', '.join(obs['evidence'])}")
            return lines, None
        if etype == "report":
            return ["[magenta]📄 Final report generated[/]"], event.get("report")
        if etype == "completed":
            reason = event.get("result", {}).get("stop_reason") or event.get("stop_reason", "")
            return [f"[bright_white]Session completed[/] ({reason})"], None
        if etype == "error":
            return [f"[red]Error:[/] {event.get('error', 'unknown error')}"], None
        return None, None

    def _normalized_target(self) -> Optional[str]:
        if not self.target:
            return None
        if self.target.startswith(("http://", "https://")):
            parsed = urlparse(self.target)
            return parsed.hostname or self.target
        return self.target

    def _execute_command(self, command: str):
        """Execute shell command and display results"""
        self.console.print(f"\n[dim]Executing:[/] [bold]{command}[/]")

        try:
            # Execute command
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                cwd=self.current_directory,
                timeout=30
            )

            # Display results
            if result.stdout:
                syntax = Syntax(result.stdout, "bash", theme="monokai", line_numbers=False)
                self.console.print(Panel(syntax, title="Output", border_style="green"))

            if result.stderr:
                self.console.print(Panel(result.stderr, title="Error", border_style="red"))

            # Show return code
            if result.returncode != 0:
                self.console.print(f"[red]Exit code: {result.returncode}[/]")
            else:
                self.console.print("[green]✓ Command completed successfully[/]")

            # Add to context
            self.context.add_command_execution(command, result.stdout + result.stderr, result.returncode)

        except subprocess.TimeoutExpired:
            self.console.print("[red]⏰ Command timed out (30s limit)[/]")
        except Exception as e:
            self.console.print(f"[red]❌ Error executing command: {e}[/]")

    def _show_help(self):
        """Show help information"""
        help_table = Table(
            title="[cyan]Interactive Commands[/]",
            box=box.MINIMAL_DOUBLE_HEAD,
            show_header=True,
            header_style="bright_cyan",
        )
        help_table.add_column("Command", style="cyan")
        help_table.add_column("Description", style="white")

        help_table.add_row("/help", "Show this help message")
        help_table.add_row("/settings", "Show current settings")
        help_table.add_row("/exec <cmd>", "Execute shell command")
        help_table.add_row("/pentest", "Start AI-driven pentest")
        help_table.add_row("/context", "Show conversation context")
        help_table.add_row("/clear", "Clear screen")
        help_table.add_row("/pwd", "Show current directory")
        help_table.add_row("/ls", "List files in current directory")
        help_table.add_row("/cd <dir>", "Change directory")
        help_table.add_row("/quit", "Exit the program")

        self.console.print(help_table)

    def _show_settings(self):
        """Show current settings"""
        settings = Text()
        settings.append("🎯 Target: ", style="bright_cyan")
        settings.append(f"{self.target}\n", style="white")
        settings.append("📋 Objective: ", style="bright_cyan")
        settings.append(f"{self.objective}\n", style="white")
        settings.append("🤖 Provider: ", style="bright_cyan")
        settings.append(f"{self.provider}\n", style="white")
        settings.append("⚔️ Advanced Tools: ", style="bright_cyan")
        settings.append("Enabled\n" if self.enable_advanced else "Disabled\n", style="white")
        settings.append("📁 Working Directory: ", style="bright_cyan")
        settings.append(f"{self.current_directory}\n", style="white")
        settings.append("💬 Messages in Context: ", style="bright_cyan")
        settings.append(str(len(self.context.messages)), style="white")

        self.console.print(
            Panel(
                settings,
                border_style="magenta",
                box=box.SQUARE,
                title="[magenta]Session Settings[/]",
                padding=(1, 2),
            )
        )

    def _show_context(self):
        """Show conversation context"""
        recent_messages = self.context.get_recent_context(5)

        if not recent_messages:
            self.console.print("[dim]No conversation context yet.[/]")
            return

        context_text = ""
        for msg in recent_messages:
            role = msg["role"]
            content = msg["content"][:100] + "..." if len(msg["content"]) > 100 else msg["content"]
            context_text += f"**{role.title()}:** {content}\n\n"

        self.console.print(Panel(Markdown(context_text), title="Recent Context", border_style="blue"))

    def _clear_screen(self):
        """Clear the screen"""
        try:
            self.console.clear()
        except Exception:
            os.system('clear' if os.name == 'posix' else 'cls')
        self._show_welcome()

    def _show_current_directory(self):
        """Show current working directory"""
        self.console.print(f"[cyan]Current directory:[/] {self.current_directory}")

    def _change_directory(self, path: str):
        """Change current directory"""
        try:
            new_path = os.path.abspath(os.path.join(self.current_directory, path))
            if os.path.exists(new_path) and os.path.isdir(new_path):
                self.current_directory = new_path
                self.console.print(f"[green]Changed to:[/] {self.current_directory}")
            else:
                self.console.print(f"[red]Directory not found:[/] {path}")
        except Exception as e:
            self.console.print(f"[red]Error changing directory:[/] {e}")

    def _start_pentest(self):
        """Start penetration testing"""
        self.console.print(f"\n[bold green]🚀 Starting AI-driven penetration test...[/]")
        self.console.print(f"[cyan]Target:[/] {self.target}")
        self.console.print(f"[cyan]Objective:[/] {self.objective}")
        try:
            report = asyncio.run(self._run_agent_session(self.objective))
            if report:
                self.console.print(
                    Panel(report, border_style="green", title="🧾 Final Report", padding=(1, 2))
                )
                self.context.add_assistant_message(report)
            else:
                self.context.add_assistant_message("Pentest cycle completed without report output.")
        except Exception as exc:
            self.console.print(f"[red]❌ Pentest failed: {exc}[/]")

    def _show_goodbye(self):
        """Show goodbye message"""
        session_duration = datetime.now() - self.context.session_start

        goodbye_text = f"""
[bold green]Session Summary[/]

💬 **Messages exchanged:** {len(self.context.messages)}
⚡ **Commands executed:** {len(self.context.command_history)}
⏱️ **Session duration:** {str(session_duration).split('.')[0]}

[dim]Thank you for using 4myPown! Stay secure! 🛡️[/]
"""
        self.console.print(Panel(goodbye_text, title="Goodbye", border_style="green"))

    @staticmethod
    def _update_env_file(env_var: str, value: str) -> None:
        env_path = Path(".env")
        lines: List[str] = []
        if env_path.exists():
            lines = env_path.read_text(encoding="utf-8").splitlines()
        updated = False
        for idx, line in enumerate(lines):
            if line.startswith(f"{env_var}="):
                lines[idx] = f"{env_var}={value}"
                updated = True
                break
        if not updated:
            lines.append(f"{env_var}={value}")
        env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _open_quick_actions_menu(self) -> None:
        self.console.print("\n[cyan]Quick Actions[/]")
        self.console.print("  1) Set OpenAI API key")
        self.console.print("  2) Set Gemini API key")
        self.console.print("  3) Cancel")
        choice = self.console.input("Select option: ").strip()

        if choice == "1":
            key = self._prompt_for_key("OpenAI")
            if key:
                self._apply_api_key("OPENAI_API_KEY", "OpenAI", key)
        elif choice == "2":
            key = self._prompt_for_key("Gemini")
            if key:
                self._apply_api_key("GEMINI_API_KEY", "Gemini", key)
        else:
            self.console.print("[dim]Menu cancelled.[/]")

    def _prompt_for_key(self, label: str) -> Optional[str]:
        try:
            return getpass.getpass(f"Enter new {label} API key: ")
        except Exception:
            return self.console.input(f"Enter new {label} API key: ")

    def _apply_api_key(self, env_var: str, label: str, value: str) -> None:
        os.environ[env_var] = value
        self._update_env_file(env_var, value)
        try:
            import pown_cli.pown_cli as agent_module

            if env_var == "OPENAI_API_KEY":
                agent_module.openai_client = None
            elif env_var == "GEMINI_API_KEY":
                agent_module.gemini_api_key = None
        except Exception:
            pass
        self.console.print(f"[green]{label} API key updated.[/]")
