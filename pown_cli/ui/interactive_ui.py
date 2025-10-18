# SPDX-License-Identifier: Apache-2.0
"""
Interactive Terminal UI for 4myPown
Simplified Rich-based interface that works standalone
"""
import sys
import os
import subprocess
from pathlib import Path
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.prompt import Prompt
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


class InteractiveUI:
    """Rich-based interactive terminal interface"""

    def __init__(self):
        if not RICH_AVAILABLE:
            print("Error: Rich library required. Run: pip install rich")
            sys.exit(1)

        self.console = Console()
        self.target = "127.0.0.1"
        self.objective = "Map open ports and services"
        self.provider = "gemini"
        self.enable_advanced = False

    def run(self):
        """Main UI loop"""
        self.console.print(self._get_banner())

        try:
            self._main_loop()
        except KeyboardInterrupt:
            self.console.print("\n[yellow]👋 Goodbye![/]")
            sys.exit(0)

    def _get_banner(self) -> str:
        """Return the 4myPown banner"""
        return """──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
                           █ █   █▀▄▀█   █ █   █▀▄   █▀█   █ █   █▀█
                           ▀▀▀   █ ▀ █   ▀█▀   █▀    █▀█   ▀█▀   █ █
                             █   █   █    █    █     █ █    █    █ █

I would be happy for you to connect, collaborate, fix a bug or add a feature to the tool 😊
X.com > @Rachid_LLLL    Gmail > rachidshade@gmail.com    GitHub > https://github.com/rachidlaad

4myPawn is an AI pentesting copilot, open-source for the pentesting community.
Bring your own API key and drive proven CLI tools (sqlmap, gobuster, nikto, nmap)
through a safe, single-command loop.

🤖 Now powered by Google Gemini for superior autonomous decision making (GPT-5 ready when billing is fixed)
⚠️  AUTHORIZED USE ONLY - Test only systems you own or have permission to test
🛡️  Enhanced with enterprise-grade safety controls and command validation
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

# Chat mode started. Type your objective/instructions
# Ctrl-C interrupts a running loop; 'quit' to exit
# Type '/' + Enter to see menu, then type option number + Enter"""

    def _main_loop(self):
        """Main interactive loop"""
        while True:
            try:
                command = self.console.input("\n[cyan]you>[/] ").strip()

                if command in ["quit", "exit", "q"]:
                    break
                elif command == "/":
                    self._show_menu()
                elif command in {"1"}:
                    self._set_target()
                elif command in {"2"}:
                    self._set_objective()
                elif command in {"3"}:
                    self._toggle_advanced_tools()
                elif command in {"4"}:
                    self._set_provider()
                elif command in {"5", "/start"}:
                    self._start_pentest()
                elif command in {"6"}:
                    break
                elif command:
                    # Treat as new objective and run immediately
                    self.objective = command
                    self.console.print(f"[bold cyan]Objective set:[/] {self.objective}")
                    self._start_pentest()

            except KeyboardInterrupt:
                self.console.print("\n[yellow]Interrupted[/]")
                continue
            except Exception as e:
                self.console.print(f"[red]Error: {e}[/]")

    def _show_menu(self):
        """Show interactive menu"""
        # Create a table for better formatting
        table = Table(title="[bold cyan]4myPown Menu Options[/]", show_header=False)
        table.add_column("Option", style="bold yellow")
        table.add_column("Description", style="white")

        table.add_row("1", "Set target")
        table.add_row("2", "Set objective")
        table.add_row("3", f"Toggle advanced tools [{'ON' if self.enable_advanced else 'OFF'}]")
        table.add_row("4", "Set AI provider")
        table.add_row("5", "Start penetration test")
        table.add_row("6", "Quit")

        self.console.print(table)

        # Show current settings
        settings_panel = Panel(
            f"[bold yellow]Current Settings:[/]\n"
            f"[cyan]Target:[/] {self.target}\n"
            f"[cyan]Objective:[/] {self.objective}\n"
            f"[cyan]Provider:[/] {self.provider}\n"
            f"[cyan]Advanced Tools:[/] {'Enabled' if self.enable_advanced else 'Disabled'}",
            title="Settings",
            border_style="green"
        )
        self.console.print(settings_panel)

    def _set_target(self):
        """Set the target"""
        new_target = Prompt.ask("[cyan]Enter target (domain, IP, or URL)[/]", default=self.target)
        if new_target:
            self.target = new_target
            self.console.print(f"[bold green]✓ Target set:[/] {self.target}")

    def _set_objective(self):
        """Set the objective"""
        new_objective = Prompt.ask("[cyan]Enter testing objective[/]", default=self.objective)
        if new_objective:
            self.objective = new_objective
            self.console.print(f"[bold green]✓ Objective set:[/] {self.objective}")

    def _toggle_advanced_tools(self):
        """Toggle advanced tools"""
        self.enable_advanced = not self.enable_advanced
        status = "enabled" if self.enable_advanced else "disabled"
        self.console.print(f"[bold green]✓ Advanced tools {status}[/]")

    def _set_provider(self):
        """Set AI provider"""
        new_provider = Prompt.ask(
            "[cyan]Select AI provider[/]",
            choices=["gemini", "openai"],
            default=self.provider
        )
        if new_provider:
            self.provider = new_provider
            self.console.print(f"[bold green]✓ Provider set:[/] {self.provider}")

    def _start_pentest(self):
        """Start the penetration test"""
        self.console.print(f"\n[bold green]🚀 Starting AI-driven penetration test...[/]")
        self.console.print(f"[cyan]Target:[/] {self.target}")
        self.console.print(f"[cyan]Objective:[/] {self.objective}")
        self.console.print(f"[cyan]Provider:[/] {self.provider}")

        if self.enable_advanced:
            self.console.print("[yellow]⚔️  Advanced tools enabled (SQLMap, Nmap, Gobuster, Nikto)[/]")

        # Build command to execute the original CLI
        agent_script = Path(__file__).resolve().parents[2] / "pown_cli.py"
        if not agent_script.exists():
            raise FileNotFoundError(f"Agent entrypoint not found at {agent_script}")

        cmd = [
            sys.executable,
            str(agent_script),
            "--prompt",
            self.objective,
            "--provider",
            self.provider,
        ]

        # Add target
        if self.target:
            scope_value = self.target
            if self.target.startswith(("http://", "https://")):
                parsed = urlparse(self.target)
                if parsed.hostname:
                    scope_value = parsed.hostname
            cmd.extend(["--scope", scope_value])

        if self.enable_advanced:
            cmd.extend(["--allow-tools", "sqlmap,nmap,gobuster,nikto"])

        try:
            self.console.print("[dim]Executing AI agent...[/]\n")

            # Execute the command
            result = subprocess.run(cmd, capture_output=False, text=True)

            if result.returncode == 0:
                self.console.print("\n[bold green]✅ Penetration test completed successfully![/]")
            else:
                self.console.print(f"\n[bold red]❌ Test completed with errors (exit code: {result.returncode})[/]")

        except Exception as e:
            self.console.print(f"[bold red]❌ Error executing test: {e}[/]")

        self.console.print("\n[dim]Press Enter to continue...[/]")
        input()
