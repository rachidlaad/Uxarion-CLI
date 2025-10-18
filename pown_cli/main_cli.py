# SPDX-License-Identifier: Apache-2.0
"""
4myPown - Interactive CLI Entry Point
Modern Rich-based terminal interface with chat-style interaction
"""
from __future__ import annotations

import asyncio
import sys
import os
import subprocess
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

try:
    import uvloop  # type: ignore
    uvloop.install()
except Exception:
    pass

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from .ui.interactive_ui import InteractiveUI
from .ui.chat_ui import ChatUI

app = typer.Typer(add_completion=False, no_args_is_help=False)
console = Console()


def print_banner():
    """Print the 4myPown banner"""
    banner = """──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
                       ██████╗   ██╗   ██╗███╗   ██╗
                       ██╔══██╗  ██║   ██║████╗  ██║
                       ██████╔╝  ██║   ██║██╔██╗ ██║
                       ██╔══██╗  ██║   ██║██║╚██╗██║
                       ██║  ██║  ╚██████╔╝██║ ╚████║
                       ╚═╝  ╚═╝   ╚═════╝ ╚═╝  ╚═══╝

                              4myPown CLI

I would be happy for you to connect, collaborate, fix a bug or add a feature to the tool 😊
X.com > @Rachid_LLLL    Gmail > rachidshade@gmail.com    GitHub > https://github.com/rachidlaad

4myPawn is an AI pentesting copilot, open-source for the pentesting community.
Official site: https://4mypawn.com/
Tip: press '/' in chat to update API keys via the quick actions menu.
Bring your own API key and drive proven CLI tools (sqlmap, gobuster, nikto, nmap)
through a safe, single-command loop.

🤖 Now powered by Google Gemini for superior autonomous decision making (GPT-5 ready when billing is fixed)
⚠️  AUTHORIZED USE ONLY - Test only systems you own or have permission to test
🛡️  Enhanced with enterprise-grade safety controls and command validation
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

# Chat mode started. Type your objective/instructions
# Ctrl-C interrupts a running loop; 'quit' to exit
# Type '/' + Enter to see menu, then type option number + Enter

you> """
    return banner


@app.command()
def chat() -> None:
    """Start interactive chat mode"""
    ui = ChatUI()
    ui.run()


@app.command()
def menu() -> None:
    """Start menu-based interactive mode"""
    # Initialize and run the menu-based UI
    ui = InteractiveUI()
    ui.run()


@app.command()
def pentest(
    objective: str = typer.Argument(..., help="What you want to test (e.g., 'Test login security')"),
    target: Optional[str] = typer.Option(None, "-t", "--target", help="Target URL or host"),
    provider: Optional[str] = typer.Option(None, "-p", "--provider", help="AI provider (openai|gemini)"),
    max_steps: int = typer.Option(15, help="Maximum execution steps"),
    dry_run: bool = typer.Option(False, help="Show plan without execution"),
    enable_advanced: bool = typer.Option(False, help="Enable advanced tools (SQLMap, Nmap, etc.)"),
) -> None:
    """Run autonomous penetration test (fallback to original functionality)"""

    print_banner()
    console.print(f"[bold cyan]# Starting autonomous pentest[/]")
    console.print(f"[cyan]# Objective:[/] {objective}")

    if target:
        console.print(f"[cyan]# Target:[/] {target}")

    agent_script = Path(__file__).resolve().parents[2] / "pown_cli.py"
    if not agent_script.exists():
        console.print(f"[red]Agent entrypoint not found at {agent_script}[/]")
        raise typer.Exit(code=1)

    cli_args = [
        sys.executable,
        str(agent_script),
        "--prompt",
        objective,
        "--max-commands",
        str(max_steps),
    ]

    if target:
        scope_value = target
        if target.startswith(("http://", "https://")):
            parsed = urlparse(target)
            if parsed.hostname:
                scope_value = parsed.hostname
        cli_args.extend(["--scope", scope_value])
    if enable_advanced:
        cli_args.extend(["--allow-tools", "sqlmap,nmap,gobuster,nikto"])
    if dry_run:
        cli_args.append("--dry-run")
    if provider:
        cli_args.extend(["--provider", provider])

    try:
        subprocess.run(cli_args, check=True)
    except subprocess.CalledProcessError as exc:
        console.print(f"[red]Agent exited with code {exc.returncode}[/]")


def main() -> None:
    """Main entry point"""
    import sys

    # If no arguments provided, start chat mode
    if len(sys.argv) == 1:
        ui = ChatUI()
        ui.run()
    else:
        app()


if __name__ == "__main__":
    main()
