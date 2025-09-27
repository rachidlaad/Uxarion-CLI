"""
4myPown - Interactive CLI Entry Point
Modern Rich-based terminal interface with chat-style interaction
"""
from __future__ import annotations

import asyncio
import sys
import os
from typing import Optional

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
from .ui.claude_style_ui import ClaudeStyleUI

app = typer.Typer(add_completion=False, no_args_is_help=False)
console = Console()


def print_banner():
    """Print the 4myPown banner"""
    banner = """──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
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
# Type '/' + Enter to see menu, then type option number + Enter

you> """
    return banner


@app.command()
def chat() -> None:
    """Start interactive chat mode with Claude Code-style UI"""
    # Initialize and run the Claude-style UI
    ui = ClaudeStyleUI()
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

    # Import and use the original functionality as fallback
    try:
        # This would import the original monolithic functionality
        from ..pown_cli import main as original_main
        import sys

        # Simulate command line args for the original function
        original_args = [
            "--prompt", objective,
            "--max-steps", str(max_steps),
        ]

        if target:
            # Try to determine if it's a domain or IP
            if target.startswith(("http://", "https://")):
                from urllib.parse import urlparse
                parsed = urlparse(target)
                original_args.extend(["--allow-domain", parsed.hostname or target])
            elif "." in target and not target.replace(".", "").isdigit():
                original_args.extend(["--allow-domain", target])
            else:
                original_args.extend(["--allow-ip", target])

        if enable_advanced:
            original_args.append("--enable-advanced-tools")

        if dry_run:
            original_args.append("--dry-run")

        if provider:
            original_args.extend(["--provider", provider])

        # Save original sys.argv and replace
        original_argv = sys.argv
        sys.argv = ["pown"] + original_args

        try:
            original_main()
        finally:
            sys.argv = original_argv

    except ImportError:
        console.print("[red]Error: Could not import original functionality[/]")
        console.print("[yellow]Please use the 'chat' command for interactive mode[/]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/]")


def main() -> None:
    """Main entry point"""
    import sys

    # If no arguments provided, start Claude-style chat mode
    if len(sys.argv) == 1:
        ui = ClaudeStyleUI()
        ui.run()
    else:
        app()


if __name__ == "__main__":
    main()