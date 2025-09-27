"""
Claude Code-style Interactive Terminal UI for 4myPown
Enhanced with code execution, conversation context, and streaming responses
"""
import sys
import os
import subprocess
import json
import time
from typing import List, Dict, Any, Optional
from datetime import datetime

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.prompt import Prompt
    from rich.syntax import Syntax
    from rich.live import Live
    from rich.markdown import Markdown
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


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


class ClaudeStyleUI:
    """Claude Code-style interactive terminal interface"""

    def __init__(self):
        if not RICH_AVAILABLE:
            print("Error: Rich library required. Run: pip install rich")
            sys.exit(1)

        self.console = Console()
        self.context = ConversationContext()
        self.current_directory = os.getcwd()

        # Settings
        self.target = "127.0.0.1"
        self.objective = "Security assessment"
        self.provider = "gemini"
        self.enable_advanced = False

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
        """Show welcome message"""
        welcome_text = f"""
[bold cyan]4myPown Claude Code-style Interface[/]

🤖 AI-powered penetration testing with interactive code execution
⚡ Multi-turn conversations with context preservation
🛠️ Command execution and real-time results
🎯 Current working directory: [dim]{self.current_directory}[/]

[yellow]Available commands:[/]
• Type any message to chat with the AI
• Use `/help` to see all commands
• Use `/settings` to configure pentest parameters
• Use `/exec <command>` to execute shell commands
• Use `/pentest` to start AI-driven security testing

[dim]Type your message and press Enter...[/]
"""
        self.console.print(Panel(welcome_text, title="Welcome", border_style="cyan"))

    def _get_user_input(self) -> str:
        """Get user input with Claude Code-style prompt"""
        return self.console.input("\n[cyan]you>[/] ").strip()

    def _process_user_input(self, user_input: str):
        """Process user input and generate responses"""
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

        if cmd == "/help":
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
        """Handle regular chat messages with AI response simulation"""
        # Show typing indicator
        with Live("[dim]🤖 AI is thinking...[/]", console=self.console) as live:
            time.sleep(1)  # Simulate processing time

        # Generate AI response
        response = self._generate_ai_response(message)

        # Display response with streaming effect
        self._display_streaming_response(response)

        self.context.add_assistant_message(response)

    def _generate_ai_response(self, message: str) -> str:
        """Generate AI response based on context"""
        # Simple rule-based responses for demo
        message_lower = message.lower()

        if any(word in message_lower for word in ["hello", "hi", "hey"]):
            return "Hello! I'm your AI pentesting assistant. How can I help you today?"

        elif any(word in message_lower for word in ["help", "what can you do"]):
            return """I can help you with:
• **Security assessments** - Run comprehensive penetration tests
• **Command execution** - Execute shell commands and analyze results
• **Code analysis** - Review and analyze security-related code
• **Vulnerability research** - Research and explain security issues
• **Tool guidance** - Help with security tools like nmap, sqlmap, etc.

What would you like to explore?"""

        elif any(word in message_lower for word in ["test", "scan", "pentest", "security"]):
            return f"""I can help you perform security testing on your target: `{self.target}`

Would you like me to:
1. Start with reconnaissance (port scanning, service detection)
2. Test for common vulnerabilities (SQL injection, XSS, etc.)
3. Analyze a specific service or application
4. Execute specific security tools

Use `/pentest` to start an automated assessment, or tell me what specific testing you'd like to perform."""

        elif any(word in message_lower for word in ["command", "exec", "run", "execute"]):
            return """I can execute commands for you! Use the `/exec` command:

Examples:
• `/exec nmap -sV 127.0.0.1` - Run network scan
• `/exec ls -la` - List files
• `/exec cat /etc/passwd` - Read system files
• `/exec python3 -c "print('Hello')"` - Run Python code

What command would you like me to execute?"""

        else:
            return f"""I understand you're asking about: "{message}"

As your AI pentesting assistant, I can help with security-related tasks. Here are some suggestions:

• Use `/exec <command>` to run security tools
• Use `/pentest` to start automated testing
• Ask me about specific vulnerabilities or tools
• Request code analysis or security reviews

What specific security task would you like assistance with?"""

    def _display_streaming_response(self, response: str):
        """Display response with streaming effect"""
        self.console.print("\n🤖 ", end="")

        # Stream response word by word
        words = response.split()
        for i, word in enumerate(words):
            self.console.print(word, end="")
            if i < len(words) - 1:
                self.console.print(" ", end="")
            time.sleep(0.05)  # Typing effect

        self.console.print()  # New line at end

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
        help_table = Table(title="Available Commands")
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
        settings_text = f"""
[bold yellow]Current Settings:[/]

🎯 **Target:** {self.target}
📋 **Objective:** {self.objective}
🤖 **AI Provider:** {self.provider}
⚔️ **Advanced Tools:** {'Enabled' if self.enable_advanced else 'Disabled'}
📁 **Working Directory:** {self.current_directory}
💬 **Messages in Context:** {len(self.context.messages)}
"""
        self.console.print(Panel(settings_text, title="Settings", border_style="yellow"))

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

        # This would integrate with the original pentest functionality
        self.console.print("[yellow]⚡ This would launch the full AI pentesting workflow[/]")
        self.console.print("[dim]Integration with existing pown_cli functionality...[/]")

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