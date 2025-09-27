# 4myPown CLI

Linux-first, Claude-Code-style CLI and AI-driven pentesting orchestrator for the 4myPown project.

This package provides:
- An autonomous orchestrator that loops through Think → Plan → Act → Reflect
- A secure sandbox for executing defensive security tools with streamable output
- Interactive session management for tools like Metasploit (stubbed when unavailable)
- A Typer + Rich terminal CLI `pown`

## Quickstart

### Option 1: Automated Setup (Recommended)

Run the setup script for guided installation:

```bash
./setup.sh
```

This will:
- Create virtual environment
- Install dependencies
- Configure AI providers (optional)
- Create `.env` file for API keys
- Show next steps

### Option 2: Manual Setup

Create a virtualenv and install manually:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .

# Copy environment template
cp .env.example .env

# Edit .env to add your API keys (optional)
nano .env
```

### Adding AI Providers (Optional)

To enable real AI models instead of local fallback:

```bash
# For Google Gemini
pip install google-generativeai
# Add to .env: GEMINI_API_KEY=your-api-key

# For OpenAI GPT-5 Mini  
pip install openai
# Add to .env: OPENAI_API_KEY=your-api-key

# For enhanced UI
pip install prompt_toolkit
```

Run a short autonomous loop (no network required, uses local fallback):

```
pown run "Recon example.com" -t https://example.com --max-loops 1
```

Run a single command via the secure sandbox:

```
pown cmd "nmap -sV -p 80,443 example.com"
```

Try the special browser-do command (works without internet; writes a local screenshot file):

```
pown cmd 'browser-do {"actions":[{"type":"navigate","url":"https://example.com"},{"type":"screenshot"}]}'
```

Manage interactive sessions (stubbed if Metasploit RPC not available):

```
pown isession start metasploit
pown isession send <session_id> "search tomcat"
pown isession status <session_id>
pown isession stop <session_id>
```

Planner utilities:

```
pown todo gen "subdomain enum then httpx"
pown todo list
pown todo clear
```

## Notes
- When AI providers (Gemini/OpenAI) are not configured, a deterministic local planner/reasoner is used to keep the CLI fully functional offline.
- Potentially destructive commands are blocked by the sandbox. Example:

```
pown cmd "rm -rf /"   # blocked with clear error
```

- Evidence and session artifacts are stored under `~/.4mypown/sessions/<session_id>/`.

## License
For educational and defensive security purposes only.
