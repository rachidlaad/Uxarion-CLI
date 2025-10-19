# Zevionx AI Agent - Autonomous Pentesting Framework

> **⚠️ IMPORTANT**: This tool is for defensive security testing only. Use only on assets you own or have explicit written authorization to test.

## Overview

Zevionx AI Agent is a fully autonomous penetration testing framework driven entirely by AI planning. Unlike traditional pentesting tools with hardcoded scripts, this system uses Large Language Models to dynamically plan, execute, and adapt reconnaissance and security testing based on real-time discoveries.

## Key Features

### 🤖 **100% AI-Driven Planning**
- No hardcoded attack sequences
- Dynamic action planning based on discoveries
- Adaptive strategy adjustment during testing
- Context-aware decision making

### 🧠 **Temporal Knowledge Graph Memory**
- Neo4j-based persistent memory across sessions
- Relationship mapping between hosts, services, and vulnerabilities
- Time-aware context for informed decisions
- Attack path discovery and correlation

### 📡 **Real-Time Event Streaming**
- Live progress monitoring via Server-Sent Events
- Redis pub/sub for scalable event distribution
- Rich terminal UI with live updates
- Web dashboard for remote monitoring

### 🐳 **Sandboxed Tool Execution**
- Docker-based isolation for pentesting tools
- Resource limits and timeout protection
- Command allowlisting for safety
- Fallback to local execution when needed

### 🛡️ **Enterprise-Grade Safety**
- Target allowlisting enforcement
- Command injection prevention
- Audit trails for all actions
- Graceful degradation when services unavailable

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Zevionx AI Agent                        │
├─────────────────────────────────────────────────────────────┤
│  Terminal UI  │  Web Dashboard  │  REST API  │  CLI Tool    │
├─────────────────────────────────────────────────────────────┤
│                    Event Bus (Redis)                        │
├─────────────────────────────────────────────────────────────┤
│  AI Orchestrator  │  Specialized Agents  │  AI Providers    │
├─────────────────────────────────────────────────────────────┤
│  Knowledge Graph (Neo4j)  │  Docker Runtime  │  Safety      │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Prerequisites

```bash
# Required
- Python 3.11+
- Docker Desktop
- AI API Key (OpenAI, Anthropic, etc.)

# Optional (for full features)
- Redis server
- Neo4j database
```

### 2. Installation

```bash
# Clone repository
git clone <repository-url>
cd Zevionx-CLI

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your AI API key and targets
```

### 3. Start Infrastructure (Optional)

```bash
# Start Redis and Neo4j (for full features)
docker compose up -d neo4j redis

# Or start everything including API server
docker compose --profile api up -d
```

### 4. Run Autonomous Reconnaissance

```bash
# CLI mode
python -m zevionx_cli.ai_orchestrator --target 127.0.0.1 --mode recon

# Interactive terminal UI
python -m zevionx_cli.ui.terminal_ui

# API server
python -m zevionx_cli.api_server
# Then visit http://localhost:8000/demo
```

## Usage Examples

### Command Line Interface

```bash
# Basic reconnaissance
python -m zevionx_cli.ai_orchestrator \
  --target scanme.example.com \
  --objective "Map all web services and identify potential vulnerabilities"

# Comprehensive penetration test
python -m zevionx_cli.ai_orchestrator \
  --target 192.168.1.100 \
  --mode pentest \
  --objective "Full security assessment with safe exploitation"
```

### Interactive Terminal UI

```bash
# Start terminal interface
python -m zevionx_cli.ui.terminal_ui

# Use the interactive menu:
you> /set target 127.0.0.1
you> /set objective Deep reconnaissance for web application
you> /start
```

### REST API

```bash
# Start API server
python -m zevionx_cli.api_server

# Start reconnaissance via API
curl -X POST http://localhost:8000/api/v1/start \
  -H "Content-Type: application/json" \
  -d '{"target": "127.0.0.1", "objective": "Web application reconnaissance"}'

# Stream live events
curl -N http://localhost:8000/api/v1/events/{session_id}
```

## Configuration

### Environment Variables

```bash
# Required - Target allowlist
ALLOWLIST=127.0.0.1,localhost,your-test-domain.com

# Required - AI Provider (choose one)
OPENAI_API_KEY=sk-your-key-here
# OR
ANTHROPIC_API_KEY=sk-ant-your-key-here

# Optional - Infrastructure
REDIS_URL=redis://localhost:6379/0
NEO4J_URI=bolt://localhost:7687
NEO4J_PASSWORD=your-password
```

### AI Providers

The system supports multiple AI providers:

- **OpenAI**: GPT-3.5, GPT-4, GPT-4 Turbo
- **Anthropic**: Claude 3 (Haiku, Sonnet, Opus)
- **Custom**: Implement your own provider

```python
# Custom provider example
from zevionx_cli.ai_providers import register_provider

class CustomProvider:
    def generate(self, prompt: str) -> str:
        # Your implementation
        return response

register_provider("custom", CustomProvider())
```

## Agent Types

### 🔍 Reconnaissance Agent
- **Purpose**: Information gathering and asset discovery
- **Tools**: nmap, curl, gobuster, nikto
- **Output**: Hosts, ports, services, endpoints, technologies

### 🔎 Scanner Agent (Planned)
- **Purpose**: Vulnerability assessment and analysis
- **Tools**: Various security scanners
- **Output**: Vulnerability reports with risk ratings

### 💥 Exploit Agent (Planned)
- **Purpose**: Safe exploitation and impact demonstration
- **Tools**: Proof-of-concept exploits
- **Output**: Exploitation evidence and recommendations

### 📊 Reporter Agent (Planned)
- **Purpose**: Professional findings synthesis
- **Tools**: Report generation and correlation
- **Output**: Executive and technical reports

## Event Types

The system streams various event types for real-time monitoring:

```json
{
  "ts": "2025-01-01T12:00:00Z",
  "type": "step.started",
  "session_id": "recon_127_0_0_1_1234567890",
  "data": {
    "id": "step-1",
    "description": "Port scan with nmap",
    "command": "nmap -sV --top-ports 100 127.0.0.1"
  }
}
```

Event types include:
- `state.update` - Session state changes
- `step.started` - Command execution begins
- `step.finished` - Command completes
- `log.append` - Command output
- `vulnerability.found` - Security finding
- `ai.analysis` - AI reasoning and analysis
- `error` - Error conditions

## Safety Features

### Target Allowlisting
```bash
# Only these targets will be tested
ALLOWLIST=127.0.0.1,192.168.1.0/24,your-test-domain.com
```

### Command Safety
- Allowlisted commands only
- Dangerous pattern detection
- Resource limits and timeouts
- Docker isolation

### Audit Trails
- All commands logged with timestamps
- Session state persistence
- Event streaming for monitoring
- Graph database for historical analysis

## Monitoring and Observability

### Neo4j Browser
```bash
# Access at http://localhost:7474
# Query example:
MATCH (h:Host)-[r:HAD_SCAN]->(s:Scan)-[:FOUND]->(p:Port)
RETURN h, s, p LIMIT 50
```

### Live Event Stream
```bash
# Monitor events in real-time
curl -N http://localhost:8000/api/v1/events/{session_id}
```

### Health Checks
```bash
curl http://localhost:8000/health
```

## Development

### Project Structure
```
zevionx_cli/
├── agents/           # Specialized AI agents
├── bus/             # Event streaming
├── memory/          # Knowledge graph
├── tools/           # Sandboxed execution
├── ui/              # Terminal and web interfaces
├── ai_providers.py  # AI provider integrations
└── api_server.py    # FastAPI server
```

### Adding New Agents
```python
from zevionx_cli.agents.base import BaseAgent

class CustomAgent(BaseAgent):
    async def execute(self, objective: str, context: dict) -> dict:
        # Your agent implementation
        return results
```

### Custom Event Handlers
```python
from zevionx_cli.bus.events import get_publisher

publisher = get_publisher()
await publisher.custom_event(session_id, "my.event", {"data": "value"})
```

## Troubleshooting

### Common Issues

**Import Errors**
```bash
# Missing dependencies
pip install -r requirements.txt

# Python path issues
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

**Docker Issues**
```bash
# Ensure Docker is running
docker info

# Check available images
docker images | grep -E "(nmap|nikto|gobuster)"
```

**Redis/Neo4j Unavailable**
```bash
# The system gracefully degrades without these services
# But for full features, ensure they're running:
docker compose up -d neo4j redis
```

**AI Provider Issues**
```bash
# Check API key configuration
echo $OPENAI_API_KEY
echo $ANTHROPIC_API_KEY

# Test provider connectivity
python -c "from zevionx_cli.ai_providers import resolve_default_provider; print(resolve_default_provider().generate('test'))"
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Add tests
5. Submit a pull request

## License

[MIT License](LICENSE)

## Disclaimer

This tool is for authorized security testing only. Users are responsible for ensuring they have proper authorization before testing any systems. The authors are not responsible for any misuse or damage caused by this tool.

## Support

- 📧 Email: rachidshade@gmail.com
- 🐦 Twitter: @Rachid_LLLL
- 💻 GitHub: https://github.com/rachidlaad

---

*Zevionx AI Agent - Bringing AI-driven autonomy to penetration testing while maintaining safety and ethics.*