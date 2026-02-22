# Uxarion CLI Orchestration Flow

## Visual Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           Uxarion AI Agent Orchestration                       │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐  │
│  │   User Interface    │    │  AutonomousOrch.    │    │   Core Services     │  │
│  │                     │    │                     │    │                     │  │
│  │ • TerminalUI        │◄──►│ • Session Mgmt      │◄──►│ • GoalManager       │  │
│  │ • InteractiveUI     │    │ • Loop Control      │    │ • PlannerService    │  │
│  │ • ClaudeStyleUI     │    │ • Phase Management  │    │ • ExecutionService  │  │
│  │ • Web Dashboard     │    │ • State Persistence │    │ • SafetyManager     │  │
│  └─────────────────────┘    └─────────────────────┘    └─────────────────────┘  │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Orchestration Flow Phases

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        PHASE-BASED EXECUTION LOOP                          │
└─────────────────────────────────────────────────────────────────────────────┘

1. INITIALIZATION PHASE
   ┌──────────────────────┐
   │ create_session()     │
   │ • Generate session   │
   │ • Bind services      │
   │ • Setup memory mgr   │
   └──────────────────────┘
              │
              ▼
2. THINKING PHASE
   ┌──────────────────────┐
   │ _think_phase()       │
   │ • AI Analysis        │
   │ • Build context      │
   │ • Generate insights  │
   └──────────────────────┘
              │
              ▼
3. PLANNING PHASE
   ┌──────────────────────┐
   │ _plan_phase()        │
   │ • Generate plan      │
   │ • Create todos       │
   │ • Strategic planning │
   └──────────────────────┘
              │
              ▼
4. ACTION LOOP (Iterative)
   ┌─────────────────────────────────────────────────────────────────────────┐
   │                          MAIN EXECUTION CYCLE                          │
   │                                                                         │
   │  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐     │
   │  │   REFLECTING    │    │     ACTING      │    │    ANALYSIS     │     │
   │  │                 │    │                 │    │                 │     │
   │  │ • Micro analysis│───►│ • Execute cmd   │───►│ • Update todos  │     │
   │  │ • AI reflection │    │ • Safety check  │    │ • Record action │     │
   │  │ • Decision make │    │ • Stream output │    │ • Error handling│     │
   │  │ • Todo updates  │    │ • Tool adapters │    │ • Memory update │     │
   │  └─────────────────┘    └─────────────────┘    └─────────────────┘     │
   │           ▲                                               │             │
   │           └───────────────────────────────────────────────┘             │
   └─────────────────────────────────────────────────────────────────────────┘
              │
              ▼
5. COMPLETION PHASE
   ┌──────────────────────┐
   │ Final Report Gen.    │
   │ • Generate report    │
   │ • Export results     │
   │ • Session cleanup    │
   └──────────────────────┘
```

## Service Component Interaction

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        CORE SERVICE ARCHITECTURE                           │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   GoalManager   │    │ PlannerService  │    │ExecutionService │
│                 │    │                 │    │                 │
│ • Model provider│───►│ • Plan generation│   │ • Command exec  │
│ • Prompt build  │    │ • Todo creation │   │ • Stream output │
│ • AI analysis   │    │ • Strategic plan│   │ • Sandbox mgmt  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  SafetyManager  │    │ EvidenceStore   │    │  ToolRegistry   │
│                 │    │                 │    │                 │
│ • Policy eval   │    │ • Session mgmt  │    │ • Tool adapters │
│ • Command block │    │ • Data persist  │    │ • Command prep  │
│ • Approval flow │    │ • State tracking│    │ • Output parse  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                                 ▼
                    ┌─────────────────┐
                    │ MemoryManager   │
                    │                 │
                    │ • Action record │
                    │ • Findings mgmt │
                    │ • Context build │
                    └─────────────────┘
```

## Command Execution Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        COMMAND EXECUTION PIPELINE                          │
└─────────────────────────────────────────────────────────────────────────────┘

1. AI Decision
   ┌─────────────────┐
   │ AI Reflection   │
   │ • Context eval  │
   │ • JSON decision │
   │ • Next action   │
   └─────────────────┘
            │
            ▼
2. Safety Evaluation
   ┌─────────────────┐
   │ SafetyManager   │
   │ • Policy check  │ ── BLOCKED ──► Command Rejected
   │ • Risk assess   │ ── REVIEW ──► User Approval
   │ • Auto-approve  │ ── ALLOW ───► Continue
   └─────────────────┘
            │
            ▼
3. Command Preparation
   ┌─────────────────┐
   │ Tool Adapter    │
   │ • Command prep  │
   │ • Parameter fix │
   │ • Safety flags  │
   └─────────────────┘
            │
            ▼
4. Execution
   ┌─────────────────┐
   │ExecutionService │
   │ • Subprocess    │
   │ • Stream output │
   │ • Capture logs  │
   └─────────────────┘
            │
            ▼
5. Analysis & Recording
   ┌─────────────────┐
   │ Action Analysis │
   │ • Parse output  │
   │ • Extract finds │
   │ • Update memory │
   │ • Todo updates  │
   └─────────────────┘
```

## State Management Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SESSION STATE FLOW                               │
└─────────────────────────────────────────────────────────────────────────────┘

Session States:
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   created   │───►│  thinking   │───►│  planning   │───►│ reflecting  │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
                                                                │
                                                                ▼
┌─────────────┐    ┌─────────────┐                    ┌─────────────┐
│  completed  │◄───│    error    │◄───────────────────│   acting    │
└─────────────┘    └─────────────┘                    └─────────────┘
                                                                │
                                                                │
                   Loop Control:                               │
                   • max_loops = 20                            │
                   • max_errors = 15                           │
                   • _stop flag                                │
                                                                │
                                                                ▼
                                                       ┌─────────────┐
                                                       │   Return    │
                                                       │ to reflect  │
                                                       └─────────────┘
```

## Data Flow Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                             DATA PERSISTENCE                               │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────┐
│  AgentSession   │ ── Contains ──► ┌─────────────────┐
│                 │                 │ • objective     │
│ • id            │                 │ • target        │
│ • state         │                 │ • loop_count    │
│ • timestamps    │                 │ • error_count   │
└─────────────────┘                 └─────────────────┘
         │
         ├── Actions ────► ┌─────────────────┐
         │                 │ • command       │
         │                 │ • exit_code     │
         │                 │ • stdout/stderr │
         │                 │ • observations  │
         │                 └─────────────────┘
         │
         ├── Todos ──────► ┌─────────────────┐
         │                 │ • description   │
         │                 │ • command       │
         │                 │ • status        │
         │                 │ • priority      │
         │                 └─────────────────┘
         │
         └── Insights ───► ┌─────────────────┐
                           │ • content       │
                           │ • tags          │
                           │ • timestamp     │
                           └─────────────────┘
```

## Key Orchestration Features

### 1. **Autonomous Loop Control**
- Maximum 20 loops with emergency exit
- Error threshold of 15 failures
- User interrupt capability (_stop flag)

### 2. **Phase-based Execution**
- **Think**: AI analysis of objective
- **Plan**: Generate strategic todos
- **Reflect**: Micro-analysis and decision making
- **Act**: Safe command execution
- **Complete**: Final report generation

### 3. **Safety Integration**
- Policy evaluation before execution
- Command sanitization and repair
- User approval for risky commands
- Sandbox execution environment

### 4. **Memory Management**
- Action recording and analysis
- Finding extraction and storage
- Context building for AI decisions
- Strategic plan tracking

### 5. **Real-time Streaming**
- Async generator pattern for UI updates
- Live command output streaming
- Phase-based progress reporting
- Error handling and recovery

The orchestrator operates as a stateful, phase-driven AI agent that safely executes penetration testing workflows through automated decision-making, safety checks, and continuous learning from command outputs.