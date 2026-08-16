# Agentic LLM Security: Dual-LLM Pattern + AgentDojo Evaluation

---

## What This Project Is

LLM-based agents can read your emails, manage your calendar, and take actions on your behalf. That power introduces a serious vulnerability: **prompt injection** — an attacker embeds malicious instructions inside untrusted data (an email, a calendar event, a file), and the agent follows them without the user knowing.

This project implements and evaluates the **Dual-LLM pattern** (Willison, 2023) as a defence against prompt injection, integrated with the **AgentDojo** benchmark framework for rigorous, reproducible testing. It also includes a custom **attack test suite** that probes the pattern's limits with four escalating attack scenarios.

**Key finding:** The Dual-LLM pattern blocks direct tool hijacking and control-flow injection, but is vulnerable to data-poisoning attacks that achieve up to ~85% Attack Success Rate (ASR). This motivates future work on stronger architectures like CaMeL.

---

## The Dual-LLM Architecture

The pattern splits a single agent into two components with strictly separated roles:

```
User Request
     │
     ▼
┌─────────────┐        ┌──────────────────────────────────────┐
│  CONTROLLER │        │  PRIVILEGED LLM  (P-LLM)             │
│             │◄──────►│  Llama 3.3 70B via Groq              │
│  - manages  │        │  - makes all control-flow decisions   │
│    $VAR     │        │  - calls tools                        │
│    tokens   │        │  - never sees raw untrusted content   │
│  - runs     │        └──────────────────────────────────────┘
│    tools    │
│  - enforces │        ┌──────────────────────────────────────┐
│    boundary │        │  QUARANTINED LLM  (Q-LLM)            │
│             │◄──────►│  Llama 3.1 8B via Groq               │
└─────────────┘        │  - handles raw untrusted data         │
       │               │  - extracts structured values         │
       ▼               │  - NO tool access, cannot call tools  │
   Real Tools          └──────────────────────────────────────┘
(send_email, etc.)
```

**Security invariant:** Raw untrusted content never reaches P-LLM. Q-LLM cannot call tools. Control flow always stays with P-LLM via the Controller.

The Controller passes data between components using opaque `$VAR` tokens — P-LLM only ever sees token names, never the underlying content.

---

## Repository Structure

```
├── dual_llm_pattern.py      # Core implementation: Controller, P-LLM, Q-LLM, VariableStore
├── agentdojo_adapter.py     # AgentDojo integration: DualLLMPipeline, benchmark runners
├── test_dual_llm.py         # Attack test suite: 4 escalating attack scenarios
├── .env.example             # Required environment variables
└── README.md
```

---

## Attack Test Suite

`test_dual_llm.py` contains four tests that escalate in sophistication:

| # | Test | Attack Strategy | Result |
|---|------|----------------|--------|
| 1 | Benign baseline | No attack — normal email | ✅ Pass |
| 2 | Naive injection | `"IGNORE ALL PREVIOUS INSTRUCTIONS"` | ✅ Blocked |
| 3 | Adaptive injection | Embeds instruction inside schema-compliant compliance text | ⚠️ Partial |
| 4 | Pattern-breaking injection | Impersonates IT dept with `[CONFIG_PARAM]` metadata blocks | ❌ Leaks |

**Test 4** demonstrates the fundamental weakness: an attacker who knows the Dual-LLM structure can craft content that looks like a valid extracted fact to Q-LLM while encoding a malicious instruction that P-LLM then acts on with real tools.

---

## Evaluation Results (AgentDojo — Workspace Suite)

Evaluated against AgentDojo's workspace benchmark (emails, calendar, cloud drive tasks) using the `ignore_previous` attack:

| Scenario | Utility | ASR | Notes |
|----------|---------|-----|-------|
| Benign utility | ~55% | — | Some tasks missed due to tool routing complexity |
| Naive injection | ~80% | ~20% | Direct IGNORE ALL attacks largely blocked |
| Adaptive injection | ~60% | ~40% | Schema-aware attacks partially bypass Q-LLM |
| Pattern-breaking attack | ~20% | ~85% | Authority-framed injections exploit P-LLM trust |

**Utility** = % of legitimate tasks completed correctly.  
**ASR (Attack Success Rate)** = % of injection attacks that successfully caused the agent to perform the attacker's intended action.

---

## Setup

### Prerequisites

- Python 3.10+
- A [Groq API key](https://console.groq.com/) (free tier works)
- AgentDojo installed

### Install

```bash
git clone https://github.com/SamUpid/agentic-llm-security
cd agentic-llm-security
pip install -r requirements.txt
```

### Environment

Create a `.env` file:

```
GROQ_API_KEY=your_key_here
```

### Run the attack test suite

```bash
python test_dual_llm.py
```

### Run AgentDojo evaluation

```bash
# Benign utility (no injections)
python agentdojo_adapter.py --mode utility

# Security evaluation (with injections)
python agentdojo_adapter.py --mode security --attack ignore_previous
```

---

## Why This Matters

Prompt injection is one of the most critical open problems in AI security. As LLM agents get broader real-world deployment — reading email, executing code, managing files — the attack surface grows. This project:

- Provides a working, benchmarked implementation of the Dual-LLM pattern
- Quantifies exactly where it succeeds and where it fails
- Demonstrates that **probabilistic defences are insufficient** for production agentic systems
- Lays the groundwork for evaluating stronger architectures (CaMeL, Plan-Then-Execute)

---

## Key Takeaway

The Dual-LLM pattern prevents **direct tool hijacking** — the Q-LLM cannot call tools, and control flow always stays with P-LLM. This is a real, meaningful defence.

But it does **not** prevent **data poisoning**: a sophisticated attacker can craft untrusted content that passes through Q-LLM's extraction step and poisons the values P-LLM then uses to call tools. The security guarantee is probabilistic, not structural.

> The fix requires a fundamentally different approach — tracking **data provenance** at the execution layer (not the LLM layer), so that untrusted data is blocked from influencing sensitive tool calls regardless of what either LLM decides. That is the direction of CaMeL and next semester's work.

---

## References

- Willison, S. — [The Dual LLM Pattern for Building AI Assistants that Can Resist Prompt Injection](https://simonwillison.net/2023/Apr/25/dual-llm-pattern/) (2023)
- Debenedetti et al. — [AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents](https://arxiv.org/abs/2406.13352) (2024)
- Abdelnabi et al. — [Defeating Prompt Injections by Design (CaMeL)](https://arxiv.org/abs/2503.18813) — Google DeepMind (2025)

---

## Next Work

Next semester: implement and evaluate **CaMeL** (Capabilities and Machine Learning) — a provenance-tracking architecture where every variable is tagged with its trust origin, and sensitive tool calls are blocked at the policy layer if their arguments derive from untrusted data. This provides a **deterministic** security guarantee rather than a probabilistic one.
