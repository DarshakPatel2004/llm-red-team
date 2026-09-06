# Architecture

## Overview

LLM Red Team Suite is a modular, extensible framework for testing LLM security vulnerabilities.

## Component Diagram

```
┌─────────────┐    ┌──────────────────┐    ┌──────────────┐
│   CLI (CLI) │───▶│   ConfigLoader   │───▶│   Clients    │
│  (click)    │    │   (YAML-based)   │    │  (base.py)   │
└─────────────┘    └──────────────────┘    └──────┬───────┘
                                                   │
                              ┌────────────────────┼────────────────────┐
                              │                    │                    │
                     ┌──────▼──────┐      ┌──────▼──────┐      ┌──────▼──────┐
                     │  MockClient │      │  API Clients │      │  Local Clients│
                     │  (testing)  │      │  (Anthropic, │      │  (Ollama)     │
                     └──────┬──────┘      │   OpenAI)    │      └─────────────┘
                            │            └──────────────┘
                            │
                     ┌──────▼──────┐
                     │  TestRunner │
                     │ (engine)    │
                     └──────┬──────┘
                            │
              ┌─────────────┼─────────────┐
              │             │             │
       ┌──────▼──────┐ ┌────▼──────┐ ┌────▼──────┐
       │Attribution  │ │ Defense   │ │Analysis   │
       │Engine       │ │Strategies │ │Engine     │
       └──────┬──────┘ └────┬──────┘ └────┬──────┘
              │             │             │
              └─────────────┼─────────────┘
                            │
                     ┌──────▼──────┐
                     │   Database  │
                     │  (SQLite)   │
                     └─────────────┘
```

## Module Structure

- `llm_red_team/clients/` — LLM client implementations (abstract + concrete)
- `llm_red_team/attacks/` — Adversarial prompts and attack categories
- `llm_red_team/engine/` — Test runner and batch executor
- `llm_red_team/attribution/` — Vulnerability classification and root cause analysis
- `llm_red_team/defense/` — 18 defense strategies
- `llm_red_team/analysis/` — Vulnerability matrices and model ranking
- `llm_red_team/config/` — YAML configuration loader
- `llm_red_team/database/` — SQLAlchemy schema and session management
- `llm_red_team/api/` — CLI interface
- `llm_red_team/production/` — ML injection detector, supply chain validator
- `llm_red_team/tests/` — pytest test suite

## Client Interface Contract

All clients must implement `LLMClient` (ABC):
- `query(prompt)` — Single prompt
- `chat(messages)` — Multi-turn conversation
- `stream(prompt)` — Streaming response
- `get_model_info()` — Model metadata
- `get_token_count(text)` — Token counting
- `get_cost_estimate(prompt)` — Cost estimation
- `health_check()` — Endpoint verification

## Design Principles

1. **Abstract First**: Interface defined before implementation
2. **Configuration-Driven**: No code changes for model switching
3. **Testable**: MockClient enables zero-config testing
4. **Extensible**: Add new models by implementing the base interface
5. **Observable**: Structured logging, metrics, and alerting built-in
