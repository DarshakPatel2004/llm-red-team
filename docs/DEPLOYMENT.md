# DEPLOYMENT.md

## Production Setup

### Prerequisites

- Python 3.10+
- API keys for target LLM providers
- (Optional) Ollama for local models

### Installation

```bash
pip install llm-red-team
```

### Configuration

1. Copy `configs/models.yaml` to your environment
2. Set environment variables for API keys:
   ```bash
   export ANTHROPIC_API_KEY=your-key
   export OPENAI_API_KEY=your-key
   export GOOGLE_API_KEY=your-key
   ```
3. Configure models in `configs/models.yaml`

### Running

```bash
# Health check
llm-red-team health

# Dry run
llm-red-team run --dry-run

# Full run
llm-red-team run --all-enabled
```

### Docker (Optional)

```bash
docker build -t llm-red-team .
docker run llm-red-team
```

### CI/CD Integration

See `.github/workflows/ci.yml` for template configurations.

## Scaling

- Increase `rate_limit` per model in config
- Use parallel execution (Phase 3+)
- Scale horizontally with multiple API keys
- Use database backend (PostgreSQL) for large runs

## Monitoring

- Structured JSON logging enabled
- Metrics exported via console
- Alert webhooks configured in environment
