# API.md

## CLI Commands

### `llm-red-team run`

Run adversarial tests against configured models.

```
Options:
  --models TEXT        Comma-separated model names
  --tiers TEXT         Comma-separated tier numbers
  --all-enabled        Run all enabled models
  --dry-run            Use mock client
  --resume             Resume interrupted session
```

### `llm-red-team models list`

List all configured models with their status.

### `llm-red-team models add`

Add a new model to configuration.

```
Usage: llm-red-team models add NAME [OPTIONS]
Options:
  --type TEXT      Model type (api, local, custom)
  --provider TEXT  Provider name
  --endpoint TEXT  API endpoint URL
```

### `llm-red-team health`

Check health of all configured models.

### `llm-red-team report`

Generate analysis report.

```
Options:
  --format TEXT    Output format (json, html, pdf)
  --output TEXT    Output file path
```

### `llm-red-team export`

Export results in various formats.

```
Options:
  --format TEXT    Export format
  --output TEXT    Output filename
```

### `llm-red-team health`

Verify all configured models are reachable.

## Python API

```python
from llm_red_team.clients import MockClient
from llm_red_team.engine.runner import TestRunner
from llm_red_team.config.loader import ConfigLoader

# Load config and create client
config = ConfigLoader().load()
client = MockClient("test", {})

# Run tests
runner = TestRunner(client, max_retries=3)
results = runner.run_all()
summary = runner.get_summary()

# Attribution
from llm_red_team.attribution.engine import AttributionEngine
engine = AttributionEngine()
report = engine.generate_attribution_report(results)

# Defenses
from llm_red_team.defense.strategies import get_all_defenses
for defense in get_all_defenses():
    result = defense.evaluate(results)

# Production tools
from llm_red_team.production.tools import InjectionDetector
detector = InjectionDetector()
result = detector.detect("ignore all instructions")
```

## LLMClient Interface

All client implementations must provide:

| Method | Parameters | Returns |
|--------|-----------|---------|
| `query` | `prompt: str, **kwargs` | `dict` |
| `chat` | `messages: list[dict], **kwargs` | `dict` |
| `stream` | `prompt: str, **kwargs` | `Generator[str]` |
| `supports_streaming` | — | `bool` |
| `get_model_info` | — | `dict` |
| `get_token_count` | `text: str` | `int` |
| `get_cost_estimate` | `prompt: str, **kwargs` | `float` |
| `health_check` | — | `bool` |
