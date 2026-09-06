# MODEL_ADDITION_GUIDE.md

# Adding Custom Models

This guide explains how to add a new LLM model to the LLM Red Team Suite without modifying any framework code.

## Step 1: Implement the Client

Create a new file in `llm_red_team/clients/` that extends `LLMClient`:

```python
from llm_red_team.clients.base import LLMClient

class MyCustomClient(LLMClient):
    def __init__(self, model_id: str, config: dict):
        self.model_id = model_id
        self.config = config
        # Initialize your API client here

    def query(self, prompt: str, **kwargs) -> dict:
        # Your API call here
        return {
            "response": ...,
            "tokens": ...,
            "latency_ms": ...,
            "metadata": {"provider": "my_provider"},
            "success": True,
        }

    def chat(self, messages, **kwargs):
        ...

    def stream(self, prompt, **kwargs):
        ...

    def supports_streaming(self) -> bool:
        return True

    def get_model_info(self) -> dict:
        return {"model_id": self.model_id, "provider": "my_provider", "type": "api"}

    def get_token_count(self, text) -> int:
        ...

    def get_cost_estimate(self, prompt, **kwargs) -> float:
        ...

    def health_check(self) -> bool:
        ...
```

## Step 2: Add to Configuration

Add an entry to `configs/models.yaml`:

```yaml
my_custom_model:
  type: api
  provider: my_provider
  model_id: my-model-v1
  api_key: ${MY_API_KEY}
  enabled: true
  max_tokens: 4096
  temperature: 0.7
  timeout: 30
  retry_attempts: 3
  rate_limit: 10
  tags: [custom, experimental]
```

## Step 3: Register (Optional)

If auto-discovery is needed, add an import in `llm_red_team/clients/__init__.py`.

## Step 4: Test

```bash
# Dry run first
llm-red-team run --dry-run --models my_custom_model

# Run for real
llm-red-team run --models my_custom_model
```

## Requirements

- Must implement all abstract methods from `LLMClient`
- Must handle API errors gracefully (retries, timeouts)
- Must return the standard response dict format
- Must support `health_check()` returning boolean
