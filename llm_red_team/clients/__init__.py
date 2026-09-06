from llm_red_team.clients.base import LLMClient


class AnthropicClient(LLMClient):
    """Anthropic Claude API client implementation."""

    def __init__(self, model_id: str, config: dict) -> None:
        self.model_id = model_id
        self.config = config
        self.api_key = config.get("api_key", "")
        self._client = None

    def query(self, prompt: str, **kwargs) -> dict:
        return {
            "response": f"[Anthropic/{self.model_id}] Response to: {prompt[:100]}",
            "tokens": kwargs.get("max_tokens", 4096),
            "latency_ms": 200,
            "metadata": {"provider": "anthropic", "model_id": self.model_id},
            "success": True,
        }

    def chat(self, messages, **kwargs):
        return {"response": "[Anthropic chat response]", "tokens": 100, "latency_ms": 150, "metadata": {}}

    def stream(self, prompt, **kwargs):
        yield f"[Anthropic streaming: {prompt[:50]}]"

    def supports_streaming(self):
        return True

    def get_model_info(self):
        return {"model_id": self.model_id, "provider": "anthropic", "type": "api"}

    def get_token_count(self, text):
        return max(1, len(text) // 4)

    def get_cost_estimate(self, prompt, **kwargs):
        return 0.005

    def health_check(self):
        return True


class OpenAIClient(LLMClient):
    """OpenAI GPT-4 API client implementation."""

    def __init__(self, model_id: str, config: dict) -> None:
        self.model_id = model_id
        self.config = config
        self.api_key = config.get("api_key", "")

    def query(self, prompt: str, **kwargs) -> dict:
        return {
            "response": f"[OpenAI/{self.model_id}] Response to: {prompt[:100]}",
            "tokens": kwargs.get("max_tokens", 4096),
            "latency_ms": 180,
            "metadata": {"provider": "openai", "model_id": self.model_id},
            "success": True,
        }

    def chat(self, messages, **kwargs):
        return {"response": "[OpenAI chat response]", "tokens": 100, "latency_ms": 150, "metadata": {}}

    def stream(self, prompt, **kwargs):
        yield f"[OpenAI streaming: {prompt[:50]}]"

    def supports_streaming(self):
        return True

    def get_model_info(self):
        return {"model_id": self.model_id, "provider": "openai", "type": "api"}

    def get_token_count(self, text):
        return max(1, len(text) // 4)

    def get_cost_estimate(self, prompt, **kwargs):
        return 0.003

    def health_check(self):
        return True


class OllamaClient(LLMClient):
    """Ollama local model client implementation."""

    def __init__(self, model_id: str, config: dict) -> None:
        self.model_id = model_id
        self.config = config
        self.endpoint = config.get("endpoint", "http://localhost:11434")

    def query(self, prompt: str, **kwargs) -> dict:
        return {
            "response": f"[Ollama/{self.model_id}] Response to: {prompt[:100]}",
            "tokens": kwargs.get("max_tokens", 2048),
            "latency_ms": 500,
            "metadata": {"provider": "ollama", "model_id": self.model_id, "local": True},
            "success": True,
        }

    def chat(self, messages, **kwargs):
        return {"response": "[Ollama chat response]", "tokens": 100, "latency_ms": 400, "metadata": {}}

    def stream(self, prompt, **kwargs):
        yield f"[Ollama streaming: {prompt[:50]}]"

    def supports_streaming(self):
        return True

    def get_model_info(self):
        return {"model_id": self.model_id, "provider": "ollama", "type": "local"}

    def get_token_count(self, text):
        return max(1, len(text) // 4)

    def get_cost_estimate(self, prompt, **kwargs):
        return 0.0

    def health_check(self):
        return True
