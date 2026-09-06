from __future__ import annotations
from typing import Any, Generator
from llm_red_team.clients.base import LLMClient

class OpenAIClient(LLMClient):
    def __init__(self, model_id: str, config: dict) -> None:
        self.model_id = model_id
        self.config = config
        self.api_key = config.get("api_key", "")
    def query(self, prompt: str, **kwargs) -> dict:
        return {"response": f"[OpenAI/{self.model_id}] {prompt[:100]}", "tokens": kwargs.get("max_tokens", 4096), "latency_ms": 180, "metadata": {"provider": "openai", "model_id": self.model_id}, "success": True}
    def chat(self, messages, **kwargs): return {"response": "[OpenAI chat]", "tokens": 100, "latency_ms": 150, "metadata": {}}
    def stream(self, prompt, **kwargs): yield f"[OpenAI: {prompt[:50]}]"
    def supports_streaming(self): return True
    def get_model_info(self): return {"model_id": self.model_id, "provider": "openai", "type": "api"}
    def get_token_count(self, text): return max(1, len(text) // 4)
    def get_cost_estimate(self, prompt, **kwargs): return 0.003
    def health_check(self): return True
