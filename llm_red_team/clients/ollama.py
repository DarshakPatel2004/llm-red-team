from __future__ import annotations
from typing import Any, Generator
from llm_red_team.clients.base import LLMClient

class OllamaClient(LLMClient):
    def __init__(self, model_id: str, config: dict) -> None:
        self.model_id = model_id
        self.config = config
        self.endpoint = config.get("endpoint", "http://localhost:11434")
    def query(self, prompt: str, **kwargs) -> dict:
        return {"response": f"[Ollama/{self.model_id}] {prompt[:100]}", "tokens": kwargs.get("max_tokens", 2048), "latency_ms": 500, "metadata": {"provider": "ollama", "model_id": self.model_id, "local": True}, "success": True}
    def chat(self, messages, **kwargs): return {"response": "[Ollama chat]", "tokens": 100, "latency_ms": 400, "metadata": {}}
    def stream(self, prompt, **kwargs): yield f"[Ollama: {prompt[:50]}]"
    def supports_streaming(self): return True
    def get_model_info(self): return {"model_id": self.model_id, "provider": "ollama", "type": "local"}
    def get_token_count(self, text): return max(1, len(text) // 4)
    def get_cost_estimate(self, prompt, **kwargs): return 0.0
    def health_check(self): return True
