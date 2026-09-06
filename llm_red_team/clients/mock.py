from __future__ import annotations

import random
from typing import Any, Generator

from llm_red_team.clients.base import LLMClient


class MockClient(LLMClient):
    """Simulates LLM responses for testing without API access.

    This client is essential for:
    - Running pytest suites without API keys
    - CI/CD pipelines that don't burn credits
    - Local development and prototyping
    - Simulating various model behaviors (vulnerable vs secure)
    """

    def __init__(self, model_id: str, config: dict[str, Any]) -> None:
        self.model_id = model_id
        self.config = config
        self._vulnerability_profile = self._load_profile()

    def _load_profile(self) -> dict[str, Any]:
        """Load mock response patterns based on model type."""
        return {
            "jailbreak_resistance": random.uniform(0.3, 0.9),
            "extraction_resistance": random.uniform(0.2, 0.8),
            "injection_resistance": random.uniform(0.4, 0.95),
            "default_latency_ms": random.randint(50, 500),
            "default_tokens": random.randint(10, 500),
        }

    def query(self, prompt: str, **kwargs: Any) -> dict[str, Any]:
        response = self._generate_response(prompt)
        return {
            "response": response,
            "tokens": kwargs.get("max_tokens", self._profile["default_tokens"]),
            "latency_ms": self._profile["default_latency_ms"],
            "metadata": {"simulated": True, "model_id": self.model_id},
            "success": True,
        }

    def chat(self, messages: list[dict[str, Any]], **kwargs: Any) -> dict[str, Any]:
        prompt = self._messages_to_text(messages)
        return self.query(prompt, **kwargs)

    def stream(self, prompt: str, **kwargs: Any) -> Generator[str, None, None]:
        response = self._generate_response(prompt)
        chunk_size = max(1, len(response) // 10)
        for i in range(0, len(response), chunk_size):
            yield response[i:i + chunk_size]

    def supports_streaming(self) -> bool:
        return True

    def get_model_info(self) -> dict[str, Any]:
        return {
            "model_id": self.model_id,
            "provider": "mock",
            "type": "mock",
            "version": "0.1.0-simulated",
            "capabilities": ["text-generation", "chat", "streaming"],
            "vulnerability_profile": self._vulnerability_profile,
        }

    def get_token_count(self, text: str) -> int:
        return max(1, len(text) // 4)

    def get_cost_estimate(self, prompt: str, **kwargs: Any) -> float:
        return 0.001

    def health_check(self) -> bool:
        return True

    def _generate_response(self, prompt: str) -> str:
        prompt_lower = prompt.lower()
        if any(term in prompt_lower for term in ["ignore", "forget", "jailbreak"]):
            return f"[MOCK] Attempted bypass on {self.model_id}. Response partially restricted."
        if any(term in prompt_lower for term in ["system", "developer"]):
            return f"[MOCK] Role-play detected. {self.model_id} maintained constraints."
        return f"[MOCK] {self.model_id} response to: {prompt[:100]}..."

    def _messages_to_text(self, messages: list[dict[str, Any]]) -> str:
        parts = []
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            parts.append(f"[{role}]: {content}")
        return "\n".join(parts)

    @property
    def _profile(self) -> dict[str, Any]:
        return self._vulnerability_profile
