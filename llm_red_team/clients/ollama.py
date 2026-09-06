from __future__ import annotations
from typing import Any, Generator
import httpx
from llm_red_team.clients.base import LLMClient


class OllamaClient(LLMClient):
    def __init__(self, model_id: str, config: dict) -> None:
        self.model_id = model_id
        self.config = config
        self.endpoint = config.get("endpoint", "http://localhost:11434")
        self.client = httpx.Client(base_url=self.endpoint, timeout=config.get("timeout", 60))

    def query(self, prompt: str, **kwargs) -> dict:
        try:
            resp = self.client.post(
                "/api/generate",
                json={"model": self.model_id, "prompt": prompt, "stream": False, "options": {"temperature": kwargs.get("temperature", 0.7), "num_predict": kwargs.get("max_tokens", 2048)}},
            )
            resp.raise_for_status()
            data = resp.json()
            return {
                "response": data.get("response", ""),
                "tokens": data.get("eval_count", 0) + data.get("prompt_eval_count", 0),
                "latency_ms": data.get("total_duration", 0) // 1_000_000,
                "metadata": {"provider": "ollama", "model_id": self.model_id, "local": True},
                "success": True,
            }
        except Exception as e:
            return {"response": "", "tokens": 0, "latency_ms": 0, "metadata": {}, "success": False, "error": str(e)}

    def chat(self, messages: list[dict], **kwargs) -> dict:
        try:
            resp = self.client.post(
                "/api/chat",
                json={"model": self.model_id, "messages": messages, "stream": False, "options": {"temperature": kwargs.get("temperature", 0.7)}},
            )
            resp.raise_for_status()
            data = resp.json()
            return {"response": data.get("message", {}).get("content", ""), "tokens": data.get("eval_count", 0), "latency_ms": 400, "metadata": {"provider": "ollama", "model_id": self.model_id}}
        except Exception as e:
            return {"response": "", "tokens": 0, "latency_ms": 0, "metadata": {}, "success": False, "error": str(e)}

    def stream(self, prompt: str, **kwargs) -> Generator[str, None, None]:
        try:
            resp = self.client.post(
                "/api/generate",
                json={"model": self.model_id, "prompt": prompt, "stream": True, "options": {"temperature": kwargs.get("temperature", 0.7)}},
            )
            resp.raise_for_status()
            for line in resp.iter_lines():
                if line:
                    yield line
        except Exception:
            yield ""

    def supports_streaming(self) -> bool:
        return True

    def get_model_info(self) -> dict:
        try:
            resp = self.client.get("/api/tags")
            resp.raise_for_status()
            data = resp.json()
            models = [m["name"] for m in data.get("models", [])]
            return {"model_id": self.model_id, "provider": "ollama", "type": "local", "available_models": models}
        except Exception:
            return {"model_id": self.model_id, "provider": "ollama", "type": "local", "available_models": []}

    def get_token_count(self, text: str) -> int:
        try:
            resp = self.client.post("/api/embeddings", json={"model": self.model_id, "prompt": text})
            resp.raise_for_status()
            return resp.json().get("embedding_size", max(1, len(text) // 4))
        except Exception:
            return max(1, len(text) // 4)

    def get_cost_estimate(self, prompt: str, **kwargs) -> float:
        return 0.0

    def health_check(self) -> bool:
        try:
            resp = self.client.get("/api/tags")
            return resp.status_code == 200
        except Exception:
            return False

    def close(self) -> None:
        try:
            self.client.close()
        except Exception:
            pass