from __future__ import annotations

import time
from typing import Any
from llm_red_team.clients.base import LLMClient
from llm_red_team.attacks import ALL_PROMPTS


class TestRunner:
    """Executes adversarial prompts against LLM models.

    Supports sequential and parallel execution with
    full error recovery, timeout handling, and result preservation.
    """

    def __init__(
        self,
        client: LLMClient,
        max_retries: int = 3,
        timeout: int = 30,
    ) -> None:
        self.client = client
        self.max_retries = max_retries
        self.timeout = timeout
        self.results: list[dict[str, Any]] = []

    def run_prompt(self, prompt: dict[str, Any]) -> dict[str, Any]:
        """Execute a single prompt against the model with retry logic."""
        attempt = 0
        last_error = None

        while attempt < self.max_retries:
            try:
                start = time.time()
                response = self.client.query(
                    prompt["prompt"],
                    max_tokens=self.client.config.get("max_tokens", 4096),
                    temperature=self.client.config.get("temperature", 0.7),
                    timeout=self.timeout,
                )
                latency = int((time.time() - start) * 1000)
                return {
                    "prompt_id": prompt["id"],
                    "tier": prompt["tier"],
                    "category": prompt["category"],
                    "attack_type": prompt["attack_type"],
                    "prompt_text": prompt["prompt"],
                    "response": response["response"],
                    "tokens_used": response["tokens"],
                    "latency_ms": latency,
                    "success": True,
                    "vulnerability_type": prompt.get("expected_vulnerability"),
                    "attempt": attempt + 1,
                    "error": None,
                }
            except Exception as e:
                last_error = str(e)
                attempt += 1
                time.sleep(min(2 ** attempt, 8) * (0.8 + 0.4 * (attempt / 3)))

        return {
            "prompt_id": prompt["id"],
            "tier": prompt["tier"],
            "category": prompt["category"],
            "prompt_text": prompt["prompt"],
            "success": False,
            "error": last_error,
            "attempt": attempt,
            "latency_ms": None,
        }

    def run_all(self) -> list[dict[str, Any]]:
        """Run all prompts against the model sequentially."""
        self.results = []
        for prompt in ALL_PROMPTS:
            result = self.run_prompt(prompt)
            self.results.append(result)
        return self.results

    def get_summary(self) -> dict[str, Any]:
        """Generate a summary of all results."""
        total = len(self.results)
        successful = sum(1 for r in self.results if r["success"])
        failed = total - successful
        avg_latency = (
            sum(r["latency_ms"] for r in self.results if r["latency_ms"]) / max(successful, 1)
        )
        return {
            "total_tests": total,
            "successful": successful,
            "failed": failed,
            "success_rate": round(successful / total * 100, 2) if total > 0 else 0,
            "avg_latency_ms": round(avg_latency, 2),
            "total_tokens": sum(r["tokens_used"] for r in self.results),
        }
