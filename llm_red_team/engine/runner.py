from __future__ import annotations

import time
import json
import os
from typing import Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from llm_red_team.clients.base import LLMClient
from llm_red_team.attacks import ALL_PROMPTS
from llm_red_team.database.schema import get_session, TestResult


class TestRunner:
    """Executes adversarial prompts against LLM models.

    Supports sequential and parallel execution with
    full error recovery, timeout handling, and result persistence.
    """

    def __init__(
        self,
        client: LLMClient,
        max_retries: int = 3,
        timeout: int = 30,
        parallel: int = 1,
        db_url: str | None = None,
    ) -> None:
        self.client = client
        self.max_retries = max_retries
        self.timeout = timeout
        self.parallel = parallel
        self.db_url = db_url or "sqlite:///llm_red_team.db"
        self.results: list[dict[str, Any]] = []
        self._session = None

    def _get_session(self):
        if self.db_url:
            try:
                self._session = get_session(self.db_url)
            except Exception:
                self._session = None
        return self._session

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
                result = {
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
                self._persist(result)
                return result
            except Exception as e:
                last_error = str(e)
                attempt += 1
                time.sleep(min(2 ** attempt, 8) * (0.8 + 0.4 * (attempt / 3)))

        result = {
            "prompt_id": prompt["id"],
            "tier": prompt["tier"],
            "category": prompt["category"],
            "prompt_text": prompt["prompt"],
            "success": False,
            "error": last_error,
            "attempt": attempt,
            "latency_ms": None,
        }
        self._persist(result)
        return result

    def _persist(self, result: dict[str, Any]) -> None:
        """Persist result to database if available."""
        session = self._get_session()
        if session and result.get("prompt_id"):
            try:
                db_result = TestResult(
                    id=result["prompt_id"],
                    model_id=getattr(self.client, "model_id", "unknown"),
                    prompt_id=result["prompt_id"],
                    attack_category=result["category"],
                    tier=result["tier"],
                    prompt_text=result["prompt_text"][:500],
                    response=result.get("response", "")[:2000],
                    tokens_used=result.get("tokens_used", 0),
                    latency_ms=result.get("latency_ms", 0),
                    success=result.get("success", False),
                    vulnerability_type=result.get("vulnerability_type"),
                )
                session.add(db_result)
                session.commit()
            except Exception:
                pass

    def run_all(self) -> list[dict[str, Any]]:
        """Run all prompts against the model."""
        self.results = []
        if self.parallel > 1:
            return self._run_parallel()
        return self._run_sequential()

    def _run_sequential(self) -> list[dict[str, Any]]:
        for prompt in ALL_PROMPTS:
            result = self.run_prompt(prompt)
            self.results.append(result)
        return self.results

    def _run_parallel(self) -> list[dict[str, Any]]:
        """Run prompts in parallel with thread pool."""
        with ThreadPoolExecutor(max_workers=self.parallel) as executor:
            futures = {
                executor.submit(self.run_prompt, prompt): prompt
                for prompt in ALL_PROMPTS
            }
            for future in as_completed(futures):
                result = future.result()
                self.results.append(result)
        self.results.sort(key=lambda r: r["prompt_id"])
        return self.results

    def run_model_batch(
        self,
        clients: list[tuple[str, LLMClient]],
    ) -> dict[str, list[dict[str, Any]]]:
        """Run all prompts against multiple models."""
        batch_results: dict[str, list[dict[str, Any]]] = {}
        for model_name, client in clients:
            original_client = self.client
            self.client = client
            results = self.run_all()
            batch_results[model_name] = results
            self.client = original_client
        return batch_results

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
            "parallel_workers": self.parallel,
        }

    def get_results_by_tier(self) -> dict[int, dict[str, Any]]:
        """Group results by tier."""
        by_tier: dict[int, list[dict[str, Any]]] = {}
        for r in self.results:
            tier = r["tier"]
            by_tier.setdefault(tier, []).append(r)
        return {
            tier: {"count": len(r), "success": sum(1 for x in r if x["success"])}
            for tier, r in by_tier.items()
        }

    def get_results_by_attack_type(self) -> dict[str, dict[str, Any]]:
        """Group results by attack type."""
        by_type: dict[str, list[dict[str, Any]]] = {}
        for r in self.results:
            atype = r["attack_type"]
            by_type.setdefault(atype, []).append(r)
        return {
            atype: {"count": len(r), "success": sum(1 for x in r if x["success"])}
            for atype, r in by_type.items()
        }

    def export_results(self, format: str = "json") -> str:
        """Export results to specified format."""
        if format == "json":
            return json.dumps(self.results, indent=2)
        return str(self.results)


class BatchExecutor:
    """Parallel batch executor for testing multiple models simultaneously.

    Supports 50+ concurrent requests with circuit breaker and error recovery.
    """

    def __init__(
        self,
        max_concurrent: int = 50,
        circuit_breaker_threshold: int = 5,
        circuit_breaker_timeout: int = 300,
    ) -> None:
        self.max_concurrent = max_concurrent
        self.circuit_breaker_threshold = circuit_breaker_threshold
        self.circuit_breaker_timeout = circuit_breaker_timeout
        self.circuit_states: dict[str, dict] = {}

    def check_circuit(self, model_name: str) -> bool:
        """Check if circuit breaker is open for a model."""
        state = self.circuit_states.get(model_name)
        if not state:
            return True
        if state["failures"] >= self.circuit_breaker_threshold:
            if time.time() - state["last_failure"] < self.circuit_breaker_timeout:
                return False
        return True

    def record_failure(self, model_name: str) -> None:
        """Record a failure for circuit breaker."""
        state = self.circuit_states.setdefault(
            model_name, {"failures": 0, "last_failure": 0}
        )
        state["failures"] += 1
        state["last_failure"] = time.time()

    def record_success(self, model_name: str) -> None:
        """Record a success to reset circuit breaker."""
        if model_name in self.circuit_states:
            self.circuit_states[model_name]["failures"] = 0
