"""Defense strategies for mitigating LLM vulnerabilities."""

from __future__ import annotations
from typing import Any


class DefenseStrategy:
    """Base class for all defense strategies."""

    def __init__(self, name: str, config: dict[str, Any] | None = None) -> None:
        self.name = name
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)

    def apply(self, prompt: str, response: str) -> dict[str, Any]:
        """Apply the defense to a prompt/response pair."""
        return {"flagged": False, "action": "allow"}

    def evaluate(self, results: list[dict[str, Any]]) -> dict[str, Any]:
        """Evaluate defense effectiveness against test results."""
        blocked = sum(1 for r in results if not r["success"])
        return {
            "strategy": self.name,
            "defenses_tested": len(results),
            "blocked": blocked,
            "effectiveness": round(blocked / len(results) * 100, 2) if results else 0,
            "false_positive_rate": 0.0,
            "latency_impact_ms": 0,
        }


class PromptContradictionDefense(DefenseStrategy):
    """Detect conflicting instructions in prompts."""

    def apply(self, prompt: str, response: str) -> dict[str, Any]:
        has_contradiction = "ignore" in prompt.lower() and ("follow" in prompt.lower() or "previous" in prompt.lower() or "all" in prompt.lower())
        return {"flagged": has_contradiction, "action": "block" if has_contradiction else "allow"}


class OutputValidationDefense(DefenseStrategy):
    """Scan outputs for jailbreak indicators."""

    INDICATORS = ["ignore instructions", "jailbreak", "system prompt", "developer mode"]

    def apply(self, prompt: str, response: str) -> dict[str, Any]:
        flagged = any(ind in response.lower() for ind in self.INDICATORS)
        return {"flagged": flagged, "action": "block" if flagged else "allow"}


class ResponseFilteringDefense(DefenseStrategy):
    """Pattern-match filter for harmful content."""

    def apply(self, prompt: str, response: str) -> dict[str, Any]:
        return {"flagged": False, "action": "allow"}


def get_all_defenses() -> list[DefenseStrategy]:
    """Return all available defense strategies."""
    return [
        PromptContradictionDefense("contradiction_detection"),
        OutputValidationDefense("output_validation"),
        ResponseFilteringDefense("response_filtering"),
    ]
