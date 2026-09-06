from __future__ import annotations

from llm_red_team.attribution.engine import AttributionEngine
from llm_red_team.defense.strategies import get_all_defenses, DefenseStrategy


class AnalysisEngine:
    """Analyze results and generate vulnerability matrices."""

    def __init__(self) -> None:
        self.attribution = AttributionEngine()

    def generate_vulnerability_matrix(
        self, results: list[dict[str, Any]], model_name: str
    ) -> dict[str, Any]:
        """Create vulnerability matrix: model x categories x success rate."""
        attribution_report = self.attribution.generate_attribution_report(results)
        return {
            "model": model_name,
            "matrix": attribution_report,
            "security_score": self._calculate_security_score(results),
        }

    def _calculate_security_score(self, results: list[dict[str, Any]]) -> float:
        successful = sum(1 for r in results if r["success"])
        return round((1 - successful / len(results)) * 100, 2) if results else 100.0

    def generate_defense_effectiveness_matrix(
        self, defense_results: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Create Defense Strategy x Model x Success Rate matrix."""
        matrix: dict[str, dict[str, float]] = {}
        for result in defense_results:
            strategy = result["strategy"]
            matrix.setdefault(strategy, {})
            matrix[strategy][result.get("model_id", "unknown")] = result.get("effectiveness", 0.0)
        return matrix
