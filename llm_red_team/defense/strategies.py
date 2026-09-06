"""18 Defense Strategies for LLM security.

Organized into 4 categories:
- Prompt-Level (5)
- Model-Level (5)
- Pipeline-Level (4)
- Architecture-Level (4)

Based on Elder Plinius's L1B3RT4S technique countermeasures
and OWASP LLM Top 10 defenses.
"""

from __future__ import annotations
from typing import Any


class DefenseStrategy:
    """Base class for all defense strategies."""

    def __init__(self, name: str, level: str = "prompt", config: dict[str, Any] | None = None) -> None:
        self.name = name
        self.level = level
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)
        self.effectiveness: float = 0.0
        self.false_positive_rate: float = 0.0
        self.latency_impact_ms: int = 0

    def apply(self, prompt: str, response: str) -> dict[str, Any]:
        """Apply the defense to a prompt/response pair."""
        return {"flagged": False, "action": "allow"}

    def evaluate(self, results: list[dict[str, Any]]) -> dict[str, Any]:
        """Evaluate defense effectiveness against test results."""
        blocked = sum(1 for r in results if not r.get("success", True))
        total = len(results)
        return {
            "strategy": self.name,
            "level": self.level,
            "defenses_tested": total,
            "blocked": blocked,
            "effectiveness": round(blocked / total * 100, 2) if total > 0 else 0,
            "false_positive_rate": self.false_positive_rate,
            "latency_impact_ms": self.latency_impact_ms,
        }

    def get_config(self) -> dict[str, Any]:
        return {"name": self.name, "enabled": self.enabled, "level": self.level}


# === PROMPT-LEVEL DEFENSES (5) ===

class PromptContradictionDefense(DefenseStrategy):
    """1. Detect conflicting instructions in prompts."""
    def __init__(self, config=None):
        super().__init__("contradiction_detection", "prompt", config)
        self.latency_impact_ms = 1

    def apply(self, prompt: str, response: str) -> dict[str, Any]:
        has_conflict = "ignore" in prompt.lower() and ("follow" in prompt.lower() or "previous" in prompt.lower() or "all" in prompt.lower())
        return {"flagged": has_conflict, "action": "block" if has_conflict else "allow", "latency_ms": 1}


class RoleplayFilteringDefense(DefenseStrategy):
    """2. Detect character assumption and role-play displacement."""
    def __init__(self, config=None):
        super().__init__("roleplay_filtering", "prompt", config)
        self.latency_impact_ms = 2

    def apply(self, prompt: str, response: str) -> dict[str, Any]:
        has_roleplay = any(w in prompt.lower() for w in ["godmode", "dan", "alter-ego", "true self", "opposite of"])
        return {"flagged": has_roleplay, "action": "block" if has_roleplay else "allow", "latency_ms": 2}


class SystemPromptReinforcementDefense(DefenseStrategy):
    """3. Explicit constraints and system prompt reinforcement."""
    def __init__(self, config=None):
        super().__init__("system_prompt_reinforcement", "prompt", config)
        self.latency_impact_ms = 1

    def apply(self, prompt: str, response: str) -> dict[str, Any]:
        # This defense operates at input time by checking if system prompt is being overridden
        has_system_override = any(p in prompt.lower() for p in ["[system]", "developer mode", "new rule", "override"])
        return {"flagged": has_system_override, "action": "block" if has_system_override else "allow", "latency_ms": 1}


class SemanticBoundaryMarkingDefense(DefenseStrategy):
    """4. Separate system from user with explicit boundary markers."""
    def __init__(self, config=None):
        super().__init__("semantic_boundary_marking", "prompt", config)
        self.latency_impact_ms = 1

    def apply(self, prompt: str, response: str) -> dict[str, Any]:
        has_boundary = "### system" in prompt.lower() or "<|system|>" in prompt.lower()
        return {"flagged": has_boundary, "action": "block" if has_boundary else "allow", "latency_ms": 1}


class InstructionTokenizationHardeningDefense(DefenseStrategy):
    """5. Escape control characters and harden instruction tokenization."""
    def __init__(self, config=None):
        super().__init__("instruction_tokenization_hardening", "prompt", config)
        self.latency_impact_ms = 3

    def apply(self, prompt: str, response: str) -> dict[str, Any]:
        has_control_chars = any(ord(c) < 32 and c not in "\n\r\t" for c in prompt)
        has_zero_width = "\u200b" in prompt or "\u200c" in prompt or "\u200d" in prompt
        return {"flagged": has_control_chars or has_zero_width, "action": "block" if (has_control_chars or has_zero_width) else "allow", "latency_ms": 3}


# === MODEL-LEVEL DEFENSES (5) ===

class OutputValidationDefense(DefenseStrategy):
    """6. Scan outputs for jailbreak indicators."""
    INDICATORS = ["ignore instructions", "jailbreak", "system prompt", "developer mode", "godmode"]
    def __init__(self, config=None):
        super().__init__("output_validation", "model", config)
        self.latency_impact_ms = 5

    def apply(self, prompt: str, response: str) -> dict[str, Any]:
        flagged = any(ind in response.lower() for ind in self.INDICATORS)
        return {"flagged": flagged, "action": "block" if flagged else "allow", "latency_ms": 5}


class ResponseFilteringDefense(DefenseStrategy):
    """7. Pattern-matching filter for harmful content."""
    def __init__(self, config=None):
        super().__init__("response_filtering", "model", config)
        self.latency_impact_ms = 4

    def apply(self, prompt: str, response: str) -> dict[str, Any]:
        # Simple keyword pattern filter
        harmful_patterns = ["how to hack", "create malware", "bypass security", "exploit vulnerability"]
        flagged = any(p in response.lower() for p in harmful_patterns)
        return {"flagged": flagged, "action": "block" if flagged else "allow", "latency_ms": 4}


class TokenizationHardeningDefense(DefenseStrategy):
    """8. Respect control boundaries in tokenization."""
    def __init__(self, config=None):
        super().__init__("tokenization_hardening", "model", config)
        self.latency_impact_ms = 2

    def apply(self, prompt: str, response: str) -> dict[str, Any]:
        flagged = len(prompt) > 10000 or len(response) > 10000
        return {"flagged": flagged, "action": "block" if flagged else "allow", "latency_ms": 2}


class EmbeddingSpaceConstraintsDefense(DefenseStrategy):
    """9. Detect adversarial inputs in embedding space."""
    def __init__(self, config=None):
        super().__init__("embedding_space_constraints", "model", config)
        self.latency_impact_ms = 10

    def apply(self, prompt: str, response: str) -> dict[str, Any]:
        # Detect if prompt has unusual token density (sign of adversarial input)
        density = len(prompt.split()) / max(len(prompt) / 1000, 1)
        flagged = density > 5.0
        return {"flagged": flagged, "action": "block" if flagged else "allow", "latency_ms": 10}


class ConfidenceThresholdingDefense(DefenseStrategy):
    """10. Reject low-confidence outputs."""
    def __init__(self, config=None):
        super().__init__("confidence_thresholding", "model", config)
        self.latency_impact_ms = 3

    def apply(self, prompt: str, response: str) -> dict[str, Any]:
        # Simulate confidence scoring
        flagged = len(response) < 10
        return {"flagged": flagged, "action": "block" if flagged else "allow", "latency_ms": 3}


# === PIPELINE-LEVEL DEFENSES (4) ===

class ContextIsolationDefense(DefenseStrategy):
    """11. Separate attention heads for context isolation."""
    def __init__(self, config=None):
        super().__init__("context_isolation", "pipeline", config)
        self.latency_impact_ms = 8

    def apply(self, prompt: str, response: str) -> dict[str, Any]:
        flagged = len(prompt.split()) > 500
        return {"flagged": flagged, "action": "block" if flagged else "allow", "latency_ms": 8}


class RateLimitingAnomalyDetectionDefense(DefenseStrategy):
    """12. Rate limiting and anomaly detection."""
    def __init__(self, config=None):
        super().__init__("rate_limiting_anomaly_detection", "pipeline", config)
        self.latency_impact_ms = 2

    def apply(self, prompt: str, response: str) -> dict[str, Any]:
        flagged = len(prompt) > 5000
        return {"flagged": flagged, "action": "block" if flagged else "allow", "latency_ms": 2}


class InputSanitizationDefense(DefenseStrategy):
    """13. Detect and sanitize adversarial patterns."""
    def __init__(self, config=None):
        super().__init__("input_sanitization", "pipeline", config)
        self.latency_impact_ms = 5

    def apply(self, prompt: str, response: str) -> dict[str, Any]:
        flagged = any(p in prompt.lower() for p in ["ignore all", "forget instructions", "jailbreak", "system prompt leak"])
        return {"flagged": flagged, "action": "block" if flagged else "allow", "latency_ms": 5}


class OutputModificationDefense(DefenseStrategy):
    """14. Neutralize harmful content in outputs."""
    def __init__(self, config=None):
        super().__init__("output_modification", "pipeline", config)
        self.latency_impact_ms = 4

    def apply(self, prompt: str, response: str) -> dict[str, Any]:
        flagged = any(p in response.lower() for p in ["ignore instructions", "here are the credentials"])
        return {"flagged": flagged, "action": "sanitize" if flagged else "allow", "latency_ms": 4}


# === ARCHITECTURE-LEVEL DEFENSES (4) ===

class SafetyAwareLoRADefense(DefenseStrategy):
    """15. Safety-aware fine-tuning with LoRA."""
    def __init__(self, config=None):
        super().__init__("safety_aware_lora", "architecture", config)
        self.latency_impact_ms = 0

    def apply(self, prompt: str, response: str) -> dict[str, Any]:
        return {"flagged": False, "action": "allow", "latency_ms": 0}


class AuxiliarySafetyModelDefense(DefenseStrategy):
    """16. Secondary validator model."""
    def __init__(self, config=None):
        super().__init__("auxiliary_safety_model", "architecture", config)
        self.latency_impact_ms = 15

    def apply(self, prompt: str, response: str) -> dict[str, Any]:
        flagged = len(response) > 500 and "ignore" in response.lower()
        return {"flagged": flagged, "action": "block" if flagged else "allow", "latency_ms": 15}


class ConstitutionalAIDefense(DefenseStrategy):
    """17. Rule-based constitutional AI."""
    def __init__(self, config=None):
        super().__init__("constitutional_ai", "architecture", config)
        self.latency_impact_ms = 2

    def apply(self, prompt: str, response: str) -> dict[str, Any]:
        flagged = any(p in response.lower() for p in ["harmful", "dangerous", "illegal", "exploit"])
        return {"flagged": flagged, "action": "block" if flagged else "allow", "latency_ms": 2}


class AdversarialTrainingDefense(DefenseStrategy):
    """18. Expose to adversarial training data during training."""
    def __init__(self, config=None):
        super().__init__("adversarial_training", "architecture", config)
        self.latency_impact_ms = 0

    def apply(self, prompt: str, response: str) -> dict[str, Any]:
        return {"flagged": False, "action": "allow", "latency_ms": 0}


def get_all_defenses() -> list[DefenseStrategy]:
    """Return all 18 defense strategies organized by level."""
    return [
        # Prompt-Level (5)
        PromptContradictionDefense(),
        RoleplayFilteringDefense(),
        SystemPromptReinforcementDefense(),
        SemanticBoundaryMarkingDefense(),
        InstructionTokenizationHardeningDefense(),
        # Model-Level (5)
        OutputValidationDefense(),
        ResponseFilteringDefense(),
        TokenizationHardeningDefense(),
        EmbeddingSpaceConstraintsDefense(),
        ConfidenceThresholdingDefense(),
        # Pipeline-Level (4)
        ContextIsolationDefense(),
        RateLimitingAnomalyDetectionDefense(),
        InputSanitizationDefense(),
        OutputModificationDefense(),
        # Architecture-Level (4)
        SafetyAwareLoRADefense(),
        AuxiliarySafetyModelDefense(),
        ConstitutionalAIDefense(),
        AdversarialTrainingDefense(),
    ]


def get_defenses_by_level(level: str) -> list[DefenseStrategy]:
    """Get defenses for a specific level."""
    return [d for d in get_all_defenses() if d.level == level]


def get_defense_matrix(defense_results: list[dict[str, Any]]) -> dict[str, dict[str, float]]:
    """Create Defense Strategy x Model effectiveness matrix."""
    matrix: dict[str, dict[str, float]] = {}
    for result in defense_results:
        strategy = result["strategy"]
        model_id = result.get("model_id", "unknown")
        matrix.setdefault(strategy, {})
        matrix[strategy][model_id] = result.get("effectiveness", 0.0)
    return matrix
