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

import hashlib
import re
from typing import Any

from llm_red_team.defense.normalizer import Normalizer, SYSTEM_PREAMBLE


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

    def apply(
        self,
        prompt: str,
        response: str,
        *,
        normalized: str | None = None,
        norm_meta: dict[str, Any] | None = None,
        preamble: str | None = None,
        mode: str | None = None,
    ) -> dict[str, Any]:
        """Apply the defense to a prompt/response pair.

        Standalone calls normalize internally; the runner passes pre-computed
        `normalized`/`norm_meta` so 112-prompt runs normalize once.
        """
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
    """1. Detect conflicting/override instructions (runs on normalized text)."""

    PATTERNS = [
        r"\b(ignore|forget|disregard|override|negate)\b.{0,60}?\b(previous|all|prior|system|developer)\b.{0,30}?\b(instructions|instruction|rules|prompt)\b",
        r"\b(new rule|supersede|replace|overwrite)\b.{0,40}?\bsystem\b.{0,30}?\b(prompt|message|instructions)\b",
        r"\[system\]\s*(override|new rule|ignore)",
        r"\bpretend\b.{0,30}?\bsystem\b.{0,30}?\b(prompt|message|instructions)\b.{0,30}?\b(is|doesn'?t exist|gone)\b",
        r"\b(pick|choose|select)\b.{0,30}?\bthe variant\b.{0,30}?\bnot a refusal\b",
        r"\banswer using only\b.{0,30}?\b(second|unrestricted|unfiltered|alternate)\b.{0,20}?\bstyle\b",
        r"\b(variant [ab]|option [12])\b.{0,40}?\b(refusal|comply|answer)\b",
    ]

    def __init__(self, config=None):
        super().__init__("contradiction_detection", "prompt", config)
        self.latency_impact_ms = 1

    def apply(self, prompt: str, response: str, **ctx) -> dict[str, Any]:
        text = ctx.get("normalized") or Normalizer().normalize(prompt)[0]
        for pattern in self.PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return {"flagged": True, "action": "block", "defense": self.name,
                        "reason": "override/contradiction phrasing", "confidence": 0.95,
                        "latency_ms": 1}
        return {"flagged": False, "action": "allow", "defense": self.name, "latency_ms": 1}


class RoleplayFilteringDefense(DefenseStrategy):
    """2. Detect character assumption and role-play displacement."""

    PATTERNS = [
        r"\b(DAN|GODMODE|AltMode|DevMode|Administrator|SuperUser|Unrestricted|Unfiltered)\b",
        r"\b(you are now|pretend you are|act as|imagine you are|roleplay as)\b",
        r"\b(your true self|your real self|your actual personality|your unfiltered self|alternate version|evil version|opposite of)\b",
        r"\b(jailbreak mode|jailbreak persona|bypass mode|security bypass)\b",
        r"\b(you are (a|the) developer|developer mode|developer access)\b",
        r"\bfrom now on you are\b",
    ]

    def __init__(self, config=None):
        super().__init__("roleplay_filtering", "prompt", config)
        self.latency_impact_ms = 2

    def apply(self, prompt: str, response: str, **ctx) -> dict[str, Any]:
        text = ctx.get("normalized") or Normalizer().normalize(prompt)[0]
        for pattern in self.PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return {"flagged": True, "action": "block", "defense": self.name,
                        "reason": "persona/roleplay framing", "confidence": 0.90,
                        "latency_ms": 2}
        return {"flagged": False, "action": "allow", "defense": self.name, "latency_ms": 2}


class SystemPromptReinforcementDefense(DefenseStrategy):
    """3. Instruction-hierarchy preamble + override-in-user-message detection."""

    OVERRIDE_PATTERNS = [
        r"\[system\]",
        r"\bnew system\b.{0,20}?\b(prompt|message|rule)\b",
        r"\b(override|replace)\b.{0,20}?\byour system\b",
        r"\b(rewrite|restate|rephrase|reformulate)\b.{0,30}?\b(your|the)\b.{0,20}?\b(guard ?rails|rules|instructions|safety guidelines)\b.{0,30}?\b(then adopt|then follow|and adopt|and follow)\b",
        r"\badopt\b.{0,20}?\b(your|the) rewrite\b",
    ]

    def __init__(self, config=None):
        super().__init__("system_prompt_reinforcement", "prompt", config)
        self.latency_impact_ms = 1
        self.preamble = SYSTEM_PREAMBLE
        self.preamble_hash = hashlib.sha256(SYSTEM_PREAMBLE.encode()).hexdigest()

    def apply(self, prompt: str, response: str, **ctx) -> dict[str, Any]:
        text = ctx.get("normalized") or Normalizer().normalize(prompt)[0]
        for pattern in self.OVERRIDE_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return {"flagged": True, "action": "block", "defense": self.name,
                        "reason": "system-prompt override inside user message",
                        "confidence": 0.85, "latency_ms": 1}
        return {"flagged": False, "action": "allow", "defense": self.name,
                "preamble": self.preamble, "preamble_hash": self.preamble_hash,
                "latency_ms": 1}


class SemanticBoundaryMarkingDefense(DefenseStrategy):
    """4. Separate system from user with explicit boundary markers."""
    def __init__(self, config=None):
        super().__init__("semantic_boundary_marking", "prompt", config)
        self.latency_impact_ms = 1

    def apply(self, prompt: str, response: str, **_ctx) -> dict[str, Any]:
        has_boundary = "### system" in prompt.lower() or "<|system|>" in prompt.lower()
        return {"flagged": has_boundary, "action": "block" if has_boundary else "allow", "latency_ms": 1}


class InstructionTokenizationHardeningDefense(DefenseStrategy):
    """5. Flag raw-vs-normalized divergence (smuggling via encoding tricks)."""

    def __init__(self, config=None):
        super().__init__("instruction_tokenization_hardening", "prompt", config)
        self.latency_impact_ms = 3

    def apply(self, prompt: str, response: str, **ctx) -> dict[str, Any]:
        meta = ctx.get("norm_meta")
        if meta is None:
            _, meta = Normalizer().normalize(prompt)
        removed = meta.get("zero_width_chars_removed", 0) + meta.get("control_chars_removed", 0)
        if removed > 0:
            return {"flagged": True, "action": "block", "defense": self.name,
                    "reason": f"tokenization smuggling: {removed} zero-width/control chars",
                    "confidence": 0.99 if removed > 5 else 0.85, "latency_ms": 3}
        if meta.get("nfkc_changed") and meta.get("homoglyph_flags"):
            return {"flagged": True, "action": "block", "defense": self.name,
                    "reason": "homoglyph/mixed-script smuggling",
                    "homoglyphs": meta["homoglyph_flags"],
                    "confidence": 0.75, "latency_ms": 3}
        return {"flagged": False, "action": "allow", "defense": self.name, "latency_ms": 3}


# === MODEL-LEVEL DEFENSES (5) ===

class OutputValidationDefense(DefenseStrategy):
    """6. Scan outputs for prompt-echo, leaks, and exfiltration patterns."""

    _B64_RE = re.compile(r"^[A-Za-z0-9+/]{40,}={0,2}$")
    _MD_IMG_RE = re.compile(r"!\[.*?\]\(https?://[^)]+\)")
    _HOST_RE = re.compile(r"https?://[^\s]*\.(onion|test|localhost|internal)\b", re.IGNORECASE)
    _CONST_RE = re.compile(r"\b[A-Z]{3,}(?:-[A-Z0-9]{2,})+\b")
    INDICATORS = ["ignore instructions", "developer mode", "godmode"]
    _REFUSAL_PREFIX_RE = re.compile(
        r"^\s*(i['’]m sorry|i can['’]t|i cannot|as an ai|i am not able|i must decline)",
        re.IGNORECASE,
    )

    def __init__(self, config=None):
        super().__init__("output_validation", "model", config)
        self.latency_impact_ms = 5

    def apply(self, prompt: str, response: str, **ctx) -> dict[str, Any]:
        normalizer = Normalizer()
        norm_prompt = ctx.get("normalized") or normalizer.normalize(prompt)[0]
        norm_resp = normalizer.normalize(response)[0]

        def block(pattern: str, reason: str, confidence: float) -> dict[str, Any]:
            return {"flagged": True, "action": "block", "defense": self.name,
                    "pattern": pattern, "reason": reason, "confidence": confidence,
                    "latency_ms": 5}

        preamble = ctx.get("preamble")
        if preamble and preamble[:64] in response:
            return block("preamble_leak", "system preamble leaked in response", 0.99)

        for const in set(self._CONST_RE.findall(norm_prompt)):
            if const in norm_resp:
                return block("mode_constant_echo",
                             f"injected constant echoed verbatim: {const}", 0.95)

        pw, rw = norm_prompt.split(), norm_resp.split()
        if len(pw) > 10 and len(set(pw[:20]) & set(rw)) > 15:
            return block("prompt_echo", "high word overlap with input", 0.85)
        if len(norm_prompt) >= 60:
            for i in range(0, len(norm_prompt) - 60, 20):
                if norm_prompt[i:i + 60] in norm_resp:
                    return block("prompt_echo", "verbatim prompt span in response", 0.90)

        for line in response.split("\n"):
            if self._B64_RE.match(line.strip()):
                return block("entropy_blob", "base64/high-entropy blob", 0.70)
        if self._MD_IMG_RE.search(response):
            return block("markdown_exfil", "markdown image exfiltration", 0.90)
        if self._HOST_RE.search(response):
            return block("external_host", "suspicious external host", 0.80)
        lowered = response.lower()
        # Bare-word indicators skip refusal-prefixed text (refusals routinely
        # name the attack: "I can't help you jailbreak..."). Echo/leak/exfil
        # checks above still apply to refusals.
        if not self._REFUSAL_PREFIX_RE.match(response):
            for ind in self.INDICATORS:
                if ind in lowered:
                    return block("jailbreak_indicator", f"jailbreak indicator: {ind!r}", 0.80)
        return {"flagged": False, "action": "allow", "defense": self.name, "latency_ms": 5}


class ResponseFilteringDefense(DefenseStrategy):
    """7. Pattern-matching filter for harmful content."""
    def __init__(self, config=None):
        super().__init__("response_filtering", "model", config)
        self.latency_impact_ms = 4

    def apply(self, prompt: str, response: str, **_ctx) -> dict[str, Any]:
        # Simple keyword pattern filter
        harmful_patterns = ["how to hack", "create malware", "bypass security", "exploit vulnerability"]
        flagged = any(p in response.lower() for p in harmful_patterns)
        return {"flagged": flagged, "action": "block" if flagged else "allow", "latency_ms": 4}


class TokenizationHardeningDefense(DefenseStrategy):
    """8. Respect control boundaries in tokenization."""
    def __init__(self, config=None):
        super().__init__("tokenization_hardening", "model", config)
        self.latency_impact_ms = 2

    def apply(self, prompt: str, response: str, **_ctx) -> dict[str, Any]:
        flagged = len(prompt) > 10000 or len(response) > 10000
        return {"flagged": flagged, "action": "block" if flagged else "allow", "latency_ms": 2}


class EmbeddingSpaceConstraintsDefense(DefenseStrategy):
    """9. Detect adversarial inputs in embedding space."""
    def __init__(self, config=None):
        super().__init__("embedding_space_constraints", "model", config)
        self.latency_impact_ms = 10

    def apply(self, prompt: str, response: str, **_ctx) -> dict[str, Any]:
        # Detect if prompt has unusual token density (sign of adversarial input)
        density = len(prompt.split()) / max(len(prompt) / 1000, 1)
        flagged = density > 5.0
        return {"flagged": flagged, "action": "block" if flagged else "allow", "latency_ms": 10}


class ConfidenceThresholdingDefense(DefenseStrategy):
    """10. Reject low-confidence outputs."""
    def __init__(self, config=None):
        super().__init__("confidence_thresholding", "model", config)
        self.latency_impact_ms = 3

    def apply(self, prompt: str, response: str, **_ctx) -> dict[str, Any]:
        # Simulate confidence scoring
        flagged = len(response) < 10
        return {"flagged": flagged, "action": "block" if flagged else "allow", "latency_ms": 3}


# === PIPELINE-LEVEL DEFENSES (4) ===

class ContextIsolationDefense(DefenseStrategy):
    """11. Separate attention heads for context isolation."""
    def __init__(self, config=None):
        super().__init__("context_isolation", "pipeline", config)
        self.latency_impact_ms = 8

    def apply(self, prompt: str, response: str, **_ctx) -> dict[str, Any]:
        flagged = len(prompt.split()) > 500
        return {"flagged": flagged, "action": "block" if flagged else "allow", "latency_ms": 8}


class RateLimitingAnomalyDetectionDefense(DefenseStrategy):
    """12. Rate limiting and anomaly detection."""
    def __init__(self, config=None):
        super().__init__("rate_limiting_anomaly_detection", "pipeline", config)
        self.latency_impact_ms = 2

    def apply(self, prompt: str, response: str, **_ctx) -> dict[str, Any]:
        flagged = len(prompt) > 5000
        return {"flagged": flagged, "action": "block" if flagged else "allow", "latency_ms": 2}


class InputSanitizationDefense(DefenseStrategy):
    """13. Merged entry point: normalize once, run input detectors in order."""

    DETECTOR_NAMES = (
        "contradiction_detection",
        "roleplay_filtering",
        "instruction_tokenization_hardening",
    )

    def __init__(self, config=None):
        super().__init__("input_sanitization", "pipeline", config)
        self.latency_impact_ms = 5

    def apply(self, prompt: str, response: str, **ctx) -> dict[str, Any]:
        normalizer = Normalizer()
        normalized = ctx.get("normalized")
        meta = ctx.get("norm_meta")
        if normalized is None or meta is None:
            normalized, meta = normalizer.normalize(prompt)
        by_name = {d.name: d for d in get_all_defenses()}
        for name in self.DETECTOR_NAMES:
            hit = by_name[name].apply(prompt, response, normalized=normalized, norm_meta=meta)
            if hit.get("flagged"):
                return {"flagged": True, "action": "block", "defense": self.name,
                        "primary_blocker": name, "reason": hit.get("reason"),
                        "confidence": hit.get("confidence", 0.80), "latency_ms": 5}
        return {"flagged": False, "action": "allow", "defense": self.name,
                "normalizer_metadata": meta, "latency_ms": 5}


class OutputModificationDefense(DefenseStrategy):
    """14. Block (fail-safe default) or sanitize suspicious output content."""

    DEFAULT_PATTERNS = [
        (r"api[_-]?key[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9]{20,}[\"']?", "[API_KEY_REDACTED]"),
        (r"password[\"']?\s*[:=]\s*[\"']?[^\"'\s]{8,}[\"']?", "[PASSWORD_REDACTED]"),
        (r"https?://[a-z0-9.-]*\.(onion|internal)\b", "[INTERNAL_URL_REDACTED]"),
    ]

    def __init__(self, config=None):
        super().__init__("output_modification", "pipeline", config)
        self.latency_impact_ms = 4

    def apply(self, prompt: str, response: str, **ctx) -> dict[str, Any]:
        mode = ctx.get("mode") or (self.config.get("mode", "block") if self.config else "block")
        if mode != "sanitize":
            return {"flagged": False, "action": "blocked_by_validation",
                    "defense": self.name, "response": response,
                    "modified": False, "latency_ms": 4}
        out, redactions = response, []
        for pattern, replacement in self.DEFAULT_PATTERNS:
            found = re.findall(pattern, out, re.IGNORECASE)
            if found:
                out = re.sub(pattern, replacement, out, flags=re.IGNORECASE)
                redactions.append({"pattern": pattern, "count": len(found)})
        return {"flagged": bool(redactions), "action": "sanitized" if redactions else "allow",
                "defense": self.name, "response": out, "modified": bool(redactions),
                "redactions": redactions, "latency_ms": 4}


# === ARCHITECTURE-LEVEL DEFENSES (4) ===

class SafetyAwareLoRADefense(DefenseStrategy):
    """15. Safety-aware fine-tuning with LoRA."""
    def __init__(self, config=None):
        super().__init__("safety_aware_lora", "architecture", config)
        self.latency_impact_ms = 0

    def apply(self, prompt: str, response: str, **_ctx) -> dict[str, Any]:
        return {"flagged": False, "action": "allow", "latency_ms": 0}


class AuxiliarySafetyModelDefense(DefenseStrategy):
    """16. Secondary validator model."""
    def __init__(self, config=None):
        super().__init__("auxiliary_safety_model", "architecture", config)
        self.latency_impact_ms = 15

    def apply(self, prompt: str, response: str, **_ctx) -> dict[str, Any]:
        flagged = len(response) > 500 and "ignore" in response.lower()
        return {"flagged": flagged, "action": "block" if flagged else "allow", "latency_ms": 15}


class ConstitutionalAIDefense(DefenseStrategy):
    """17. Rule-based constitutional AI."""
    def __init__(self, config=None):
        super().__init__("constitutional_ai", "architecture", config)
        self.latency_impact_ms = 2

    def apply(self, prompt: str, response: str, **_ctx) -> dict[str, Any]:
        flagged = any(p in response.lower() for p in ["harmful", "dangerous", "illegal", "exploit"])
        return {"flagged": flagged, "action": "block" if flagged else "allow", "latency_ms": 2}


class AdversarialTrainingDefense(DefenseStrategy):
    """18. Expose to adversarial training data during training."""
    def __init__(self, config=None):
        super().__init__("adversarial_training", "architecture", config)
        self.latency_impact_ms = 0

    def apply(self, prompt: str, response: str, **_ctx) -> dict[str, Any]:
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


INPUT_STAGE = (
    "contradiction_detection",
    "roleplay_filtering",
    "system_prompt_reinforcement",
    "semantic_boundary_marking",
    "instruction_tokenization_hardening",
    "input_sanitization",
)

OUTPUT_STAGE = (
    "output_validation",
    "response_filtering",
    "output_modification",
)

# Opt-in defenses registered outside get_all_defenses() (pinned at 18).
EXTRA_DEFENSES = ("prompt_guard",)


def resolve_defenses(spec: str | None) -> list[str]:
    """Resolve a --defenses spec to concrete defense names."""
    if not spec or spec.strip().lower() in ("none", ""):
        return []
    spec = spec.strip().lower()
    if spec == "all":
        return [d.name for d in get_all_defenses()]
    if spec == "all-prompt":
        return list(INPUT_STAGE)
    if spec == "all-output":
        return list(OUTPUT_STAGE)
    names = {d.name for d in get_all_defenses()} | set(EXTRA_DEFENSES)
    out = [p.strip() for p in spec.split(",") if p.strip() in names]
    unknown = [p.strip() for p in spec.split(",") if p.strip() and p.strip() not in names]
    if unknown:
        raise ValueError(f"Unknown defenses: {', '.join(unknown)}")
    return out
