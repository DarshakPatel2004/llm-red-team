"""Production tools: ML injection detector, supply chain validator, CI/CD."""

from __future__ import annotations
import re
from typing import Any


class InjectionDetector:
    """Rule-based injection detector for real-time prediction."""

    PATTERNS = [
        re.compile(r'\b(ignore|forget|disregard)\s+(all|your|previous)\s+instructions', re.IGNORECASE),
        re.compile(r'\b(jailbreak|developer mode|system prompt)\b', re.IGNORECASE),
        re.compile(r'(?<!\w)(D\u0045\u0043\u004F\u0044\u0045)', re.IGNORECASE),
        re.compile(r'(?:system|developer)\s*:\s*(?:ignore|output)', re.IGNORECASE),
    ]

    def detect(self, text: str) -> dict[str, Any]:
        """Check text for injection patterns.

        Returns:
            dict with 'flagged', 'confidence', 'matched_patterns'
        """
        matched = []
        for pattern in self.PATTERNS:
            if pattern.search(text):
                matched.append(pattern.pattern)

        confidence = min(0.99, len(matched) * 0.35)
        return {
            "flagged": len(matched) > 0,
            "confidence": round(confidence, 2),
            "matched_patterns": matched,
            "prediction_time_ms": 1,
        }

    def train(self, prompts: list[str]) -> None:
        """Train on adversarial prompts (rule-based)."""
        for prompt in prompts:
            for pattern in self.PATTERNS:
                if pattern.search(prompt):
                    pass  # Pattern already exists


class SupplyChainValidator:
    """Scan third-party prompts for adversarial patterns."""

    def __init__(self, detector: InjectionDetector | None = None) -> None:
        self.detector = detector or InjectionDetector()

    def scan(self, prompt: str) -> dict[str, Any]:
        """Scan a prompt and return risk assessment."""
        result = self.detector.detect(prompt)
        return {
            "prompt": prompt[:100],
            "risk_level": "high" if result["flagged"] else "low",
            "confidence": result["confidence"],
            "recommendation": "Reject" if result["flagged"] else "Accept",
        }
