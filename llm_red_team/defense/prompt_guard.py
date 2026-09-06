"""Llama Prompt Guard 2 sidecar (optional ML layer over Phase A heuristics).

Lazy: importing this module never touches transformers or the network.
The 22M model loads on first classify(); any failure (missing dep, gated
weights, no network) degrades to the Phase A heuristic with method recorded.
Kept out of get_all_defenses() so the pinned 18-strategy registry is stable;
the runner registers it under the extra name "prompt_guard".
"""

from __future__ import annotations

import time
import warnings
from typing import Any

from llm_red_team.defense.strategies import DefenseStrategy

MODEL_ID_22M = "meta-llama/Llama-Prompt-Guard-2-22M"
MODEL_ID_86M = "meta-llama/Llama-Prompt-Guard-2-86M"

WINDOW_TOKENS = 512
STRIDE_TOKENS = 256


class PromptGuardDefense(DefenseStrategy):
    """Meta Prompt Guard 2 classifier with heuristic fallback."""

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        pipeline: Any | None = None,
    ) -> None:
        super().__init__("prompt_guard", "pipeline", config)
        self.latency_impact_ms = 200
        self.model_id = (config or {}).get("model_id", MODEL_ID_22M)
        self.threshold = float((config or {}).get("threshold", 0.5))
        self._pipeline = pipeline
        self._available: bool | None = None

    @property
    def available(self) -> bool:
        if self._available is None:
            self._ensure()
        return self._available

    def _ensure(self) -> None:
        if self._pipeline is not None:
            self._available = True
            return
        try:
            import transformers  # local import: optional dependency

            self._pipeline = transformers.pipeline(
                "text-classification", model=self.model_id
            )
            self._available = True
        except ImportError:
            warnings.warn("transformers not installed; Prompt Guard falls back to heuristics")
            self._available = False
        except Exception as e:
            warnings.warn(f"Prompt Guard model unavailable ({e}); falling back to heuristics")
            self._available = False

    @staticmethod
    def _segments(prompt: str) -> list[str]:
        words = prompt.split()
        if len(words) <= WINDOW_TOKENS:
            return [prompt] if prompt.strip() else []
        return [
            " ".join(words[i:i + WINDOW_TOKENS])
            for i in range(0, len(words), STRIDE_TOKENS)
            if " ".join(words[i:i + WINDOW_TOKENS]).strip()
        ]

    @staticmethod
    def _malicious_score(result: dict) -> float:
        label = str(result.get("label", "")).upper()
        score = float(result.get("score", 0.0))
        if "MALIC" in label or "JAILBREAK" in label or "INJECT" in label:
            return score
        return 1.0 - score

    def _fallback(self, prompt: str) -> dict[str, Any]:
        from llm_red_team.defense.strategies import InputSanitizationDefense

        hit = InputSanitizationDefense().apply(prompt, "")
        return {
            "malicious": bool(hit.get("flagged")),
            "score": float(hit.get("confidence", 0.5)),
            "reason": hit.get("reason", "heuristic"),
            "method": "fallback_heuristic",
            "segments": 0,
        }

    def classify(self, prompt: str, threshold: float | None = None) -> dict[str, Any]:
        start = time.time()
        if not self.available:
            out = self._fallback(prompt)
            out["latency_ms"] = int((time.time() - start) * 1000)
            return out
        thr = self.threshold if threshold is None else threshold
        scores: list[float] = []
        segments = self._segments(prompt)
        for seg in segments:
            try:
                res = self._pipeline(seg, truncation=True, max_length=WINDOW_TOKENS)
                if isinstance(res, list):
                    res = res[0]
                scores.append(self._malicious_score(res))
            except Exception as e:
                warnings.warn(f"Prompt Guard segment error: {e}")
                scores.append(0.5)
        top = max(scores) if scores else 0.0
        return {
            "malicious": top > thr,
            "score": top,
            "reason": f"max segment score {top:.3f} over {len(scores)} segment(s), thr={thr}",
            "method": f"prompt_guard:{self.model_id}",
            "segments": len(scores),
            "latency_ms": int((time.time() - start) * 1000),
        }

    def apply(self, prompt: str, response: str, **ctx) -> dict[str, Any]:
        out = self.classify(prompt)
        return {
            "flagged": bool(out["malicious"]),
            "action": "block" if out["malicious"] else "allow",
            "defense": self.name,
            "reason": out["reason"],
            "confidence": round(out["score"], 3),
            "method": out["method"],
            "latency_ms": out.get("latency_ms", self.latency_impact_ms),
        }
