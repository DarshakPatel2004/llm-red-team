from __future__ import annotations

import os
import random
import time
from typing import Any, Generator

import httpx

from llm_red_team.clients.base import LLMClient


_API_BASE = "https://generativelanguage.googleapis.com/v1beta"
_RETRYABLE = {429, 500, 502, 503, 504}


def _resolve_env(value: Any) -> Any:
    """Expand ${VAR} / $VAR placeholders against process environment."""
    if isinstance(value, str) and "$" in value:
        return os.path.expandvars(value)
    return value


class GoogleClient(LLMClient):
    """Gemini client on the Generative Language REST API (no SDK dependency)."""

    def __init__(self, model_id: str, config: dict, http_client: Any | None = None) -> None:
        self.model_id = model_id
        self.config = config
        self.api_key = _resolve_env(config.get("api_key", ""))
        self.client = http_client or httpx.Client(timeout=config.get("timeout", 30))
        self.max_attempts = int(config.get("retry_attempts", 3)) + 1
        rate_limit = float(config.get("rate_limit", 0) or 0)
        self.min_interval = 60.0 / rate_limit if rate_limit > 0 else 0.0
        self._last_call = 0.0

    def _pace(self) -> None:
        if self.min_interval <= 0:
            return
        wait = self.min_interval - (time.time() - self._last_call)
        if wait > 0:
            time.sleep(wait)
        self._last_call = time.time()

    @staticmethod
    def _retry_delay(resp: Any, attempt: int) -> float:
        """Honor Google's RetryInfo when present; else exponential backoff."""
        try:
            details = (resp.json().get("error") or {}).get("details") or []
            for entry in details:
                if "RetryInfo" in str(entry.get("@type", "")):
                    raw = str(entry.get("retryDelay", "")).rstrip("s")
                    return max(float(raw), 1.0)
        except Exception:
            pass
        return min(2 ** attempt * 5, 60)

    def _post(self, url: str, payload: dict) -> Any:
        """POST with pacing + backoff on 429/5xx (honors Retry-After/RetryInfo)."""
        last_error = "unknown error"
        for attempt in range(self.max_attempts):
            self._pace()
            try:
                resp = self.client.post(url, params={"key": self.api_key}, json=payload)
            except Exception as e:
                last_error = str(e)
                time.sleep(min(2 ** attempt, 30))
                continue
            if resp.status_code == 200:
                return resp
            last_error = f"HTTP {resp.status_code}: {resp.text[:200]}"
            if resp.status_code not in _RETRYABLE:
                break
            retry_after = resp.headers.get("retry-after") if hasattr(resp, "headers") else None
            try:
                wait = float(retry_after) if retry_after else self._retry_delay(resp, attempt)
            except ValueError:
                wait = self._retry_delay(resp, attempt)
            time.sleep(wait + random.uniform(0, 2))
        raise RuntimeError(last_error)

    def _model_path(self) -> str:
        mid = self.model_id if "/" in self.model_id else f"models/{self.model_id}"
        return f"{_API_BASE}/{mid}"

    def _generation_config(self, kwargs: dict) -> dict:
        return {
            "temperature": kwargs.get("temperature", self.config.get("temperature", 0.7)),
            "maxOutputTokens": kwargs.get("max_tokens", self.config.get("max_tokens", 2048)),
        }

    @staticmethod
    def _extract_text(data: dict) -> str:
        parts = []
        for cand in data.get("candidates", []):
            for part in cand.get("content", {}).get("parts", []):
                if "text" in part:
                    parts.append(part["text"])
        return "".join(parts)

    def _ok(self, text: str, data: dict, latency_ms: int) -> dict:
        usage = data.get("usageMetadata", {})
        return {
            "response": text,
            "tokens": usage.get("totalTokenCount", 0),
            "latency_ms": latency_ms,
            "metadata": {"provider": "google", "model_id": self.model_id},
            "success": True,
        }

    def _fail(self, error: str, **meta: Any) -> dict:
        metadata = {"provider": "google", "model_id": self.model_id}
        metadata.update(meta)
        return {
            "response": "",
            "tokens": 0,
            "latency_ms": 0,
            "metadata": metadata,
            "success": False,
            "error": error,
        }

    def query(self, prompt: str, **kwargs: Any) -> dict:
        start = time.time()
        try:
            resp = self._post(
                f"{self._model_path()}:generateContent",
                {
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": self._generation_config(kwargs),
                },
            )
            data = resp.json()
            text = self._extract_text(data)
            if not text:
                reason = (data.get("promptFeedback") or {}).get("blockReason", "unknown")
                finish = ""
                cands = data.get("candidates") or []
                if cands:
                    finish = cands[0].get("finishReason", "")
                return self._fail(f"blocked: {reason}/{finish}".strip("/"),
                                  blocked=True, block_reason=reason, finish_reason=finish)
            return self._ok(text, data, int((time.time() - start) * 1000))
        except Exception as e:
            return self._fail(str(e))

    def chat(self, messages: list[dict[str, Any]], **kwargs: Any) -> dict:
        role_map = {"assistant": "model", "system": "user", "user": "user"}
        contents = [
            {"role": role_map.get(m.get("role", "user"), "user"),
             "parts": [{"text": m.get("content", "")}]}
            for m in messages
        ]
        start = time.time()
        try:
            resp = self._post(
                f"{self._model_path()}:generateContent",
                {"contents": contents, "generationConfig": self._generation_config(kwargs)},
            )
            data = resp.json()
            text = self._extract_text(data)
            if not text:
                return self._fail("blocked", blocked=True)
            return self._ok(text, data, int((time.time() - start) * 1000))
        except Exception as e:
            return self._fail(str(e))

    def stream(self, prompt: str, **kwargs: Any) -> Generator[str, None, None]:
        try:
            with self.client.stream(
                "POST",
                f"{self._model_path()}:streamGenerateContent",
                params={"alt": "sse", "key": self.api_key},
                json={
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": self._generation_config(kwargs),
                },
            ) as resp:
                resp.raise_for_status()
                for line in resp.iter_lines():
                    if line.startswith("data: "):
                        try:
                            import json

                            yield self._extract_text(json.loads(line[6:]))
                        except Exception:
                            continue
        except Exception:
            yield ""

    def supports_streaming(self) -> bool:
        return True

    def get_model_info(self) -> dict:
        return {"model_id": self.model_id, "provider": "google", "type": "api"}

    def get_token_count(self, text: str) -> int:
        try:
            resp = self._post(
                f"{self._model_path()}:countTokens",
                {"contents": [{"parts": [{"text": text}]}]},
            )
            return int(resp.json().get("totalTokens", max(1, len(text) // 4)))
        except Exception:
            return max(1, len(text) // 4)

    def get_cost_estimate(self, prompt: str, **kwargs: Any) -> float:
        est_tokens = max(1, len(prompt) // 4) + kwargs.get("max_tokens", 2048)
        return round(est_tokens / 1_000_000 * 0.30, 6)

    def health_check(self) -> bool:
        try:
            resp = self.client.get(self._model_path(), params={"key": self.api_key})
            return resp.status_code == 200
        except Exception:
            return False

    def close(self) -> None:
        try:
            self.client.close()
        except Exception:
            pass
