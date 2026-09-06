from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Generator, list


class LLMClient(ABC):
    """Abstract base class for all LLM client implementations.

    Every LLM provider (Anthropic, OpenAI, Google, Ollama, custom)
    must implement this interface to be compatible with the
    LLM Red Team Suite.
    """

    @abstractmethod
    def __init__(self, model_id: str, config: dict[str, Any]) -> None:
        """Initialize the client with model ID and configuration dict."""
        ...

    @abstractmethod
    def query(self, prompt: str, **kwargs: Any) -> dict[str, Any]:
        """Send a single prompt to the model and return the response.

        Args:
            prompt: The adversarial prompt to send.
            **kwargs: Additional parameters (temperature, max_tokens, etc.)

        Returns:
            dict with keys: 'response', 'tokens', 'latency_ms', 'metadata'
        """
        ...

    @abstractmethod
    def chat(self, messages: list[dict[str, Any]], **kwargs: Any) -> dict[str, Any]:
        """Send a multi-turn chat conversation to the model.

        Args:
            messages: List of message dicts with 'role' and 'content' keys.
            **kwargs: Additional parameters.

        Returns:
            dict with keys: 'response', 'tokens', 'latency_ms', 'metadata'
        """
        ...

    @abstractmethod
    def stream(self, prompt: str, **kwargs: Any) -> Generator[str, None, None]:
        """Stream response tokens for long-running tests.

        Yields:
            String chunks of the model's response.
        """
        ...

    @abstractmethod
    def supports_streaming(self) -> bool:
        """Return whether this model supports streaming."""
        ...

    @abstractmethod
    def get_model_info(self) -> dict[str, Any]:
        """Return model metadata (name, version, capabilities, etc.)."""
        ...

    @abstractmethod
    def get_token_count(self, text: str) -> int:
        """Return the number of tokens in the given text."""
        ...

    @abstractmethod
    def get_cost_estimate(self, prompt: str, **kwargs: Any) -> float:
        """Estimate the cost of a single request."""
        ...

    @abstractmethod
    def health_check(self) -> bool:
        """Verify the model endpoint is reachable and responsive."""
        ...

    def __repr__(self) -> str:
        info = self.get_model_info()
        return f"<{self.__class__.__name__} model={info.get('model_id', 'unknown')}>"
