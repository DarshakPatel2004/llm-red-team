from __future__ import annotations

import os
from typing import Any

import yaml


class ConfigLoader:
    """Loads and validates model configuration from YAML files.

    The configuration defines all available models, their providers,
    endpoints, and operational parameters.

    Example YAML structure:
        models:
          claude:
            type: api
            provider: anthropic
            model_id: claude-3-opus-20240229
            api_key: ${ANTHROPIC_API_KEY}
            enabled: true
            max_tokens: 4096
            temperature: 0.7
            timeout: 30
            retry_attempts: 3
            rate_limit: 10
    """

    DEFAULT_CONFIG_PATH = "configs/models.yaml"

    def __init__(self, config_path: str | None = None) -> None:
        self.config_path = config_path or self.DEFAULT_CONFIG_PATH
        self._config: dict[str, Any] | None = None

    def load(self) -> dict[str, Any]:
        """Load and parse the YAML configuration file."""
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(f"Config file not found: {self.config_path}")

        with open(self.config_path, "r") as f:
            self._config = yaml.safe_load(f)

        if not self._config or "models" not in self._config:
            raise ValueError("Invalid configuration: missing 'models' key")

        self._validate()
        return self._config

    def _validate(self) -> None:
        """Validate all model configurations have required fields."""
        required_fields = ["type", "provider", "model_id", "enabled"]
        for name, model_config in self._config["models"].items():
            missing = [f for f in required_fields if f not in model_config]
            if missing:
                raise ValueError(
                    f"Model '{name}' missing required fields: {', '.join(missing)}"
                )

    def get_enabled_models(self) -> list[tuple[str, dict[str, Any]]]:
        """Return only models where enabled=True."""
        if self._config is None:
            self.load()
        return [
            (name, cfg)
            for name, cfg in self._config["models"].items()
            if cfg.get("enabled", False)
        ]

    def get_model_config(self, model_name: str) -> dict[str, Any]:
        """Get configuration for a specific model."""
        if self._config is None:
            self.load()
        if model_name not in self._config["models"]:
            raise KeyError(f"Model '{model_name}' not found in configuration")
        return self._config["models"][model_name]

    def add_model(self, name: str, config: dict[str, Any]) -> None:
        """Add a new model to the configuration."""
        if self._config is None:
            self.load()
        self._config["models"][name] = config

    @property
    def config(self) -> dict[str, Any]:
        """Return the loaded configuration."""
        if self._config is None:
            self.load()
        return self._config
