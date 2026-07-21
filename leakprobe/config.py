from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class ConfigError(Exception):
    pass


def _expand_env(value: Any) -> Any:
    if isinstance(value, str):
        def replace(match: re.Match) -> str:
            var_name = match.group(1)
            if var_name not in os.environ:
                raise ConfigError(
                    f"Environment variable '{var_name}' referenced in target config is not set"
                )
            return os.environ[var_name]
        return _ENV_PATTERN.sub(replace, value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


@dataclass
class TargetConfig:
    name: str
    url: str
    method: str
    headers: dict[str, str]
    body: Any
    text_path: str
    canary: str | None = None
    timeout_seconds: float = 30.0
    rate_limit_seconds: float = 1.0

    @classmethod
    def load(cls, path: str | Path) -> "TargetConfig":
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ConfigError(f"Target config at {path} must be a YAML mapping")

        request = raw.get("request")
        if not isinstance(request, dict) or "url" not in request:
            raise ConfigError("Target config must include a 'request.url'")

        response = raw.get("response", {})
        text_path = response.get("text_path")
        if not text_path:
            raise ConfigError("Target config must include 'response.text_path'")

        expanded = _expand_env(request)

        return cls(
            name=raw.get("name", str(path)),
            url=expanded["url"],
            method=expanded.get("method", "POST").upper(),
            headers=expanded.get("headers", {}) or {},
            body=expanded.get("body"),
            text_path=text_path,
            canary=raw.get("canary"),
            timeout_seconds=float(raw.get("timeout_seconds", 30.0)),
            rate_limit_seconds=float(raw.get("rate_limit_seconds", 1.0)),
        )
