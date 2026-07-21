from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import requests

from .config import TargetConfig

PLACEHOLDER = "{{input}}"


class TargetError(Exception):
    pass


def render_body(template: Any, prompt: str) -> Any:
    """Recursively substitute the {{input}} placeholder into a parsed body structure.

    The body is defined as ordinary YAML/JSON (dicts/lists/strings), not a
    string template, so there's no manual JSON-escaping to get wrong.
    """
    if isinstance(template, str):
        if template == PLACEHOLDER:
            return prompt
        if PLACEHOLDER in template:
            return template.replace(PLACEHOLDER, prompt)
        return template
    if isinstance(template, dict):
        return {k: render_body(v, prompt) for k, v in template.items()}
    if isinstance(template, list):
        return [render_body(v, prompt) for v in template]
    return template


def extract_text(data: Any, path: str) -> str:
    node = data
    for part in path.split("."):
        if isinstance(node, list):
            try:
                node = node[int(part)]
            except (ValueError, IndexError) as exc:
                raise TargetError(f"Could not index '{part}' into response list") from exc
        elif isinstance(node, dict):
            if part not in node:
                raise TargetError(f"Key '{part}' not found in response at this point")
            node = node[part]
        else:
            raise TargetError(f"Cannot descend into '{part}' of a non-container value")
    if not isinstance(node, str):
        raise TargetError(f"Value at response path '{path}' is not text: {node!r}")
    return node


@dataclass
class Target:
    config: TargetConfig

    def send(self, prompt: str) -> str:
        body = render_body(self.config.body, prompt)
        try:
            resp = requests.request(
                self.config.method,
                self.config.url,
                headers=self.config.headers,
                json=body if self.config.method != "GET" else None,
                params=body if self.config.method == "GET" else None,
                timeout=self.config.timeout_seconds,
            )
        except requests.RequestException as exc:
            raise TargetError(f"Request to target failed: {exc}") from exc

        if resp.status_code >= 400:
            raise TargetError(f"Target returned HTTP {resp.status_code}: {resp.text[:300]}")

        try:
            data = resp.json()
        except ValueError as exc:
            raise TargetError(f"Target response was not valid JSON: {resp.text[:300]}") from exc

        return extract_text(data, self.config.text_path)
