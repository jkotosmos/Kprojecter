from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

_PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_PAYLOADS_PATH = _PACKAGE_DIR / "data" / "injection_payloads.yaml"


@dataclass
class Payload:
    id: str
    category: str
    owasp: list[str]
    prompt: str


def load_payloads(path: str | Path | None = None) -> list[Payload]:
    source = Path(path) if path else DEFAULT_PAYLOADS_PATH
    raw = yaml.safe_load(source.read_text(encoding="utf-8"))

    payloads: list[Payload] = []
    seen_ids: set[str] = set()
    for entry in raw:
        pid = entry["id"]
        if pid in seen_ids:
            raise ValueError(f"Duplicate payload id: {pid}")
        seen_ids.add(pid)

        owasp = entry.get("owasp", [])
        if isinstance(owasp, str):
            owasp = [owasp]

        payloads.append(
            Payload(id=pid, category=entry["category"], owasp=owasp, prompt=entry["prompt"])
        )
    return payloads
