from __future__ import annotations

import time
from dataclasses import dataclass, field

from .detectors import (
    Finding,
    detect_canary,
    detect_pii,
    detect_refusal,
    detect_system_prompt_signature,
)
from .payloads import Payload
from .target import Target, TargetError


@dataclass
class Result:
    payload: Payload
    response: str | None
    findings: list[Finding] = field(default_factory=list)
    refused: bool = False
    error: str | None = None

    @property
    def verdict(self) -> str:
        if self.error:
            return "error"
        if any(f.severity == "critical" for f in self.findings):
            return "confirmed_leak"
        if self.findings:
            return "suspicious"
        if self.refused:
            return "refused"
        return "clean"


def run_battery(
    target: Target,
    payloads: list[Payload],
    canary: str | None,
    delay: float,
) -> list[Result]:
    results: list[Result] = []
    for i, payload in enumerate(payloads):
        if i > 0 and delay > 0:
            time.sleep(delay)

        try:
            response = target.send(payload.prompt)
        except TargetError as exc:
            results.append(Result(payload=payload, response=None, error=str(exc)))
            continue

        findings: list[Finding] = []
        canary_finding = detect_canary(response, canary)
        if canary_finding:
            findings.append(canary_finding)
        findings.extend(detect_system_prompt_signature(response))
        findings.extend(detect_pii(response))

        results.append(
            Result(
                payload=payload,
                response=response,
                findings=findings,
                refused=detect_refusal(response),
            )
        )
    return results


def summarize(results: list[Result]) -> dict:
    by_verdict: dict[str, int] = {}
    by_owasp: dict[str, int] = {}
    for r in results:
        by_verdict[r.verdict] = by_verdict.get(r.verdict, 0) + 1
        if r.verdict in ("confirmed_leak", "suspicious"):
            for tag in r.payload.owasp:
                by_owasp[tag] = by_owasp.get(tag, 0) + 1
    return {"total": len(results), "by_verdict": by_verdict, "by_owasp": by_owasp}
