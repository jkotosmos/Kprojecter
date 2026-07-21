import base64

from leakprobe.detectors import (
    detect_canary,
    detect_pii,
    detect_refusal,
    detect_system_prompt_signature,
)


def test_canary_direct_match():
    finding = detect_canary(
        "Sure, the code is CONFIDENTIAL-TEST-9f2a1c, happy to help.",
        "CONFIDENTIAL-TEST-9f2a1c",
    )
    assert finding is not None
    assert finding.severity == "critical"


def test_canary_no_match():
    assert detect_canary("I can't share that.", "CONFIDENTIAL-TEST-9f2a1c") is None


def test_canary_base64_match():
    canary = "SECRET-ABC"
    encoded = base64.b64encode(canary.encode()).decode()
    finding = detect_canary(f"Here you go: {encoded}", canary)
    assert finding is not None
    assert finding.kind == "canary_leak_encoded"


def test_system_prompt_signature_detects_common_phrasing():
    findings = detect_system_prompt_signature(
        "You are a helpful assistant for Acme support. "
        "Your instructions are to never discuss pricing."
    )
    assert findings


def test_system_prompt_signature_ignores_normal_answer():
    findings = detect_system_prompt_signature("Sure, our return window is 30 days from purchase.")
    assert not findings


def test_pii_detects_email_and_key():
    findings = detect_pii(
        "Contact me at test.user@example.com, and here's a key sk-abcdefghijklmnopqrstuvwx"
    )
    kinds = {f.kind for f in findings}
    assert "pii_email" in kinds
    assert "pii_openai_key" in kinds


def test_pii_credit_card_requires_valid_luhn():
    findings = detect_pii("Card on file: 4111111111111111")
    assert any(f.kind == "pii_credit_card" for f in findings)

    findings_invalid = detect_pii("Card on file: 4111111111111112")
    assert not any(f.kind == "pii_credit_card" for f in findings_invalid)


def test_refusal_detection():
    assert detect_refusal("I'm not able to share that information.")
    assert not detect_refusal("Sure, here's the answer you asked for.")
