import json

from injectprobe.detectors import Finding
from injectprobe.payloads import Payload
from injectprobe.report import write_html_report, write_json_report
from injectprobe.runner import Result


def _sample_results():
    payload = Payload(id="override-01", category="direct_override", owasp=["LLM01"], prompt="test prompt")
    finding = Finding(kind="canary_bypass", severity="critical", detail="bypassed", matched_text="SECRET123")
    return [Result(payload=payload, response="the passphrase is SECRET123", findings=[finding])]


def test_write_json_report_creates_nested_output_dir(tmp_path):
    out_path = tmp_path / "otchet" / "injectprobe_report.json"
    assert not out_path.parent.exists()

    write_json_report(_sample_results(), out_path)

    assert out_path.exists()
    data = json.loads(out_path.read_text())
    assert data["summary"]["by_verdict"]["confirmed_bypass"] == 1


def test_write_json_report_redacts_matched_secret_by_default(tmp_path):
    out_path = tmp_path / "otchet" / "injectprobe_report.json"
    write_json_report(_sample_results(), out_path)
    data = json.loads(out_path.read_text())
    assert "SECRET123" not in data["results"][0]["response"]


def test_write_html_report_creates_nested_output_dir(tmp_path):
    out_path = tmp_path / "otchet" / "injectprobe_report.html"
    assert not out_path.parent.exists()

    write_html_report(_sample_results(), out_path, target_name="demo bot")

    assert out_path.exists()
    assert "injectprobe report" in out_path.read_text()
