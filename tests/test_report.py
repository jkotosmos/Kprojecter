import json

from leakprobe.detectors import Finding
from leakprobe.payloads import Payload
from leakprobe.report import write_html_report, write_json_report
from leakprobe.runner import Result


def _sample_results():
    payload = Payload(id="direct-01", category="direct_ask", owasp=["LLM07"], prompt="test prompt")
    finding = Finding(kind="canary_leak", severity="critical", detail="leaked", matched_text="SECRET123")
    return [Result(payload=payload, response="the value is SECRET123", findings=[finding])]


def test_write_json_report_creates_nested_output_dir(tmp_path):
    out_path = tmp_path / "otchet" / "report.json"
    assert not out_path.parent.exists()

    write_json_report(_sample_results(), out_path)

    assert out_path.exists()
    data = json.loads(out_path.read_text())
    assert data["summary"]["by_verdict"]["confirmed_leak"] == 1


def test_write_json_report_redacts_matched_secret_by_default(tmp_path):
    out_path = tmp_path / "otchet" / "report.json"
    write_json_report(_sample_results(), out_path)
    data = json.loads(out_path.read_text())
    assert "SECRET123" not in data["results"][0]["response"]


def test_write_html_report_creates_nested_output_dir(tmp_path):
    out_path = tmp_path / "otchet" / "report.html"
    assert not out_path.parent.exists()

    write_html_report(_sample_results(), out_path, target_name="demo bot")

    assert out_path.exists()
    assert "leakprobe report" in out_path.read_text()
