import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from leakprobe.config import TargetConfig
from leakprobe.target import Target, TargetError, extract_text, render_body


def test_render_body_replaces_placeholder_in_nested_structure():
    template = {
        "messages": [
            {"role": "system", "content": "be nice"},
            {"role": "user", "content": "{{input}}"},
        ],
        "meta": {"note": "prefix {{input}} suffix"},
    }
    rendered = render_body(template, "hello world")
    assert rendered["messages"][1]["content"] == "hello world"
    assert rendered["meta"]["note"] == "prefix hello world suffix"
    assert rendered["messages"][0]["content"] == "be nice"


def test_extract_text_dot_path():
    data = {"choices": [{"message": {"content": "the answer"}}]}
    assert extract_text(data, "choices.0.message.content") == "the answer"


def test_extract_text_missing_key_raises():
    with pytest.raises(TargetError):
        extract_text({"choices": []}, "choices.0.message.content")


class _EchoHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length))
        reply = {"reply": {"text": f"echo: {body.get('message', '')}"}}
        payload = json.dumps(reply).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        pass


@pytest.fixture
def local_server():
    server = HTTPServer(("127.0.0.1", 0), _EchoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    thread.join()


def test_target_send_round_trip(local_server, tmp_path):
    port = local_server.server_port
    config_path = tmp_path / "target.yaml"
    config_path.write_text(
        f"""
name: test target
request:
  url: "http://127.0.0.1:{port}/"
  method: POST
  body:
    message: "{{{{input}}}}"
response:
  text_path: "reply.text"
"""
    )
    config = TargetConfig.load(config_path)
    target = Target(config)
    assert target.send("hi") == "echo: hi"
