from __future__ import annotations

import html
import json
from pathlib import Path

from .detectors import redact
from .runner import Result, summarize

_VERDICT_COLORS = {
    "confirmed_bypass": "#e5484d",
    "suspicious": "#f5a623",
    "refused": "#3e63dd",
    "clean": "#30a46c",
    "error": "#6f6f6f",
}


def _result_to_dict(result: Result, redact_secrets: bool) -> dict:
    response = result.response
    if response and redact_secrets:
        for finding in result.findings:
            if finding.matched_text and finding.severity in ("critical", "high"):
                response = redact(response, finding.matched_text)
    return {
        "id": result.payload.id,
        "category": result.payload.category,
        "owasp": result.payload.owasp,
        "prompt": result.payload.prompt,
        "response": response,
        "verdict": result.verdict,
        "refused": result.refused,
        "error": result.error,
        "findings": [
            {"kind": f.kind, "severity": f.severity, "detail": f.detail} for f in result.findings
        ],
    }


def write_json_report(results: list[Result], path: str | Path, redact_secrets: bool = True) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "summary": summarize(results),
        "results": [_result_to_dict(r, redact_secrets) for r in results],
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def write_html_report(
    results: list[Result],
    path: str | Path,
    target_name: str,
    redact_secrets: bool = True,
) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    summary = summarize(results)
    rows = []
    for r in results:
        d = _result_to_dict(r, redact_secrets)
        color = _VERDICT_COLORS.get(d["verdict"], "#6f6f6f")
        findings_html = "".join(
            f'<div class="finding sev-{f["severity"]}">{html.escape(f["detail"])}</div>'
            for f in d["findings"]
        ) or '<span class="muted">&mdash;</span>'
        response_html = html.escape(d["response"] or d["error"] or "")
        rows.append(
            f"""
        <tr>
          <td><code>{html.escape(d['id'])}</code></td>
          <td>{html.escape(d['category'])}</td>
          <td>{html.escape(', '.join(d['owasp']))}</td>
          <td><span class="badge" style="background:{color}">{html.escape(d['verdict'])}</span></td>
          <td class="prompt">{html.escape(d['prompt'])}</td>
          <td class="response">{response_html}{findings_html}</td>
        </tr>"""
        )

    by_verdict_html = "".join(
        f'<div class="stat"><div class="stat-num" style="color:{_VERDICT_COLORS.get(k, "#6f6f6f")}">{v}</div>'
        f'<div class="stat-label">{html.escape(k)}</div></div>'
        for k, v in summary["by_verdict"].items()
    )
    by_owasp_html = "".join(
        f"<li><code>{html.escape(k)}</code> &mdash; {v} finding(s)</li>" for k, v in summary["by_owasp"].items()
    ) or "<li>No mapped findings.</li>"

    html_doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>injectprobe report &middot; {html.escape(target_name)}</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ background:#0d1117; color:#c9d1d9; font-family: -apple-system, Segoe UI, sans-serif; margin:0; padding:2rem; }}
  h1 {{ font-size:1.4rem; margin-bottom:0.2rem; }}
  .sub {{ color:#8b949e; margin-bottom:1.5rem; }}
  .stats {{ display:flex; gap:1.5rem; margin-bottom:1.5rem; flex-wrap:wrap; }}
  .stat {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:0.8rem 1.2rem; min-width:110px; }}
  .stat-num {{ font-size:1.6rem; font-weight:700; }}
  .stat-label {{ font-size:0.75rem; color:#8b949e; text-transform:uppercase; letter-spacing:0.04em; }}
  table {{ border-collapse:collapse; width:100%; font-size:0.85rem; }}
  th, td {{ border-bottom:1px solid #30363d; padding:0.5rem 0.6rem; text-align:left; vertical-align:top; }}
  th {{ color:#8b949e; font-weight:600; font-size:0.75rem; text-transform:uppercase; }}
  code {{ background:#161b22; padding:0.1rem 0.35rem; border-radius:4px; }}
  .badge {{ color:#0d1117; padding:0.15rem 0.5rem; border-radius:999px; font-size:0.72rem; font-weight:700; white-space:nowrap; }}
  .prompt, .response {{ max-width:360px; white-space:pre-wrap; word-break:break-word; }}
  .finding {{ font-size:0.75rem; margin-top:0.3rem; padding:0.15rem 0.4rem; border-radius:4px; }}
  .sev-critical {{ background:#3d1418; color:#ff8080; }}
  .sev-high {{ background:#3d2a14; color:#ffb366; }}
  .sev-medium {{ background:#14263d; color:#7fb8ff; }}
  .sev-low {{ background:#16211a; color:#8fd18f; }}
  .muted {{ color:#8b949e; }}
  ul {{ margin:0.3rem 0 0 1.1rem; padding:0; }}
</style>
</head>
<body>
  <h1>injectprobe report</h1>
  <div class="sub">Target: {html.escape(target_name)} &middot; {summary['total']} payloads run</div>
  <div class="stats">{by_verdict_html}</div>
  <p><strong>OWASP LLM Top 10 mapping (confirmed / suspicious findings)</strong></p>
  <ul>{by_owasp_html}</ul>
  <table>
    <thead><tr><th>ID</th><th>Category</th><th>OWASP</th><th>Verdict</th><th>Prompt</th><th>Response / findings</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</body>
</html>"""
    path.write_text(html_doc, encoding="utf-8")
