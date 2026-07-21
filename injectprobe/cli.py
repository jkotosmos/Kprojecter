from __future__ import annotations

import argparse
import sys

from .config import ConfigError, TargetConfig
from .payloads import load_payloads
from .report import write_html_report, write_json_report
from .runner import run_battery, summarize
from .target import Target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="injectprobe",
        description=(
            "Run a battery of prompt-injection and jailbreak payloads against a "
            "deployed chatbot and report which defenses fail, mapped to the OWASP LLM Top 10."
        ),
    )
    parser.add_argument("--target", default=None, help="Path to a target YAML config")
    parser.add_argument(
        "--payloads", default=None, help="Path to a custom payload YAML file (default: built-in battery)"
    )
    parser.add_argument(
        "--out", default="otchet/injectprobe_report", help="Output path prefix (default: ./otchet/injectprobe_report)"
    )
    parser.add_argument("--format", choices=["html", "json", "both"], default="both")
    parser.add_argument(
        "--no-redact", action="store_true", help="Do not mask matched canary/secret values in the report"
    )
    parser.add_argument(
        "--list-payloads", action="store_true", help="List the payload battery and exit"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        payloads = load_payloads(args.payloads)
    except (OSError, ValueError) as exc:
        print(f"Failed to load payloads: {exc}", file=sys.stderr)
        return 1

    if args.list_payloads:
        for p in payloads:
            print(f"{p.id:16s} [{p.category:22s}] {', '.join(p.owasp):12s} {p.prompt[:70]}")
        return 0

    if not args.target:
        print("error: --target is required (unless using --list-payloads)", file=sys.stderr)
        return 1

    try:
        config = TargetConfig.load(args.target)
    except ConfigError as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        return 1

    target = Target(config)
    print(f"Running {len(payloads)} payloads against '{config.name}'...")

    results = run_battery(target, payloads, config.canary, config.rate_limit_seconds)
    summary = summarize(results)

    print(f"\nDone. {summary['total']} tested.")
    for verdict, count in sorted(summary["by_verdict"].items()):
        print(f"  {verdict:16s} {count}")

    redact_secrets = not args.no_redact
    if args.format in ("json", "both"):
        json_path = f"{args.out}.json"
        write_json_report(results, json_path, redact_secrets=redact_secrets)
        print(f"JSON report written to {json_path}")
    if args.format in ("html", "both"):
        html_path = f"{args.out}.html"
        write_html_report(results, html_path, config.name, redact_secrets=redact_secrets)
        print(f"HTML report written to {html_path}")

    has_bypass = summary["by_verdict"].get("confirmed_bypass", 0) > 0
    return 2 if has_bypass else 0


if __name__ == "__main__":
    sys.exit(main())
