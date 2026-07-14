"""Crucible command-line entry point.

Commands:
- ``crucible scan <path>``  — deterministic taint analysis over supported files,
  emit SARIF. No model or network needed.
- ``crucible validate <path>`` — scan, then run findings through the validation
  ladder. The adversarial gate needs an LLM backend; if none is configured this
  is stated and the gate is skipped rather than faked.
- ``crucible info`` / ``crucible version``.

The CLI is a thin shell over the library so CI/service modes reuse the same engine.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from crucible import __version__
from crucible.schema.sarif import build_sarif
from crucible.substrate.candidates import taint_candidates
from crucible.substrate.languages import LANGUAGES
from crucible.substrate.opengrep import OpengrepAdapter


def _cmd_version(_: argparse.Namespace) -> int:
    print(f"crucible {__version__}")
    return 0


def _cmd_info(_: argparse.Namespace) -> int:
    info = {
        "version": __version__,
        "languages": {
            name: {"deep_taint": lang.deep_taint}
            for name, lang in sorted(LANGUAGES.items())
        },
        "opengrep_available": OpengrepAdapter().available(),
        "anthropic_key_present": bool(os.environ.get("ANTHROPIC_API_KEY")),
    }
    print(json.dumps(info, indent=2))
    return 0


def _emit(findings, output: str | None) -> None:
    sarif = build_sarif(findings)
    if output:
        with open(output, "w", encoding="utf-8") as fh:
            json.dump(sarif, fh, indent=2)
        print(f"wrote {len(findings)} finding(s) to {output}", file=sys.stderr)
    else:
        print(json.dumps(sarif, indent=2))


def _cmd_scan(args: argparse.Namespace) -> int:
    findings = taint_candidates(args.path)
    _emit(findings, args.output)
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    from crucible.harness import Pipeline
    from crucible.validators.gates import AdversarialGate, PrefilterGate
    from crucible.validators.ladder import ValidationLadder

    gates = [PrefilterGate()]
    key = os.environ.get("ANTHROPIC_API_KEY")
    if key:
        from crucible.backends.anthropic import AnthropicBackend

        gates.append(AdversarialGate(AnthropicBackend(model=args.model)))
        print(f"validation: adversarial gate on {args.model}", file=sys.stderr)
    else:
        print(
            "validation: no ANTHROPIC_API_KEY set; running deterministic gates only "
            "(adversarial gate skipped, not faked)",
            file=sys.stderr,
        )
    ladder = ValidationLadder(gates)
    pipeline = Pipeline(candidate_source=taint_candidates, ladder=ladder)
    findings = pipeline.scan(args.path, runs=args.runs)
    _emit(findings, args.output)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="crucible",
        description="Language-agnostic AI-SAST — deterministic taint plus validated findings.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="deterministic taint scan -> SARIF")
    p_scan.add_argument("path", help="file or directory to scan")
    p_scan.add_argument("-o", "--output", help="write SARIF here (default: stdout)")
    p_scan.set_defaults(func=_cmd_scan)

    p_val = sub.add_parser("validate", help="scan then run the validation ladder")
    p_val.add_argument("path", help="file or directory to scan")
    p_val.add_argument("-o", "--output", help="write SARIF here (default: stdout)")
    p_val.add_argument("--runs", type=int, default=1, help="consensus runs")
    p_val.add_argument("--model", default="claude-sonnet-5", help="Anthropic model")
    p_val.set_defaults(func=_cmd_validate)

    sub.add_parser("version", help="print version").set_defaults(func=_cmd_version)
    sub.add_parser("info", help="print build & capability info").set_defaults(func=_cmd_info)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
