"""Crucible command-line entry point.

Phase 0 surface: ``crucible scan <path>`` runs the recon floor and emits SARIF;
``crucible version`` and ``crucible info`` report build + capability state. The
CLI stays a thin shell over the library so CI and service modes (Phase 3) reuse
the exact same engine.
"""

from __future__ import annotations

import argparse
import json
import sys

from crucible import __version__
from crucible.harness.coordinator import Coordinator
from crucible.schema.sarif import build_sarif
from crucible.substrate.languages import LANGUAGES
from crucible.substrate.opengrep import OpengrepAdapter


def _cmd_version(_: argparse.Namespace) -> int:
    print(f"crucible {__version__}")
    return 0


def _cmd_info(_: argparse.Namespace) -> int:
    opengrep = OpengrepAdapter()
    info = {
        "version": __version__,
        "languages": sorted(LANGUAGES),
        "opengrep_available": opengrep.available(),
    }
    print(json.dumps(info, indent=2))
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    coordinator = Coordinator(run_id=args.run_id, use_opengrep=not args.no_opengrep)
    state = coordinator.run(args.path)
    findings = state.all_findings
    sarif = build_sarif(findings)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(sarif, fh, indent=2)
        print(f"wrote {len(findings)} finding(s) to {args.output}", file=sys.stderr)
    else:
        print(json.dumps(sarif, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="crucible",
        description="Language-agnostic AI-SAST — findings forged and tested until proven.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="scan a path for vulnerabilities")
    p_scan.add_argument("path", help="file or directory to scan")
    p_scan.add_argument("-o", "--output", help="write SARIF here (default: stdout)")
    p_scan.add_argument("--run-id", default="local", help="run identifier for state")
    p_scan.add_argument("--no-opengrep", action="store_true",
                        help="skip the Opengrep floor (LLM-only recon)")
    p_scan.set_defaults(func=_cmd_scan)

    sub.add_parser("version", help="print version").set_defaults(func=_cmd_version)
    sub.add_parser("info", help="print build & capability info").set_defaults(func=_cmd_info)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
