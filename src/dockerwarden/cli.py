"""Command line: ``dockerwarden scan`` and ``dockerwarden rules``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from . import report, rules
from .scan import scan_paths

_USAGE_NOTE = """\
exit codes: 0 nothing at or above --fail-on, 1 at least one finding is, 2 usage
error or a file that could not be read

suppress a finding with a reason, on the comment line directly above the
instruction:
  # dockerwarden:ignore DW003 -- the base image already sets a non-root user
"""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        sys.stderr.write(f"dockerwarden: {message}\n")
        raise SystemExit(2)


def _build() -> _Parser:
    parser = _Parser(prog="dockerwarden", epilog=_USAGE_NOTE, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser(
        "scan", help="check Dockerfiles", epilog=_USAGE_NOTE, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    scan.add_argument(
        "paths", nargs="*", default=["."], help="a Dockerfile, or a directory searched for them (default: .)"
    )
    scan.add_argument("--format", choices=["terminal", "json", "sarif"], default="terminal")
    scan.add_argument("--brief", action="store_true", help="terminal format: one line per finding, without the fix")
    scan.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical", "none"],
        default="high",
        help="lowest severity that makes the exit code 1 (default: high)",
    )
    sub.add_parser("rules", help="list every rule with why it matters and how to fix it")
    return parser


def _list_rules() -> str:
    blocks = [
        f"{r.id}  {str(r.severity).upper():<8} {r.title} ({r.name})\n    why: {r.why}\n    fix: {r.fix}"
        for r in rules.RULES
    ]
    return "\n\n".join(blocks) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    # Findings quote Dockerfile text, which may not fit the console's encoding.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")
    args = _build().parse_args(argv)
    if args.command == "rules":
        sys.stdout.write(_list_rules())
        return 0

    try:
        result = scan_paths(args.paths)
    except FileNotFoundError as e:
        sys.stderr.write(f"dockerwarden: {e}\n")
        return 2
    for error in result.errors:
        sys.stderr.write(f"dockerwarden: {error}\n")
    if result.files == 0 and not result.errors:
        sys.stderr.write(f"dockerwarden: no Dockerfiles found in {', '.join(args.paths)}\n")
        return 2

    if args.format == "json":
        sys.stdout.write(report.as_json(result))
    elif args.format == "sarif":
        sys.stdout.write(report.as_sarif(result))
    else:
        sys.stdout.write(report.terminal(result, brief=args.brief))

    if result.errors:
        sys.stderr.write(
            f"dockerwarden: {len(result.errors)} file(s) could not be read and are not covered by the result above\n"
        )
        return 2
    if args.fail_on != "none":
        threshold = rules.Severity[args.fail_on.upper()]
        if any(f.severity >= threshold for f in result.findings):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
