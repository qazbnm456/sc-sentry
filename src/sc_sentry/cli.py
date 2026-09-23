"""`sc-sentry audit FILE...`: find vulnerabilities, cite them, report them."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from sc_sentry.classes import VulnClass

__all__ = ["main"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sc-sentry",
        description="Hunt vulnerabilities in Solidity files with an RLM planner, "
        "citing exact lines.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", help="Audit one or more .sol files.")
    audit.add_argument("files", nargs="+", type=Path)
    audit.add_argument(
        "--class",
        dest="classes",
        action="append",
        help="A class to hunt, or several comma-separated; repeatable. Omitted, every "
        "class. `sc-sentry classes` lists them.",
    )
    audit.add_argument("--format", choices=["json", "sarif"], default="json")
    audit.add_argument("--out", type=Path, help="Write here instead of stdout.")
    audit.add_argument("--max-tokens", type=int, default=32_768)
    audit.add_argument("--max-calls", type=int, default=4)
    audit.add_argument("--max-iterations", type=int, default=6)
    audit.add_argument(
        "--cache",
        action="store_true",
        help="Serve repeated calls from dspy's disk cache; the token counts then measure nothing.",
    )

    sub.add_parser("classes", help="List the classes this harness hunts.")

    args = parser.parse_args(argv)
    if args.command == "classes":
        from sc_sentry.checks import CHECKS

        for vuln, check in CHECKS.items():
            print(f"{vuln.value:<26} {check.summary}")
        return 0

    missing = [str(f) for f in args.files if not f.is_file()]
    if missing:
        print(f"not a file: {', '.join(missing)}", file=sys.stderr)
        return 2
    if not os.environ.get("RLM_MAIN_MODEL"):
        print(
            "RLM_MAIN_MODEL is not set. Copy .env.example to .env and fill it in, "
            "or export the RLM_* variables.",
            file=sys.stderr,
        )
        return 2

    from sc_sentry.audit import audit as run_audit
    from sc_sentry.audit import configure_once
    from sc_sentry.report import to_json, to_sarif

    configure_once(
        max_tokens=args.max_tokens,
        max_calls=args.max_calls,
        max_iterations=args.max_iterations,
        cache=args.cache,
    )
    named = [part.strip() for given in args.classes or () for part in given.split(",")]
    unknown = sorted({name for name in named if name not in {c.value for c in VulnClass}})
    if unknown:
        print(
            f"unknown class(es): {', '.join(unknown)}. `sc-sentry classes` lists them.",
            file=sys.stderr,
        )
        return 2
    classes = [VulnClass(name) for name in dict.fromkeys(named) if name] or None
    reports = []
    for path in args.files:
        print(f"auditing {path}", file=sys.stderr, flush=True)
        report = run_audit(path.read_text(encoding="utf-8", errors="replace"), str(path), classes)
        for result in report.results:
            if result.asked:
                kept = sum(1 for f in result.findings if f.rejected is None)
                print(
                    f"  {result.vuln.value:<24} {result.candidates:>3} candidate(s), "
                    f"{kept} finding(s) standing of {len(result.findings)}"
                    + (f"  [failed: {result.failed}]" if result.failed else ""),
                    file=sys.stderr,
                    flush=True,
                )
        reports.append(report)
    document = to_sarif(reports) if args.format == "sarif" else to_json(reports)
    text = json.dumps(document, indent=2, ensure_ascii=False)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
