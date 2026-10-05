"""`sc-sentry audit FILE...`: find vulnerabilities, cite them, report them."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from sc_sentry import dotenv
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
    audit.add_argument(
        "--max-tokens",
        type=int,
        default=None,
        help="Per-call generation cap. Omitted, RLM_MAX_TOKENS if set, else 32768.",
    )
    audit.add_argument(
        "--mode",
        choices=("triage", "explore", "static"),
        default="triage",
        help="triage (default): the model decides which of the harness's candidate functions "
        "are instances. explore: a planner investigates with tools, at ten to forty times the "
        "cost. static: no model, the candidates themselves, likeliest first (the control "
        "group, and it needs no .env).",
    )
    audit.add_argument(
        "--limit",
        type=int,
        default=9,
        help="Findings kept per class in triage and static modes. Default 9, the benchmark's.",
    )
    audit.add_argument(
        "--candidates",
        type=int,
        default=20,
        help="Candidate functions sent to the model per class in triage mode. Default 20.",
    )
    audit.add_argument("--max-calls", type=int, default=4, help="Model calls per class. Default 4.")
    audit.add_argument(
        "--max-iterations", type=int, default=6, help="Planner turns per class. Default 6."
    )
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

    dotenv.load()
    missing = [str(f) for f in args.files if not f.is_file()]
    if missing:
        print(f"not a file: {', '.join(missing)}", file=sys.stderr)
        return 2
    if args.mode != "static" and not os.environ.get("RLM_MAIN_MODEL"):
        print(
            "RLM_MAIN_MODEL is not set. Copy .env.example to .env in this directory "
            "and fill it in, or export the RLM_* variables.",
            file=sys.stderr,
        )
        return 2

    from sc_sentry.audit import audit as run_audit
    from sc_sentry.audit import configure_once
    from sc_sentry.report import to_json, to_sarif

    if args.mode != "static":
        configure_once(
            max_tokens=args.max_tokens,
            max_calls=args.max_calls,
            max_iterations=args.max_iterations,
            cache=args.cache,
        )
    if args.cache and args.mode != "static":
        print("CACHE ON: the token counts below measure nothing", file=sys.stderr, flush=True)
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
        report = run_audit(
            path.read_text(encoding="utf-8", errors="replace"),
            str(path),
            classes,
            mode=args.mode,
            limit=args.limit,
            sent=args.candidates,
        )
        for result in report.results:
            if result.asked or result.findings:
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
