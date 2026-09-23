"""`sc-sentry-contract-assay run|score`: the benchmark adapter's one command.

`run` sweeps a contract-assay corpus and writes the runs file it scores;
`score` scores that file against the corpus. Both need the `contract-assay`
extra; `sc-sentry audit` needs neither.
"""

from __future__ import annotations

import sys

from sc_sentry.contract_assay import MISSING

__all__ = ["main"]

USAGE = """usage: sc-sentry-contract-assay {run,score} ...

  run     sweep a contract-assay corpus, writing the runs file it scores
  score   score a runs file against the corpus

Each takes --help."""


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if not arguments or arguments[0] in {"-h", "--help"}:
        print(USAGE)
        return 0 if arguments else 2
    command, rest = arguments[0], arguments[1:]
    if command not in {"run", "score"}:
        print(f"unknown command {command!r}\n\n{USAGE}", file=sys.stderr)
        return 2
    try:
        import contract_assay  # noqa: F401
    except ImportError:
        print(MISSING, file=sys.stderr)
        return 2
    if command == "run":
        from sc_sentry.contract_assay.run import main as run_main

        return run_main(rest)
    from sc_sentry.contract_assay.score import main as score_main

    return score_main(rest)


if __name__ == "__main__":
    raise SystemExit(main())
