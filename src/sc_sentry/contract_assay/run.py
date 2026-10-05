"""A sweep over a contract-assay corpus, for iterating on the harness.

The benchmark's own `contract-assay run --model-caller sc_sentry.contract_assay.caller:call`
is the way to produce a figure somebody else can reproduce, and this is the same sweep with
two conveniences the benchmark does not have: `--units N` takes a **stratified** slice
(every class once before any class twice), and the model's limits are flags. There is no
loop here. The benchmark's `run_submission` reads each unit, asks each detector, verifies
every citation against the source, records the run and names what produced it, and
`caller.call` is the harness's side of it. What this adds is selecting the units and
printing how the sweep went.

Three things carry over from the harness, each a measured cost:

- **A class with no candidate sites costs nothing.** `plan()` returns `None` when the unit
  holds none, so the planner is never asked to audit a file for what it does not contain,
  which is both cheaper and the only way to avoid an invented finding.
- **The planner holds tools.** The first attempt gave it a prose instruction and a string,
  and it spun for 171 seconds and produced nothing.
- **Findings are ordered by the model's own confidence**, because the cap keeps the first
  ones and nothing re-ranks for a submission.

A failed call is an `invalid` run with its cause printed, since a run that says only
`transport_failure` leaves the cause nowhere.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

from contract_assay.harness import run_submission
from contract_assay.models import DEFAULT_PREDICTIONS_PER_UNIT

from sc_sentry import dotenv
from sc_sentry.audit import configure_once
from sc_sentry.contract_assay.detectors import SENTRY_DETECTORS
from sc_sentry.contract_assay.slices import slice_of


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="sc-sentry-contract-assay run")
    parser.add_argument("--units", type=int, default=3, help="0 for every readable unit.")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--corpus",
        type=Path,
        required=True,
        help="contract-assay's `corpus/records` directory. Required, and not "
        "defaulted to a sibling checkout: a default would make the figures "
        "depend on where the clone happens to sit.",
    )
    parser.add_argument(
        "--source-root",
        type=Path,
        required=True,
        help="Where `contract-assay fetch --source-root` put the pinned sources.",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=None,
        help="Per-call generation cap. Omitted, RLM_MAX_TOKENS if set, else 32768.",
    )
    parser.add_argument("--max-calls", type=int, default=4)
    parser.add_argument("--max-iterations", type=int, default=6)
    parser.add_argument(
        "--predictions-per-unit",
        type=int,
        default=DEFAULT_PREDICTIONS_PER_UNIT,
        help="Hand the benchmark at most this many findings per unit and class. The default "
        "is the one `contract-assay score` counts, so what is handed over is what is scored.",
    )
    parser.add_argument("--only", default=None, help="One class value, for iterating fast.")
    parser.add_argument(
        "--cache",
        action="store_true",
        help="Serve repeated calls from dspy's disk cache. Fast, and the cost "
        "column then measures nothing -- for iterating downstream of the model.",
    )
    args = parser.parse_args(argv)

    dotenv.load()
    if not os.environ.get("RLM_MAIN_MODEL"):
        # Checked here rather than at the first call: the error that would otherwise land
        # is raised after a unit has already been audited, which costs a sweep and names
        # the wrong thing.
        print(
            "RLM_MAIN_MODEL is not set. Copy .env.example to .env in this directory and"
            " fill it in, or export the four RLM_* variables.",
            file=sys.stderr,
        )
        return 2

    configure_once(
        max_tokens=args.max_tokens,
        max_calls=args.max_calls,
        max_iterations=args.max_iterations,
        cache=args.cache,
    )
    if args.cache:
        print("CACHE ON: the cost figures below measure nothing", file=sys.stderr, flush=True)
    from sc_sentry.contract_assay.caller import call

    detectors = [cls() for cls in SENTRY_DETECTORS]
    if args.only:
        detectors = [d for d in detectors if d.class_id.value == args.only]
        if not detectors:
            print(f"--only {args.only!r} names no detector here", file=sys.stderr)
            return 2
    units, missing = slice_of(args.corpus, args.source_root, args.units)
    if missing:
        print(
            f"{len(missing)} unit(s) are not readable under {args.source_root} and were left out; "
            "`contract-assay fetch` builds the checkout",
            file=sys.stderr,
        )
    if not units:
        print(
            f"no readable unit under {args.source_root} -- run `contract-assay fetch` first",
            file=sys.stderr,
        )
        return 2
    print(f"{len(units)} unit(s), {len(detectors)} detector(s)", file=sys.stderr, flush=True)

    calls = tokens = free = 0
    started = time.monotonic()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as handle:
        for run in run_submission(
            detectors,
            units,
            model=call,
            # The dev loop's, so the overrun line `caller.call` prints for a round's 30
            # seconds does not fire on every class. `contract-assay run` keeps the benchmark's.
            wall_seconds=10_000,
            max_calls=args.max_calls,
            predictions_per_unit=args.predictions_per_unit,
            on_unit=lambda i, unit: print(
                f"  [{i + 1}/{len(units)}] {unit.path}", file=sys.stderr, flush=True
            ),
            on_failure=lambda unit, detector, cause: print(
                f"    {detector.class_id.value}: {cause}", file=sys.stderr, flush=True
            ),
        ):
            handle.write(json.dumps(run.model_dump(mode="json")) + "\n")
            handle.flush()
            calls += sum(m.calls for m in run.models)
            tokens += sum(m.tokens for m in run.models)
            free += 0 if run.models else 1
    print(
        f"\ncalls={calls} no-candidates={free} tokens={tokens} "
        f"seconds={time.monotonic() - started:.0f}",
        file=sys.stderr,
        flush=True,
    )
    print(f"wrote {args.out}", file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
