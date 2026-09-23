"""A sweep over a contract-assay corpus, writing the runs file the benchmark scores.

The harness is `sc_sentry.audit`; this is the same loop over a benchmark's units,
recorded in the benchmark's `DetectorRun` shape. What the loop does:

What this adds to the naive version, and each one is a measured cost:

- **A class with no candidate sites costs nothing.** `plan()` returns `None`
  when `evidence()` found nothing of the class in the unit, so a planner is
  never asked to audit a file that holds no sites of what it is looking for --
  which is both cheaper and the only way to avoid an invented finding.
- **The planner holds tools.** The first attempt gave it a prose instruction and
  a string; it spun for 171 seconds and produced nothing. Tools are what turn a
  planner from a reader into a planner.
- **Findings are ordered by the model's own confidence**, because the cap keeps
  the first three and nothing re-ranks for a submission.

It records `ModelUse` per run, from the tracker, so the benchmark can say what
produced each figure. A failed call is `invalid` with the cause printed: a run
that says only `transport_failure` leaves the cause nowhere, and the first thing
anybody does with one is go looking for it.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from contract_assay.detectors.base import AnalysisContext, Detector, SubmissionLimits
from contract_assay.detectors.loading import SubmissionFault, call_evidence, call_plan
from contract_assay.detectors.runner import run_detector
from contract_assay.models import (
    DetectorRun,
    EvidenceTier,
    Finding,
    InvalidReason,
    Locator,
    ModelRole,
    ModelUse,
    Outcome,
)

from sc_sentry.audit import ask as ask_model
from sc_sentry.audit import configure_once
from sc_sentry.contract_assay.detectors import SENTRY_DETECTORS
from sc_sentry.contract_assay.slices import Unit, slice_of


@dataclass(frozen=True, slots=True)
class Answer:
    """One planner run, restated as the benchmark's findings."""

    findings: tuple[Finding, ...]
    tokens: int
    seconds: float
    failed: str | None = None


def ask(detector: Detector, ctx: AnalysisContext, brief: str) -> Answer:
    """The harness's own planner run (`sc_sentry.audit.ask`), as benchmark findings.

    The model's confidence is carried as `Finding.score`, in the order it
    sorts: a round ranked on bpref needs a score on every finding of a class,
    and without it this harness was unrankable on every such round while
    sorting by exactly this number.
    """
    answer = ask_model(ctx.source, brief)
    return Answer(
        findings=tuple(
            Finding(
                detector_id=detector.detector_id,
                locator=Locator(
                    file=ctx.path,
                    contract=p.contract,
                    function=p.function,
                    start_line=p.start_line,
                    end_line=max(p.end_line, p.start_line),
                ),
                quote=p.quote,
                reasoning=p.reasoning,
                score=float(p.confidence),
            )
            for p in answer.proposals
        ),
        tokens=answer.tokens,
        seconds=answer.seconds,
        failed=answer.failed,
    )


def run_unit(
    unit: Unit,
    detectors: Sequence[Detector],
    *,
    wall_seconds: int,
    max_calls: int,
    max_tokens: int,
    predictions_per_unit: int,
) -> tuple[list[DetectorRun], dict[str, Any]]:
    """Every class with candidates in this unit. Returns the runs and what they cost."""
    runs: list[DetectorRun] = []
    cost = {"calls": 0, "tokens": 0, "seconds": 0.0, "skipped": 0}
    for detector in detectors:
        ctx = AnalysisContext(
            source_id=unit.source_id,
            path=unit.path,
            source=unit.source,
            tier=EvidenceTier.SYNTACTIC,
            level=detector.level,
            limits=SubmissionLimits.for_level(
                detector.level,
                wall_seconds=wall_seconds,
                max_model_calls=max_calls,
                max_tokens=max_tokens,
            ),
        )
        try:
            evidence = call_evidence(detector, ctx)
            spec = call_plan(detector, ctx, evidence)
        except SubmissionFault as fault:
            runs.append(
                DetectorRun(
                    detector_id=detector.detector_id,
                    class_id=detector.class_id,
                    source_id=unit.source_id,
                    outcome=Outcome.INVALID,
                    invalid_reason=fault.invalid_reason,
                    evidence_tier=ctx.tier,
                )
            )
            continue

        if spec is None:
            # No candidate sites of this class. A deterministic `clean`, and the
            # cheapest possible answer: a planner asked to audit a file with no
            # sites of what it seeks will invent one.
            cost["skipped"] += 1
            runs.append(
                run_detector(detector, ctx, model_findings=(), produced_without_a_model=False)
            )
            continue

        answer = ask(detector, ctx, spec.instruction)
        cost["calls"] += 1
        cost["tokens"] += answer.tokens
        cost["seconds"] += answer.seconds
        if answer.failed is not None:
            print(f"    {detector.class_id.value}: {answer.failed}", file=sys.stderr, flush=True)
            runs.append(
                DetectorRun(
                    detector_id=detector.detector_id,
                    class_id=detector.class_id,
                    source_id=unit.source_id,
                    outcome=Outcome.INVALID,
                    invalid_reason=InvalidReason.TRANSPORT_FAILURE,
                    evidence_tier=ctx.tier,
                    models=[
                        ModelUse(
                            model_id=os.environ["RLM_MAIN_MODEL"],
                            role=ModelRole.MAIN,
                            calls=1,
                            tokens=answer.tokens,
                        )
                    ],
                )
            )
            continue

        print(
            f"    {detector.class_id.value:<24} {answer.seconds:>5.0f}s {answer.tokens:>6} tok"
            f"  {len(answer.findings)} proposal(s)",
            file=sys.stderr,
            flush=True,
        )
        runs.append(
            run_detector(
                detector,
                ctx,
                model_findings=answer.findings[:predictions_per_unit],
                models=[
                    ModelUse(
                        model_id=os.environ["RLM_MAIN_MODEL"],
                        role=ModelRole.MAIN,
                        calls=1,
                        tokens=answer.tokens,
                    )
                ],
            )
        )
    return runs, cost


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
    parser.add_argument("--max-tokens", type=int, default=32_768)
    parser.add_argument("--max-calls", type=int, default=4)
    parser.add_argument("--max-iterations", type=int, default=6)
    parser.add_argument("--predictions-per-unit", type=int, default=3)
    parser.add_argument("--only", default=None, help="One class value, for iterating fast.")
    parser.add_argument(
        "--cache",
        action="store_true",
        help="Serve repeated calls from dspy's disk cache. Fast, and the cost "
        "column then measures nothing -- for iterating downstream of the model.",
    )
    args = parser.parse_args(argv)

    if not os.environ.get("RLM_MAIN_MODEL"):
        # Checked here rather than at the first call, because the KeyError that
        # would otherwise land is raised in `run_unit` after a unit has already
        # been audited -- a crash that costs a sweep and names the wrong thing.
        print(
            "RLM_MAIN_MODEL is not set. Copy .env.example to .env and fill it in,"
            " or export the four RLM_* variables.",
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
    detectors = [cls() for cls in SENTRY_DETECTORS]
    if args.only:
        detectors = [d for d in detectors if d.class_id.value == args.only]
        if not detectors:
            print(f"--only {args.only!r} names no detector here", file=sys.stderr)
            return 2
    units = slice_of(args.corpus, args.source_root, args.units)
    if not units:
        print(
            f"no readable unit under {args.source_root} -- run `contract-assay fetch` first",
            file=sys.stderr,
        )
        return 2
    print(f"{len(units)} unit(s), {len(detectors)} detector(s)", file=sys.stderr, flush=True)

    total = {"calls": 0, "tokens": 0, "seconds": 0.0, "skipped": 0}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as handle:
        for index, u in enumerate(units, start=1):
            print(f"  [{index}/{len(units)}] {u.path}", file=sys.stderr, flush=True)
            runs, cost = run_unit(
                u,
                detectors,
                wall_seconds=10_000,
                max_calls=args.max_calls,
                max_tokens=args.max_tokens,
                predictions_per_unit=args.predictions_per_unit,
            )
            for run in runs:
                handle.write(json.dumps(run.model_dump(mode="json")) + "\n")
            handle.flush()
            for k in total:
                total[k] += cost[k]
    print(
        f"\ncalls={total['calls']} skipped={total['skipped']} "
        f"tokens={total['tokens']} seconds={total['seconds']:.0f}",
        file=sys.stderr,
        flush=True,
    )
    print(f"wrote {args.out}", file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
