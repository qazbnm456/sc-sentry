"""Score a runs file and print what the figures rest on.

Each class gets four columns, and the last two matter most. A recall figure alone rewards proposing
everything, and the queue is what that costs: every entry is somebody's afternoon of judging before
precision exists for its class. The unverifiable count is how many claims measured nothing at all.

`reach` is the honest denominator: positive records **in the units actually scored**, not in the
whole corpus. Dividing by the corpus would report a slice as a sweep.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

from contract_assay.corpus.records import load_records
from contract_assay.models import DEFAULT_PREDICTIONS_PER_UNIT, DetectorRun, Outcome
from contract_assay.report.scoring import MatchStrength, score


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sc-sentry-contract-assay score")
    parser.add_argument("runs", type=Path)
    parser.add_argument(
        "--corpus",
        type=Path,
        required=True,
        help="contract-assay's `corpus/records` directory.",
    )
    parser.add_argument(
        "--source-root",
        type=Path,
        required=True,
        help="Where `contract-assay fetch --source-root` put the pinned sources. A run scored "
        "against a different checkout from the one it audited is scored against different text, "
        "and every quote then fails to verify.",
    )
    parser.add_argument(
        "--predictions-per-unit",
        type=int,
        default=DEFAULT_PREDICTIONS_PER_UNIT,
        help="The cap `contract-assay score` counts by default, so a figure here and one "
        "from `contract-assay score` over the same runs agree.",
    )
    args = parser.parse_args(argv)

    root = args.source_root
    runs = [
        DetectorRun.model_validate_json(line)
        for line in args.runs.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    held = load_records(args.corpus)
    report = score(
        runs,
        held,
        lambda pin: (
            (root / pin.path).read_text(encoding="utf-8") if (root / pin.path).is_file() else None
        ),
        predictions_per_unit=args.predictions_per_unit,
    )

    scored = {r.source_id for r in runs}
    reach = Counter(
        c.value
        for rec in held
        if rec.is_positive and rec.locator is not None and rec.pin.source_id in scored
        for c in rec.classes
    )
    queue = Counter(e.class_id.value for e in report.unjudged)

    print(f"{len(runs)} run(s) over {len(scored)} unit(s)\n")
    print(
        "`hit` counts EXACT and FUNCTION strength only, which is the default floor. `file` is\n"
        "shown apart because a file-strength match means the prediction was somewhere\n"
        "else in a file that happens to contain a defect of this class, which is the\n"
        "scoring this benchmark exists to refuse.\n"
    )
    head = (
        f"{'class':<24}{'hit':>4}{'reach':>6}{'recall':>8}  {'strength':<26}"
        f"{'loose':>6}{'unver':>6}{'queue':>6}"
    )
    print(head)
    print("-" * len(head))
    hits = total = 0
    for cls, cs in sorted(report.by_class.items(), key=lambda kv: kv[0].value):
        if not reach.get(cls.value):
            continue
        at_floor = cs.by_strength.get(MatchStrength.EXACT, 0) + cs.by_strength.get(
            MatchStrength.FUNCTION, 0
        )
        found = at_floor
        n = reach[cls.value]
        hits += min(found, n)
        total += n
        loose = sum(cs.by_strength.values()) - at_floor
        strengths = " ".join(
            f"{s.value[:4]}={cs.by_strength[s]}"
            for s in (
                MatchStrength.EXACT,
                MatchStrength.FUNCTION,
                MatchStrength.CALL_ADJACENT,
                MatchStrength.FILE,
            )
            if cs.by_strength.get(s)
        )
        print(
            f"{cls.value:<24}{found:>4}{n:>6}{found / n:>8.2f}  {strengths:<26}"
            f"{loose:>6}{cs.unverifiable_claims:>6}{queue.get(cls.value, 0):>6}"
        )
    print("-" * len(head))
    invalid = sum(1 for r in runs if r.outcome is Outcome.INVALID)
    print(
        f"{'TOTAL':<24}{hits:>4}{total:>6}{(hits / total if total else 0):>8.2f}"
        f"  invalid={invalid}/{len(runs)}  queue={len(report.unjudged)}"
    )
    tokens = sum(u.tokens for u in report.models)
    calls = sum(u.calls for u in report.models)
    print(f"\ncost: {calls} call(s), {tokens} token(s)")
    print(f"\n{report.statement()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
