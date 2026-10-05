"""The harness as a contract-assay `ModelCaller`: what the benchmark calls when a detector asks.

`contract-assay run` loops over the corpus and the detectors, and when a detector's
`plan()` returns an instruction it calls `call` below. `plan()` returns `None` for a
class with no candidate sites in the unit, so for those the harness is never asked
and the run is a deterministic `clean`. The harness is a planner for one class on one
file, which is the shape `call_per_class` has in the benchmark's walkthrough, so each
detector gets its own call with its own class's brief.

    contract-assay run \\
        --manifest src/sc_sentry/contract_assay/manifests/access_control.manifest.json \\
        ... one --manifest for each class ... \\
        --records contract-assay/corpus/records --source-root checkout \\
        --model-caller sc_sentry.contract_assay.caller:call --limit 5 --out run.jsonl

The model comes from `.env` in the working directory or the environment, and it is
read when this module is imported, so a missing `RLM_MAIN_MODEL` ends the command with
one line instead of failing every unit. The limits that `rlm-harness` takes are set
once, from the first call: `--max-calls` through `ctx.limits`, and the rest from
`SC_SENTRY_MAX_ITERATIONS` (6) and `SC_SENTRY_CACHE=1`. The per-call generation cap is
`RLM_MAX_TOKENS`, which is not the benchmark's `--max-tokens`: that one is a budget for
a whole unit.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Sequence

from contract_assay.detectors.base import AnalysisContext, Detector, ModelTaskSpec
from contract_assay.harness import ModelReply
from contract_assay.models import (
    DEFAULT_PREDICTIONS_PER_UNIT,
    Finding,
    Locator,
    ModelRole,
    ModelUse,
)

from sc_sentry import dotenv, triage
from sc_sentry.audit import Answer, ask, configure_once
from sc_sentry.classes import VulnClass
from sc_sentry.contract_assay.detectors import to_benchmark_findings
from sc_sentry.task import Proposal

__all__ = ["call", "models_used", "to_findings"]

dotenv.load()

MAIN_MODEL = os.environ.get("RLM_MAIN_MODEL", "")
if not MAIN_MODEL:
    # At import, so the command that names this caller ends with one line. Left to the
    # first call, every unit comes back `transport_failure`, which reads like a harness
    # that finds nothing.
    raise RuntimeError(
        "RLM_MAIN_MODEL is not set. Copy .env.example to .env in this directory and fill it "
        "in, or export the RLM_* variables."
    )
SUB_MODEL = os.environ.get("RLM_SUB_MODEL") or MAIN_MODEL
MAX_ITERATIONS = int(os.environ.get("SC_SENTRY_MAX_ITERATIONS", "6"))
CACHE = os.environ.get("SC_SENTRY_CACHE") == "1"
MODE = os.environ.get("SC_SENTRY_MODE", "triage")
if MODE not in ("triage", "explore"):
    raise RuntimeError(f"SC_SENTRY_MODE must be triage or explore, not {MODE!r}")
CANDIDATES = int(os.environ.get("SC_SENTRY_CANDIDATES", str(triage.DEFAULT_CANDIDATES)))


def to_findings(
    detector: Detector, ctx: AnalysisContext, proposals: Sequence[Proposal]
) -> tuple[Finding, ...]:
    """The planner's proposals as findings, with the model's confidence as the score.

    A round ranked on bpref needs a score on every finding of a class, and this harness
    sorts by exactly this number, so dropping it would leave it unrankable on every such
    round while it already knew the order.
    """
    return tuple(
        Finding(
            detector_id=detector.detector_id,
            locator=Locator(
                file=ctx.path,
                contract=p.contract,
                function=p.function,
                start_line=p.start_line,
                # A backwards span collapses to its start, so it is not dropped for a
                # reason that reads as the model's fault.
                end_line=max(p.end_line, p.start_line),
            ),
            quote=p.quote,
            reasoning=p.reasoning,
            score=float(p.confidence),
        )
        for p in proposals
    )


def models_used(
    usage: Sequence[tuple[str, int, int]], *, main: str, sub: str
) -> tuple[ModelUse, ...]:
    """The `(model, calls, tokens)` rows of one planner run as the run's `ModelUse` entries.

    A row is the sub-model when it is that name, bare or behind a provider prefix, and
    anything else is charged to the main model so an unexpected name is counted and not
    lost. When the provider reports no usage at all the planner still made a call, so one
    call and no tokens is named instead of nothing: a run that names no model is refused,
    and zero tokens is the sign the benchmark's first check looks for.
    """
    totals: dict[ModelRole, list[int]] = {}
    for name, calls, tokens in usage:
        is_sub = sub != main and (name == sub or name.endswith("/" + sub))
        entry = totals.setdefault(ModelRole.SUB if is_sub else ModelRole.MAIN, [0, 0])
        entry[0] += calls
        entry[1] += tokens
    if not totals:
        return (ModelUse(model_id=main, role=ModelRole.MAIN, calls=1, tokens=0),)
    return tuple(
        ModelUse(
            model_id=sub if role is ModelRole.SUB else main, role=role, calls=calls, tokens=tokens
        )
        for role, (calls, tokens) in totals.items()
    )


def _triage(detector: Detector, ctx: AnalysisContext) -> ModelReply:
    """The harness's candidate functions, with the model deciding which are instances.

    The citations are the code's, so a finding cannot fail its citation check for a quote the
    model misread, and the report keeps every candidate: a function the model marked moves up,
    one it never saw or ruled out stays below. A failed call therefore costs the model's
    judgement and not the findings, and says so on stderr.
    """
    vuln = VulnClass(detector.class_id.value)
    limit = DEFAULT_PREDICTIONS_PER_UNIT
    entries, shown, answer = triage.run(vuln, ctx.source, ctx.path, sent=CANDIDATES)
    answered = answer or triage.TriageAnswer(verdicts={}, tokens=0, seconds=0.0)
    found = triage.triage_findings(
        vuln, ctx.source, ctx.path, entries, shown, answered, limit=limit
    )
    findings = to_benchmark_findings(detector.detector_id, ctx.path, found)
    models = models_used(answered.usage, main=MAIN_MODEL, sub=SUB_MODEL) if shown else ()
    print(
        f"    {detector.class_id.value:<24} {answered.seconds:>5.0f}s {answered.tokens:>7} tok"
        f"  {len(entries)} candidate function(s), {shown} reviewed, {len(findings)} reported",
        file=sys.stderr,
        flush=True,
    )
    if answered.failed is not None:
        print(
            f"      triage failed ({answered.failed}); these are the unreviewed candidates",
            file=sys.stderr,
            flush=True,
        )
    _warn_over(ctx, answered.seconds, answered.tokens)
    return ModelReply(findings=findings, models=models)


def _warn_over(ctx: AnalysisContext, seconds: float, tokens: int) -> None:
    for spent, limit, unit in (
        (seconds, ctx.limits.wall_seconds, "s"),
        (tokens, ctx.limits.max_tokens, " tokens"),
    ):
        if spent > limit:
            # Not enforced here, and not by `contract-assay run`. A round kills or refuses a
            # call that overruns, so this is how a harness that is too slow or too costly
            # finds out before the round does. The limits are for a whole unit, and this
            # is one class of it.
            print(
                f"      {spent:.0f}{unit} exceeds the {limit}{unit} a round allows",
                file=sys.stderr,
                flush=True,
            )


def call(detector: Detector, spec: ModelTaskSpec, ctx: AnalysisContext) -> ModelReply:
    """One model run for this detector's class over this unit, and what it cost.

    `triage` (the default) reviews the harness's own candidate functions in one call. `explore`
    is the planner with tools, which investigates and cites what it finds.
    """
    configure_once(
        max_tokens=None,
        max_calls=ctx.limits.max_model_calls,
        max_iterations=MAX_ITERATIONS,
        cache=CACHE,
    )
    if MODE == "triage":
        return _triage(detector, ctx)
    answer: Answer = ask(ctx.source, spec.instruction)
    models = models_used(answer.usage, main=MAIN_MODEL, sub=SUB_MODEL)
    print(
        f"    {detector.class_id.value:<24} {answer.seconds:>5.0f}s {answer.tokens:>7} tok"
        f"  {len(answer.proposals)} proposal(s)",
        file=sys.stderr,
        flush=True,
    )
    _warn_over(ctx, answer.seconds, answer.tokens)
    if answer.failed is not None:
        return ModelReply(failed=answer.failed, models=models)
    return ModelReply(findings=to_findings(detector, ctx, answer.proposals), models=models)
