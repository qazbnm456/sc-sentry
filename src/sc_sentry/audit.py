"""The harness: one Solidity file, the classes asked for, a planner per class.

What it does beyond asking a model to "find bugs", and each is a measured cost:

- **A class with no candidate sites costs nothing.** `sc_sentry.checks` finds
  where a class could be; a class with no candidates in the file is never
  asked about -- which is both cheaper and the only way to avoid an invented
  finding.
- **The planner holds tools.** The first attempt gave it a prose instruction and
  a string; it spun for 171 seconds and produced nothing. Tools (`sites.py`)
  are what turn a planner from a reader into a planner.
- **Findings are ordered by the model's own confidence**, which is kept on each
  finding, so whoever reads the report can cut it where they like.
- **Every finding is screened by its class's definition** (`checks.rejects`).
  A rejected finding is kept in the report with the reason, never dropped: a
  reader deciding whether the screen is too strict needs to see what it took.

The model comes from the environment (`RLM_*`, see `.env.example`), because
here there is nothing else to ask: this is the whole run.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from sc_sentry.briefs import BRIEFS
from sc_sentry.checks import CHECKS, parse
from sc_sentry.classes import VulnClass
from sc_sentry.sites import tools_for
from sc_sentry.task import Proposal, Proposals, audit_task

__all__ = [
    "Answer",
    "ClassResult",
    "Finding",
    "Report",
    "ask",
    "audit",
    "configure_once",
    "usage_of",
]


@dataclass(frozen=True, slots=True)
class Answer:
    """One planner run: its proposals, most confident first, and what it cost."""

    proposals: tuple[Proposal, ...]
    tokens: int
    seconds: float
    failed: str | None = None
    usage: tuple[tuple[str, int, int], ...] = ()
    """Each language model the run reached, as `(model, calls, tokens)`.

    `tokens` is their sum. The rows are kept apart because a planner and its
    sub-model are different models with different costs, and a figure that adds
    them cannot say which one a change made cheaper. A provider that reports no
    usage leaves this empty, and `tokens` is then zero.
    """


@dataclass(frozen=True, slots=True)
class Finding:
    """One cited defect, and whether the class definition let it stand."""

    vuln: VulnClass
    file: str
    start_line: int
    end_line: int
    function: str | None
    contract: str | None
    quote: str
    reasoning: str
    confidence: int
    rejected: str | None = None
    """What the class definition did not find established at these lines, or
    `None` when the finding stands."""
    origin: str = "model"
    """`static` for a candidate the harness cited without a model, `model` for one a
    planner proposed. Whoever reads a report should be able to tell which they hold."""


@dataclass(frozen=True, slots=True)
class ClassResult:
    vuln: VulnClass
    candidates: int
    asked: bool
    findings: tuple[Finding, ...] = ()
    tokens: int = 0
    seconds: float = 0.0
    failed: str | None = None


@dataclass(frozen=True, slots=True)
class Report:
    file: str
    model: str
    results: tuple[ClassResult, ...] = field(default_factory=tuple)

    @property
    def findings(self) -> tuple[Finding, ...]:
        return tuple(f for r in self.results for f in r.findings)


_CONFIGURED = False

DEFAULT_MAX_TOKENS = 32_768
"""Generous, because a reasoning model's chain of thought and its structured
answer share one cap, and a turn that overruns it is cut off mid-JSON."""


def resolve_max_tokens(given: int | None) -> int:
    if given is not None:
        return given
    env = os.environ.get("RLM_MAX_TOKENS", "").strip()
    return int(env) if env else DEFAULT_MAX_TOKENS


def configure_once(
    *, max_tokens: int | None, max_calls: int, max_iterations: int, cache: bool = False
) -> None:
    """Models and endpoint from the environment, once per process.

    Caching is off by default, because dspy caches on disk and a cached answer
    comes back in two seconds having spent zero tokens -- a cost figure about a
    different run. `cache=True` is for iterating on everything downstream of
    the model, where the cached answer is exactly what is wanted.

    `max_tokens=None` means `RLM_MAX_TOKENS` if set, else `DEFAULT_MAX_TOKENS`:
    an explicit flag wins over the environment, and the environment over ours.
    """
    global _CONFIGURED
    if _CONFIGURED:
        return
    from dataclasses import replace

    import dspy
    from rlm_harness import RLMConfig, configure

    dspy.configure_cache(enable_disk_cache=cache, enable_memory_cache=cache)
    cfg = replace(
        RLMConfig.from_env(),
        max_tokens=resolve_max_tokens(max_tokens),
        max_llm_calls=max_calls,
        max_iterations=max_iterations,
        # Measured: 4 of 64 calls died as "Failed to produce a valid 'findings'
        # after 1 attempts" -- the reasoning-model truncation shape, where the
        # chain-of-thought and the structured answer share one `max_tokens` and
        # a turn that overruns is cut off mid-JSON.
        max_retries=3,
    )
    configure(cfg)
    # Pinned after `configure`, because `RLMConfig` has no temperature field and
    # the LM does not exist before this point. Unpinned means the server's
    # default -- typically 1.0 -- and two runs over one file are two samples of
    # an unrecorded distribution.
    lm = getattr(dspy.settings, "lm", None)
    if lm is not None and hasattr(lm, "kwargs"):
        lm.kwargs["temperature"] = float(os.environ.get("SC_SENTRY_TEMPERATURE", "0.0"))
        lm.cache = cache
    _CONFIGURED = True


def usage_of(
    usage_data: Mapping[str, Sequence[Mapping[str, Any]]],
) -> tuple[tuple[str, int, int], ...]:
    """dspy's usage tracker as `(model, calls, tokens)` rows."""
    return tuple(
        (
            str(model),
            len(calls),
            sum(
                int(call.get("total_tokens") or 0)
                or (int(call.get("prompt_tokens") or 0) + int(call.get("completion_tokens") or 0))
                for call in calls
            ),
        )
        for model, calls in usage_data.items()
    )


def ask(source: str, brief: str) -> Answer:
    """One planner run for one class on one file. Never raises."""
    import dspy

    task = audit_task(source, tools_for(source))
    started = time.monotonic()
    usage_data: Mapping[str, Sequence[Mapping[str, Any]]] = {}
    try:
        with dspy.track_usage() as tracker:
            try:
                result = task.run(brief=brief, source=source)
            finally:
                # Read on failure as well. A call that raised was still made, and what
                # it spent is spent: a cost that counted only successes would let a
                # sweep that kept failing report that it cost nothing.
                usage_data = dict(getattr(tracker, "usage_data", {}))
    except Exception as failure:
        usage = usage_of(usage_data)
        return Answer(
            proposals=(),
            tokens=sum(tokens for _, _, tokens in usage),
            seconds=time.monotonic() - started,
            failed=f"{type(failure).__name__}: {failure}",
            usage=usage,
        )
    usage = usage_of(usage_data)
    proposals = (
        result.findings if isinstance(result, Proposals) else getattr(result, "findings", [])
    )
    ordered = sorted(proposals, key=lambda p: -getattr(p, "confidence", 3))
    return Answer(
        proposals=tuple(ordered),
        tokens=sum(tokens for _, _, tokens in usage),
        seconds=time.monotonic() - started,
        usage=usage,
    )


MODES = ("explore", "triage", "static")

DEFAULT_STATIC_LIMIT = 9
"""How many findings a class keeps per file without a model: the benchmark's default cap."""


def audit(
    source: str,
    path: str,
    classes: Iterable[VulnClass] | None = None,
    *,
    mode: str = "explore",
    limit: int | None = DEFAULT_STATIC_LIMIT,
    sent: int = 20,
) -> Report:
    """Audit one file for each class asked (every class by default).

    `mode` is how a class is answered:

    - `explore`: a planner with tools investigates and cites what it finds.
    - `triage`: the harness's candidate functions go to the model in one call, which decides
      which are instances. The citations are the code's, and the report keeps every
      candidate, the model's picks first. At most `sent` go to the model.
    - `static`: no model. The candidate functions are the findings, likeliest first.

    Both of the last two keep at most `limit` findings for a class.
    """
    if mode not in MODES:
        raise ValueError(f"mode must be one of {', '.join(MODES)}, not {mode!r}")
    wanted = list(classes) if classes is not None else list(VulnClass)
    parsed = parse(source)
    results: list[ClassResult] = []
    for vuln in wanted:
        check = CHECKS[vuln]
        candidates = check.find(source)
        if not candidates:
            results.append(ClassResult(vuln=vuln, candidates=0, asked=False))
            continue
        if mode == "triage":
            from sc_sentry import triage

            entries, shown, triaged = triage.run(vuln, source, path, sent=sent)
            answer_t = triaged or triage.TriageAnswer(verdicts={}, tokens=0, seconds=0.0)
            results.append(
                ClassResult(
                    vuln=vuln,
                    candidates=len(candidates),
                    asked=shown > 0,
                    findings=triage.triage_findings(
                        vuln, source, path, entries, shown, answer_t, limit=limit
                    ),
                    tokens=answer_t.tokens,
                    seconds=answer_t.seconds,
                    failed=answer_t.failed,
                )
            )
            continue
        if mode == "static":
            from sc_sentry.static import static_findings

            results.append(
                ClassResult(
                    vuln=vuln,
                    candidates=len(candidates),
                    asked=False,
                    findings=static_findings(vuln, source, path, limit=limit),
                )
            )
            continue
        answer = ask(source, BRIEFS[vuln])
        spans = [candidate.span for candidate in candidates]
        findings = tuple(
            Finding(
                vuln=vuln,
                file=path,
                start_line=p.start_line,
                end_line=max(p.end_line, p.start_line),
                function=p.function,
                contract=p.contract,
                quote=p.quote,
                reasoning=p.reasoning,
                confidence=p.confidence,
                rejected=check.rejects(parsed, spans, p.start_line, max(p.end_line, p.start_line)),
            )
            for p in answer.proposals
        )
        results.append(
            ClassResult(
                vuln=vuln,
                candidates=len(candidates),
                asked=True,
                findings=findings,
                tokens=answer.tokens,
                seconds=answer.seconds,
                failed=answer.failed,
            )
        )
    return Report(file=path, model=os.environ.get("RLM_MAIN_MODEL", ""), results=tuple(results))
