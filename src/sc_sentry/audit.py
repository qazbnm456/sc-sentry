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
from collections.abc import Iterable
from dataclasses import dataclass, field

from sc_sentry.briefs import BRIEFS
from sc_sentry.checks import CHECKS, parse
from sc_sentry.classes import VulnClass
from sc_sentry.sites import tools_for
from sc_sentry.task import Proposal, Proposals, audit_task

__all__ = ["Answer", "ClassResult", "Finding", "Report", "ask", "audit", "configure_once"]


@dataclass(frozen=True, slots=True)
class Answer:
    """One planner run: its proposals, most confident first, and what it cost."""

    proposals: tuple[Proposal, ...]
    tokens: int
    seconds: float
    failed: str | None = None


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


def ask(source: str, brief: str) -> Answer:
    """One planner run for one class on one file. Never raises."""
    import dspy

    task = audit_task(source, tools_for(source))
    started = time.monotonic()
    tokens = 0
    try:
        with dspy.track_usage() as tracker:
            result = task.run(brief=brief, source=source)
    except Exception as failure:
        return Answer(
            proposals=(),
            tokens=0,
            seconds=time.monotonic() - started,
            failed=f"{type(failure).__name__}: {failure}",
        )
    for calls in getattr(tracker, "usage_data", {}).values():
        for call in calls:
            tokens += int(call.get("total_tokens") or 0) or (
                int(call.get("prompt_tokens") or 0) + int(call.get("completion_tokens") or 0)
            )
    proposals = (
        result.findings if isinstance(result, Proposals) else getattr(result, "findings", [])
    )
    ordered = sorted(proposals, key=lambda p: -getattr(p, "confidence", 3))
    return Answer(proposals=tuple(ordered), tokens=tokens, seconds=time.monotonic() - started)


def audit(source: str, path: str, classes: Iterable[VulnClass] | None = None) -> Report:
    """Audit one file for each class asked (every class by default)."""
    wanted = list(classes) if classes is not None else list(VulnClass)
    parsed = parse(source)
    results: list[ClassResult] = []
    for vuln in wanted:
        check = CHECKS[vuln]
        candidates = check.find(source)
        if not candidates:
            results.append(ClassResult(vuln=vuln, candidates=0, asked=False))
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
