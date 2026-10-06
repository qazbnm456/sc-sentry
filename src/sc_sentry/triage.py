"""Triage: the model decides which of the harness's own candidate functions are instances.

The planner in `audit.ask` explores a file with tools and cites what it finds, and on the
public corpus most of what it cited was not where it said. The candidate finders already know
where a class could be and cite those places exactly, so this asks the model the question it is
better placed to answer than a finder, which of those functions is the real thing, and leaves the
citation to the code. One call covers a class in a file, and the candidates arrive as a numbered
list with each function's code, so the answer is a verdict per number.

Whatever the model decides, nothing is lost: a function it marked as an instance comes first,
most confident first, then the ones it never saw, then the ones it ruled out, with the reason
kept. A report is never shorter than the candidates, so the model can move a function up and
cannot hide one.
"""

from __future__ import annotations

import re
import threading
import time
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from sc_sentry.audit import Finding, usage_of
from sc_sentry.checks import CHECKS, CandidateFunction, parse
from sc_sentry.classes import VulnClass
from sc_sentry.solidity import Syntax
from sc_sentry.solidity.syntax import FunctionSite
from sc_sentry.static import UNREVIEWED_CONFIDENCE, finding_for, unreviewed_reasoning

__all__ = [
    "DEFAULT_CANDIDATES",
    "Budget",
    "TriageAnswer",
    "Verdict",
    "Verdicts",
    "ask",
    "class_definition",
    "render",
    "run",
    "run_budgeted",
    "triage_findings",
]

SKILLS = Path(__file__).resolve().parent / "skills"
DEFAULT_CANDIDATES = 20
"""How many candidate functions go to the model for one class in one file, likeliest first."""
MAX_FUNCTION_LINES = 40
CHARS_PER_TOKEN = 3
"""Solidity with its identifiers tokenizes at about this many characters to a token, a little
under prose, so an estimate made with it errs toward spending less."""
FORMAT_OVERHEAD_TOKENS = 500
"""What the signature and the output schema add around the prompt."""
MIN_CANDIDATES = 3
"""The fewest candidates worth a call: fewer than this and the order is nearly the whole answer."""
MIN_COMPLETION_TOKENS = 4000
"""A reasoning model's chain of thought shares the completion cap with its answer, and measured
it spends 2,600 to 5,000 tokens before the verdicts. Below this the answer is cut off
mid-verdict, which parses as no answer and costs what a whole one does."""
MIN_SECONDS = 3.0
"""Below this a call would be abandoned before it could answer."""


class Verdict(BaseModel):
    """The model's decision about one numbered candidate."""

    id: int = Field(ge=1, description="The candidate's number in the list.")
    instance: bool = Field(
        description="True only when this function is an instance of the class as defined above."
    )
    confidence: int = Field(ge=1, le=5, description="1 is barely, 5 is certain.")
    reasoning: str = Field(
        min_length=1,
        description=(
            "One or two sentences: what in this function makes it an instance, or which "
            "look-alike from the definition rules it out."
        ),
    )


class Verdicts(BaseModel):
    verdicts: list[Verdict] = Field(default_factory=list)


INSTRUCTIONS = """\
You review Solidity for one class of vulnerability. You are given the definition of the class,
then candidate functions found by static analysis, numbered. A candidate means the shape the class
is about is present in that function, which is a precondition and not a defect, so most
candidates are not instances. For every candidate decide whether the function is an instance of
the class as defined, using only the code shown. Rule out the look-alikes the definition names.
Answer with one verdict for each candidate number, and no other numbers."""


def class_definition(vuln: VulnClass) -> str:
    """The class's summary and its skill, without the front matter."""
    head = f"Class: {vuln.value}. {CHECKS[vuln].summary}"
    path = SKILLS / vuln.value.replace("_", "-") / "SKILL.md"
    if not path.is_file():
        return head
    body = re.sub(r"\A---\n.*?\n---\n", "", path.read_text(encoding="utf-8"), flags=re.DOTALL)
    return f"{head}\n\n{body.strip()}"


def _function_of(parsed: Syntax, entry: CandidateFunction) -> FunctionSite | None:
    """The innermost function whose lines hold the entry's cited site."""
    line = entry.best.site.start_line
    inside = [f for f in parsed.functions if f.site.start_line <= line <= f.site.end_line]
    return min(inside, key=lambda f: f.site.end_line - f.site.start_line, default=None)


def _code(parsed: Syntax, first: int, last: int, around: int) -> str:
    """Numbered lines of a function, kept to a window around the cited site when it is long."""
    numbered = [(n, parsed.lines[n - 1]) for n in range(first, last + 1)]
    if len(numbered) > MAX_FUNCTION_LINES:
        head, window = 5, MAX_FUNCTION_LINES - 5
        start = max(first + head, min(around - window // 2, last - window + 1))
        kept = numbered[:head] + [(0, "")] + [r for r in numbered if start <= r[0] < start + window]
        numbered = kept
    return "\n".join("   ..." if n == 0 else f"{n:>5} | {text}" for n, text in numbered)


def render(entries: Sequence[CandidateFunction], parsed: Syntax) -> str:
    """The candidates as the model reads them: a header, what fired, and the code."""
    blocks: list[str] = []
    for number, entry in enumerate(entries, start=1):
        fn = _function_of(parsed, entry)
        site = entry.best.site
        name = f"{entry.contract or '?'}.{entry.function or '(file level)'}"
        if fn is not None:
            reach = " ".join(
                part for part in (fn.visibility, fn.state_mutability, *fn.modifiers) if part
            )
            first, last = fn.site.start_line, fn.site.end_line
            header = f"#{number} {name} [{reach}] lines {first}-{last}"
        else:
            first, last = site.start_line, site.end_line
            header = f"#{number} {name} lines {first}-{last}"
        fired = ", ".join(
            f"{predicate} x{count}" if count > 1 else predicate
            for predicate, count in Counter(c.predicate for c in entry.candidates).items()
        )
        blocks.append(f"{header}\nfired: {fired}\n{_code(parsed, first, last, site.start_line)}")
    return "\n\n".join(blocks)


@dataclass(frozen=True, slots=True)
class TriageAnswer:
    """One call's verdicts by candidate number, and what it cost."""

    verdicts: Mapping[int, Verdict]
    tokens: int
    seconds: float
    failed: str | None = None
    usage: tuple[tuple[str, int, int], ...] = ()


def ask(
    definition: str, table: str, *, count: int, config: Mapping[str, Any] | None = None
) -> TriageAnswer:
    """One model call over `count` numbered candidates. Never raises.

    `config` is passed to the model call itself (`max_tokens`, `timeout`), for a caller that has
    a budget to keep.
    """
    import dspy

    class Triage(dspy.Signature):  # type: ignore[misc]
        class_definition: str = dspy.InputField()
        candidates: str = dspy.InputField()
        verdicts: Verdicts = dspy.OutputField()

    Triage.__doc__ = INSTRUCTIONS
    started = time.monotonic()
    usage_data: Mapping[str, Sequence[Mapping[str, Any]]] = {}
    try:
        with dspy.track_usage() as tracker:
            try:
                extra = {"config": dict(config)} if config else {}
                result = dspy.Predict(Triage)(
                    class_definition=definition, candidates=table, **extra
                )
            finally:
                usage_data = dict(getattr(tracker, "usage_data", {}))
    except Exception as failure:
        usage = usage_of(usage_data)
        return TriageAnswer(
            verdicts={},
            tokens=sum(tokens for _, _, tokens in usage),
            seconds=time.monotonic() - started,
            failed=f"{type(failure).__name__}: {failure}",
            usage=usage,
        )
    usage = usage_of(usage_data)
    decided: dict[int, Verdict] = {}
    for verdict in getattr(result, "verdicts", Verdicts()).verdicts:
        if 1 <= verdict.id <= count:
            decided.setdefault(verdict.id, verdict)
    return TriageAnswer(
        verdicts=decided,
        tokens=sum(tokens for _, _, tokens in usage),
        seconds=time.monotonic() - started,
        usage=usage,
    )


def triage_findings(
    vuln: VulnClass,
    source: str,
    path: str,
    entries: Sequence[CandidateFunction],
    sent: int,
    answer: TriageAnswer,
    *,
    limit: int | None = None,
) -> tuple[Finding, ...]:
    """The candidates as findings: instances first, then unseen ones, then those ruled out.

    `sent` is how many of `entries` the model was shown. Instances come most confident first, the
    unseen (past `sent`, or given no verdict) in the order the finders ranked them, and a function
    the model ruled out last with its reason, marked `rejected` so a reader can see what it took.
    """
    chosen: list[tuple[int, Finding]] = []
    unseen: list[Finding] = []
    ruled_out: list[Finding] = []
    for index, entry in enumerate(entries):
        verdict = answer.verdicts.get(index + 1) if index < sent else None
        if verdict is None:
            unseen.append(
                finding_for(
                    vuln,
                    source,
                    path,
                    entry,
                    confidence=UNREVIEWED_CONFIDENCE,
                    reasoning=unreviewed_reasoning(entry),
                    origin="static",
                )
            )
        elif verdict.instance:
            chosen.append(
                (
                    verdict.confidence,
                    finding_for(
                        vuln,
                        source,
                        path,
                        entry,
                        confidence=verdict.confidence,
                        reasoning=verdict.reasoning,
                        origin="model",
                    ),
                )
            )
        else:
            ruled_out.append(
                finding_for(
                    vuln,
                    source,
                    path,
                    entry,
                    confidence=UNREVIEWED_CONFIDENCE,
                    reasoning=verdict.reasoning,
                    origin="model",
                    rejected="reviewed_not_an_instance",
                )
            )
    ordered = [f for _, f in sorted(chosen, key=lambda item: -item[0])] + unseen + ruled_out
    return tuple(ordered if limit is None else ordered[:limit])


def run(
    vuln: VulnClass, source: str, path: str, *, sent: int = DEFAULT_CANDIDATES
) -> tuple[Sequence[CandidateFunction], int, TriageAnswer | None]:
    """The candidate functions, how many went to the model, and its answer, or None if none did."""
    entries = CHECKS[vuln].functions(source)
    parsed = parse(source)
    shown = entries[:sent]
    if not shown or parsed is None:
        return entries, 0, None
    answer = ask(class_definition(vuln), render(shown, parsed), count=len(shown))
    return entries, len(shown), answer


@dataclass(frozen=True, slots=True)
class Budget:
    """What one file may cost across all its classes, for a host that meters from outside.

    A host that refuses the call past its limit, or kills the process at its wall clock, records
    the unit as a harness that failed and discards what the harness wrote. So this keeps the
    harness inside the limit by doing less: a class the budget cannot cover keeps its static
    order, and the report still stands. `None` is no limit.
    """

    seconds: float | None = None
    calls: int | None = None
    tokens: int | None = None

    @property
    def bounded(self) -> bool:
        return any(limit is not None for limit in (self.seconds, self.calls, self.tokens))


@dataclass(frozen=True, slots=True)
class _Job:
    vuln: VulnClass
    shown: int
    table: str
    definition: str
    completion_cap: int | None


def _tokens(text: str) -> int:
    return -(-len(text) // CHARS_PER_TOKEN)


def _prompt_tokens(definition: str, table: str) -> int:
    return _tokens(INSTRUCTIONS + definition + table) + FORMAT_OVERHEAD_TOKENS


def _floor(vuln: VulnClass, entries: Sequence[CandidateFunction], parsed: Syntax) -> int:
    """The least a useful call for this class costs: its fewest candidates and a whole answer."""
    table = render(entries[: min(MIN_CANDIDATES, len(entries))], parsed)
    return _prompt_tokens(class_definition(vuln), table) + MIN_COMPLETION_TOKENS


def _fit(
    vuln: VulnClass,
    entries: Sequence[CandidateFunction],
    parsed: Syntax,
    *,
    sent: int,
    share: int | None,
) -> _Job | None:
    """The most candidates, likeliest first, that leave the answer room within `share` tokens."""
    definition = class_definition(vuln)
    shown = min(sent, len(entries))
    floor = min(MIN_CANDIDATES, len(entries))
    while shown >= max(floor, 1):
        table = render(entries[:shown], parsed)
        if share is None:
            return _Job(vuln, shown, table, definition, None)
        prompt = _prompt_tokens(definition, table)
        if share - prompt >= MIN_COMPLETION_TOKENS:
            return _Job(vuln, shown, table, definition, share - prompt)
        shown -= 1
    return None


def _answers(jobs: Sequence[_Job], seconds: float | None) -> dict[VulnClass, TriageAnswer]:
    """Every job's call at once, and whatever has answered when the time is up.

    The calls run side by side, so the file costs the slowest of them and not their sum. A call
    still running at the deadline is abandoned and its class is reported as unanswered: the
    threads are daemons, so they never hold the process open past the host's wall clock.
    """
    answered: dict[VulnClass, TriageAnswer] = {}
    started = time.monotonic()

    def left() -> float | None:
        return None if seconds is None else max(0.0, seconds - (time.monotonic() - started))

    def work(job: _Job) -> None:
        config: dict[str, Any] = {}
        if job.completion_cap is not None:
            config["max_tokens"] = job.completion_cap
        if (remaining := left()) is not None:
            config["timeout"] = remaining
        answered[job.vuln] = ask(job.definition, job.table, count=job.shown, config=config)

    threads = [threading.Thread(target=work, args=(job,), daemon=True) for job in jobs]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(left())
    done = dict(answered)
    for job in jobs:
        if job.vuln not in done:
            done[job.vuln] = TriageAnswer(
                verdicts={},
                tokens=0,
                seconds=time.monotonic() - started,
                failed=f"no answer within the {seconds:.0f}s budget"
                if seconds is not None
                else "the call ended without an answer",
            )
    return done


def run_budgeted(
    vulns: Sequence[VulnClass], source: str, *, sent: int = DEFAULT_CANDIDATES, budget: Budget
) -> dict[VulnClass, tuple[Sequence[CandidateFunction], int, TriageAnswer | None]]:
    """What `run` returns for each class, with one budget shared by all of them.

    The classes with the most candidate functions come first, because an order matters most where
    there is the most to order. A class gets a call only if a useful one still fits in what is
    left of the tokens, so a budget that cannot pay for every class pays for some of them in
    full, which is worth more than all of them cut off. What the cheapest calls leave over is
    shared equally, and each call sends as many candidates as its share holds.
    """
    results: dict[VulnClass, tuple[Sequence[CandidateFunction], int, TriageAnswer | None]] = {
        vuln: (CHECKS[vuln].functions(source), 0, None) for vuln in vulns
    }
    parsed = parse(source)
    if parsed is None or (budget.seconds is not None and budget.seconds < MIN_SECONDS):
        return results
    ranked = sorted((v for v in vulns if results[v][0]), key=lambda v: -len(results[v][0]))
    floors: dict[VulnClass, int] = {}
    for vuln in ranked:
        if budget.calls is not None and len(floors) >= max(budget.calls, 0):
            break
        floor = _floor(vuln, results[vuln][0], parsed)
        if budget.tokens is None or sum(floors.values()) + floor <= budget.tokens:
            floors[vuln] = floor
    spare = (
        (budget.tokens - sum(floors.values())) // len(floors)
        if budget.tokens is not None and floors
        else None
    )
    jobs = [
        job
        for vuln, floor in floors.items()
        if (
            job := _fit(
                vuln,
                results[vuln][0],
                parsed,
                sent=sent,
                share=None if spare is None else floor + spare,
            )
        )
        is not None
    ]
    answers = _answers(jobs, budget.seconds)
    for job in jobs:
        results[job.vuln] = (results[job.vuln][0], job.shown, answers[job.vuln])
    return results
