"""The harness's own findings, with no model: its candidates, one per function.

`checks.py` finds where a class could be. This turns those sites into findings the way a
reader would cite them, and it is the control group for everything the model adds: a model
that does not beat these has not earned its calls.

A finding is cited at one candidate site, whole lines, in the function the class is about,
because a defect is located to a function and a cap counts findings. The candidates come
out likeliest first when the class has a `priority`, and in source order when it does not.
Nothing here is reviewed by a model, so each finding says so and carries the lowest
confidence; what the model reviewed is marked apart in `audit`.
"""

from __future__ import annotations

from sc_sentry.audit import Finding
from sc_sentry.checks import CHECKS, Candidate, CandidateFunction
from sc_sentry.classes import VulnClass

__all__ = ["describe", "quote_of", "static_findings"]

UNREVIEWED_CONFIDENCE = 1


def quote_of(source: str, start_line: int, end_line: int) -> str:
    """The whole lines of the source a citation covers."""
    return "\n".join(source.split("\n")[start_line - 1 : end_line])


def describe(candidate: Candidate) -> str:
    """What established a candidate, as a reader would say it."""
    what = candidate.predicate.replace("_", " ")
    detail = ", ".join(f"{key}={value}" for key, value in candidate.detail.items() if value != "")
    return f"{what} ({detail})" if detail else what


def _reasoning(entry: CandidateFunction) -> str:
    more = len(entry.candidates) - 1
    tail = f"; {more} more site(s) in this function" if more else ""
    return f"Candidate, not reviewed by a model: {describe(entry.best)}{tail}."


def static_findings(
    vuln: VulnClass, source: str, path: str, *, limit: int | None = None
) -> tuple[Finding, ...]:
    """The class's candidate functions as findings, likeliest first, at most `limit`."""
    out: list[Finding] = []
    for entry in CHECKS[vuln].functions(source):
        site = entry.best.site
        out.append(
            Finding(
                vuln=vuln,
                file=path,
                start_line=site.start_line,
                end_line=max(site.end_line, site.start_line),
                function=entry.function,
                contract=entry.contract,
                quote=quote_of(source, site.start_line, site.end_line),
                reasoning=_reasoning(entry),
                confidence=UNREVIEWED_CONFIDENCE,
                origin="static",
            )
        )
        if limit is not None and len(out) >= limit:
            break
    return tuple(out)
