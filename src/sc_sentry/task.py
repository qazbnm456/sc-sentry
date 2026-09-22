"""The task: one class, one unit, a planner with a parser and eight skills.

Built on `rlm-harness` because the job is exactly what an LM-coordination
framework is for -- a planner that decides what to look at next, sub-models that
read, tools that answer precisely, and a validated structured result at the end.
The first attempt at this failed for the opposite reason to the obvious one: not
because a planner is expensive, but because it was given nothing to plan with.
A prose instruction and a source string leave a planner reading and guessing;
the same planner with `sites.tools_for` under it asks and is answered.

Two things the skills carry that no tool can:

- **what each class is**, including the shapes that look like it and are not,
  which is where precision comes from;
- **how to cite**, which is where recall comes from. A quote that is not at the
  locator is discarded before it is scored, and the run then reads as a detector
  that found nothing rather than as one that was wrong.

The catalogue is injected at startup (`render_skills_manifest`) rather than
discovered by a tool call, so the planner never spends a turn finding out what
it knows.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field
from rlm_harness import RLMTask, load_skills_as_tools, render_skills_manifest
from rlm_harness.tools import make_schema_validator

SKILLS = str(Path(__file__).resolve().parent / "skills")


class Proposal(BaseModel):
    """One candidate defect. Lines and quote must come from a tool, not from memory."""

    start_line: int = Field(ge=1, description="1-indexed, inclusive.")
    end_line: int = Field(ge=1, description="1-indexed, inclusive.")
    quote: str = Field(
        min_length=1,
        description=(
            "The EXACT source text at those lines, copied verbatim from the SAME tool "
            "answer that gave you start_line and end_line."
        ),
    )
    reasoning: str = Field(
        min_length=1,
        description=(
            "Why this is an instance, and which 'not an instance' reasons from the skill "
            "you checked and ruled out."
        ),
    )
    contract: str | None = None
    function: str = Field(
        min_length=1,
        description=(
            "The enclosing function, as a tool reported it. Required: a finding with no "
            "function cannot match at function strength, which is most rounds' floor."
        ),
    )
    confidence: int = Field(
        default=3, ge=1, le=5, description="5 = certain. Used to order the report."
    )


class Proposals(BaseModel):
    findings: list[Proposal] = Field(default_factory=list)


DISCIPLINE = """\
You are auditing one Solidity source unit for ONE vulnerability class, named in
the brief.

Work in this order:

1. Call `outline()` once to see the unit's size, state and functions.
2. Read the skill for the class in the brief, and read `citing-source`.
3. Call the tools the skill points at. They return exact source text with exact
   line numbers; every candidate you consider must come from one of them.
4. For EACH candidate the tools returned, decide: instance, or ruled out by a
   named reason from the skill's "not an instance" section. Do not skip
   candidates silently.
5. Report every candidate you decided is an instance, best first.

Before you may return an empty list, you must have considered every candidate
the tools returned for this class and be able to name, for each, the specific
reason it is not an instance. "Nothing obvious" is not a reason. An empty list
after a real accounting is a correct answer; an empty list because the file
looked unfamiliar is a missed defect.

The four rules that decide whether your work is scored at all:

- **`start_line`, `end_line`, `quote` and `function` arrive together, from one
  tool answer. Never mix fields from different answers.** A quote that is real
  but paired with another candidate's line numbers is discarded, and it is the
  most common way a correct finding is thrown away.
- **Cite the SMALLEST complete statement that contains the defect**, not the
  enclosing function. A span covering a whole function matches only at
  file-level strength, which most rounds score below their floor -- so a
  40-line span is a finding that was right and did not count.
- `quote` must be the EXACT text at those lines, copied from the tool output.
  Do not retype it, tidy it, or abbreviate it.
- You may report up to THREE findings and **the allowance exists to be used.**
  If two or three candidates survive your accounting, report two or three, best
  first. Reporting one when three survived leaves two defects unreported, and
  measurement shows that is the common case rather than the rare one. Only the
  first three are scored and nothing re-ranks for you, so order them by how sure
  you are.
- Rank by certainty, not by severity. Severity is not scored here.

Report only the class in the brief. Another class's defect reported here is
scored against this class and counts against it.
"""


def audit_task(source: str, tools: Sequence[Any]) -> RLMTask:
    """A task bound to one unit's tools, with the skills catalogue injected."""
    manifest = render_skills_manifest(SKILLS, header="<available_skills>")

    class Audit(RLMTask):  # type: ignore[misc]
        signature = "brief: str, source: str -> findings: Proposals"
        output_field = "findings"
        output_model = Proposals
        instructions = f"{DISCIPLINE}\n\n{manifest}\n</available_skills>"

    Audit.tools = [
        *tools,
        *load_skills_as_tools(SKILLS, discovery="inject"),
        make_schema_validator(Proposals),
    ]
    return Audit()
