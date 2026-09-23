"""What the harness promises without a model: its detectors, its briefs, its ordering.

No test here calls a model. Each one pins a behaviour a model run depends on and
would hide if it broke: a detector missing from the registry is a class that
silently scores nothing, and an unscored finding is a class no bpref round can
rank.
"""

from __future__ import annotations

from typing import Any

import pytest
from contract_assay.detectors.base import AnalysisContext, SubmissionLimits
from contract_assay.models import EvidenceRef, EvidenceTier, Locator

from sc_sentry import run
from sc_sentry.briefs import BRIEFS
from sc_sentry.detectors import SENTRY_DETECTORS, Slippage
from sc_sentry.task import Proposal, Proposals

SOURCE = "contract Vault {\n    function withdraw() external {}\n}\n"


def a_context(detector: Any) -> AnalysisContext:
    return AnalysisContext(
        source_id="commit:vault@aaaaaaaaaaaa:src/Vault.sol",
        path="src/Vault.sol",
        source=SOURCE,
        tier=EvidenceTier.SYNTACTIC,
        level=detector.level,
        limits=SubmissionLimits.for_level(
            detector.level, wall_seconds=60, max_model_calls=4, max_tokens=20_000
        ),
    )


class TestTheRegistry:
    def test_each_detector_is_one_class_and_one_id(self) -> None:
        ids = [cls.detector_id for cls in SENTRY_DETECTORS]
        classes = [cls.class_id for cls in SENTRY_DETECTORS]
        assert len(set(ids)) == len(ids) == len(SENTRY_DETECTORS)
        assert len(set(classes)) == len(classes)

    def test_every_detector_has_a_brief(self) -> None:
        # `plan()` indexes BRIEFS by class, so a missing brief is a KeyError
        # at the first unit with a candidate site -- mid-sweep, not at import.
        assert {cls.class_id for cls in SENTRY_DETECTORS} <= set(BRIEFS)


class TestPlanning:
    def test_no_evidence_means_no_question(self) -> None:
        # A planner asked to audit a file with no sites of its class invents one.
        detector = Slippage()
        assert detector.plan(a_context(detector), []) is None

    def test_evidence_means_the_class_brief(self) -> None:
        detector = Slippage()
        ctx = a_context(detector)
        evidence = [
            EvidenceRef(
                predicate="a_swap_site",
                tier=EvidenceTier.SYNTACTIC,
                locator=Locator(file=ctx.path, start_line=2, end_line=2),
            )
        ]
        spec = detector.plan(ctx, evidence)
        assert spec is not None
        assert spec.instruction == BRIEFS[detector.class_id]


class TestTheAnswer:
    def test_findings_are_ordered_and_scored_by_the_models_confidence(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The confidence is the declared ordering a bpref round ranks on.

        It was used to sort the findings and then dropped, so every sc-sentry
        finding reached the scorer unscored and every bpref round left this
        harness unrankable.
        """

        def proposal(confidence: int, line: int) -> Proposal:
            return Proposal(
                start_line=line,
                end_line=line,
                quote="function withdraw() external {}",
                reasoning="an unguarded withdrawal",
                function="withdraw",
                confidence=confidence,
            )

        class Task:
            def run(self, **_: Any) -> Proposals:
                return Proposals(findings=[proposal(2, 2), proposal(5, 2), proposal(3, 2)])

        monkeypatch.setattr(run, "audit_task", lambda source, tools: Task())
        monkeypatch.setattr(run, "tools_for", lambda source: [])
        detector = Slippage()
        answer = run.ask(detector, a_context(detector), BRIEFS[detector.class_id])
        assert answer.failed is None
        assert [f.score for f in answer.findings] == [5.0, 3.0, 2.0]
