"""The contract-assay adapter: the same checks, restated in the benchmark's types.

Skipped when the benchmark is not installed -- it is an optional extra.
"""

from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("contract_assay")

from contract_assay.detectors.base import AnalysisContext, SubmissionLimits
from contract_assay.models import EvidenceTier

from sc_sentry import audit as audit_module
from sc_sentry.briefs import BRIEFS
from sc_sentry.checks import CHECKS
from sc_sentry.classes import VulnClass
from sc_sentry.contract_assay import run
from sc_sentry.contract_assay.detectors import SENTRY_DETECTORS, Slippage
from sc_sentry.task import Proposal, Proposals

from .test_core import VAULT


def a_context(detector: Any, source: str = VAULT) -> AnalysisContext:
    return AnalysisContext(
        source_id="commit:vault@aaaaaaaaaaaa:src/Vault.sol",
        path="src/Vault.sol",
        source=source,
        tier=EvidenceTier.SYNTACTIC,
        level=detector.level,
        limits=SubmissionLimits.for_level(
            detector.level, wall_seconds=60, max_model_calls=4, max_tokens=20_000
        ),
    )


class TestTheDetectors:
    def test_one_detector_per_class_the_harness_checks(self) -> None:
        classes = {VulnClass(cls.class_id.value) for cls in SENTRY_DETECTORS}
        ids = {cls.detector_id for cls in SENTRY_DETECTORS}
        assert classes == set(CHECKS)
        assert len(ids) == len(SENTRY_DETECTORS)

    def test_evidence_is_the_harness_candidates(self) -> None:
        # The adapter adds no judgement: what the benchmark records as
        # established is exactly what `sc-sentry audit` asks about.
        for cls in SENTRY_DETECTORS:
            detector = cls()
            evidence = detector.evidence(a_context(detector))
            candidates = CHECKS[VulnClass(detector.class_id.value)].find(VAULT)
            assert [(e.predicate, e.locator.start_line) for e in evidence] == [
                (c.predicate, c.site.start_line) for c in candidates
            ]

    def test_no_evidence_means_no_question(self) -> None:
        detector = Slippage()
        assert detector.plan(a_context(detector), []) is None

    def test_evidence_means_the_class_brief(self) -> None:
        detector = Slippage()
        ctx = a_context(detector)
        spec = detector.plan(ctx, detector.evidence(ctx))
        assert spec is not None
        assert spec.instruction == BRIEFS[VulnClass.SLIPPAGE]


class TestTheRunsFile:
    def test_findings_carry_the_confidence_as_the_score(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A round ranked on bpref needs a score on every finding of a class.

        The confidence was used to sort and then dropped, so every finding
        reached the scorer unscored and every bpref round left the harness
        unrankable.
        """

        def proposal(confidence: int) -> Proposal:
            return Proposal(
                start_line=5,
                end_line=5,
                quote="swap",
                reasoning="r",
                function="sell",
                confidence=confidence,
            )

        class Task:
            def run(self, **_: Any) -> Proposals:
                return Proposals(findings=[proposal(2), proposal(5), proposal(3)])

        monkeypatch.setattr(audit_module, "audit_task", lambda source, tools: Task())
        monkeypatch.setattr(audit_module, "tools_for", lambda source: [])
        detector = Slippage()
        answer = run.ask(detector, a_context(detector), BRIEFS[VulnClass.SLIPPAGE])
        assert answer.failed is None
        assert [f.score for f in answer.findings] == [5.0, 3.0, 2.0]


class TestTheCommand:
    def test_run_and_score_are_its_subcommands(self, capsys: pytest.CaptureFixture[str]) -> None:
        from sc_sentry.contract_assay.cli import main

        assert main([]) == 2
        assert main(["--help"]) == 0
        assert "run" in capsys.readouterr().out
        with pytest.raises(SystemExit):
            main(["run", "--help"])
        assert "sc-sentry-contract-assay run" in capsys.readouterr().out
        with pytest.raises(SystemExit):
            main(["score", "--help"])
        assert "sc-sentry-contract-assay score" in capsys.readouterr().out
        assert main(["sweep"]) == 2
