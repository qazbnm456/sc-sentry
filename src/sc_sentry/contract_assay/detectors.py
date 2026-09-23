"""The harness's checks, as contract-assay `Detector`s: one per class.

A detector is the part of a harness the benchmark scores *through*. It does not
call a model -- `plan()` says what to ask and the runner asks -- so what lives
here is the deterministic half, restated in the benchmark's types:

- `evidence()` is `sc_sentry.checks`'s candidates, as `EvidenceRef`s;
- `verdict()` is `sc_sentry.checks`'s rejection, **asking the evidence it was
  given** rather than re-deriving the observation, so the benchmark's record of
  what was established and the verdict cannot disagree.

Nothing is decided here that `sc-sentry audit` does not also decide.
"""

from __future__ import annotations

from collections.abc import Sequence

from contract_assay.detectors.base import AnalysisContext, Detector, ModelTaskSpec
from contract_assay.models import (
    EvidenceRef,
    FailedCheck,
    Finding,
    Locator,
    RejectionKind,
)
from contract_assay.models import (
    VulnerabilityClass as V,
)

from sc_sentry.briefs import BRIEFS
from sc_sentry.checks import CHECKS, Check, Span, parse
from sc_sentry.classes import VulnClass

__all__ = ["SENTRY_DETECTORS"]


class _Base(Detector):
    """Shared plumbing, and it really does declare none of the three fields.

    `detector_id`, `class_id` and `api_version` are declared all together or not
    at all, and this class is not an entry point, so it declares none. It also
    does not declare `level`: that is a property derived from `class_id`, and a
    class attribute here would shadow it and report every class at one level.
    """

    @property
    def _check(self) -> Check:
        return CHECKS[VulnClass(self.class_id.value)]

    def evidence(self, ctx: AnalysisContext) -> Sequence[EvidenceRef]:
        return [
            EvidenceRef(
                predicate=candidate.predicate,
                tier=ctx.tier,
                locator=Locator(
                    file=ctx.path,
                    contract=candidate.site.host.contract,
                    function=candidate.site.host.function,
                    start_line=candidate.site.start_line,
                    end_line=candidate.site.end_line,
                ),
                detail=dict(candidate.detail),
            )
            for candidate in self._check.find(ctx.source)
        ]

    def plan(self, ctx: AnalysisContext, evidence: Sequence[EvidenceRef]) -> ModelTaskSpec | None:
        """The brief for this class, or nothing when the unit holds no candidates.

        `None` when `evidence()` found nothing to reason about: a call not made
        is budget left for the next unit, and a planner asked to audit a file
        with no sites of the class will invent one.
        """
        if not evidence:
            return None
        return ModelTaskSpec(instruction=BRIEFS[VulnClass(self.class_id.value)], max_steps=6)

    def verdict(
        self, ctx: AnalysisContext, finding: Finding, evidence: Sequence[EvidenceRef]
    ) -> Sequence[FailedCheck]:
        spans = [
            Span(ref.predicate, ref.locator.start_line, ref.locator.end_line, ref.locator.function)
            for ref in evidence
        ]
        what = self._check.rejects(
            parse(ctx.source), spans, finding.locator.start_line, finding.locator.end_line
        )
        if what is None:
            return []
        return [
            FailedCheck(
                check=f"{what}_established_here",
                kind=RejectionKind.VERDICT,
                detail=f"evidence() established no {what.replace('_', ' ')} at the cited lines",
            )
        ]


class AccessControl(_Base):
    detector_id = "sentry-access-control"
    class_id = V.ACCESS_CONTROL
    api_version = "1.1"


class Reentrancy(_Base):
    detector_id = "sentry-reentrancy"
    class_id = V.REENTRANCY
    api_version = "1.1"


class UncheckedExternalCall(_Base):
    detector_id = "sentry-unchecked-external-call"
    class_id = V.UNCHECKED_EXTERNAL_CALL
    api_version = "1.1"


class OracleIntegrity(_Base):
    detector_id = "sentry-oracle-integrity"
    class_id = V.ORACLE_INTEGRITY
    api_version = "1.1"


class ArithmeticRounding(_Base):
    detector_id = "sentry-arithmetic-rounding"
    class_id = V.ARITHMETIC_ROUNDING
    api_version = "1.1"


class Slippage(_Base):
    detector_id = "sentry-slippage"
    class_id = V.SLIPPAGE
    api_version = "1.1"


class DenialOfService(_Base):
    detector_id = "sentry-denial-of-service"
    class_id = V.DENIAL_OF_SERVICE
    api_version = "1.1"


class InsecureRandomness(_Base):
    detector_id = "sentry-insecure-randomness"
    class_id = V.INSECURE_RANDOMNESS
    api_version = "1.1"


SENTRY_DETECTORS: tuple[type[Detector], ...] = (
    AccessControl,
    ArithmeticRounding,
    DenialOfService,
    InsecureRandomness,
    OracleIntegrity,
    Reentrancy,
    Slippage,
    UncheckedExternalCall,
)
