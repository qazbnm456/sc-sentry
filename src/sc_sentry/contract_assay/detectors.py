"""The harness's checks, as contract-assay `Detector`s: one per class.

A detector is the part of a harness the benchmark scores *through*. It does not call a model:
`plan()` says what to ask, and the runner asks. What lives here is therefore the deterministic half,
restated in the benchmark's types:

- `evidence()` is `sc_sentry.checks`'s candidates, as `EvidenceRef`s.
- `verdict()` is `sc_sentry.checks`'s rejection. It **asks the evidence it was given** rather than
  deriving the observation again, so the benchmark's record of what was established and the verdict
  cannot disagree.

Nothing is decided here that `sc-sentry audit` does not also decide.
"""

from __future__ import annotations

from collections.abc import Sequence

from contract_assay.detectors.base import AnalysisContext, Detector, ModelTaskSpec
from contract_assay.models import (
    DEFAULT_PREDICTIONS_PER_UNIT,
    EvidenceRef,
    FailedCheck,
    Finding,
    Locator,
    RejectionKind,
)
from contract_assay.models import (
    VulnerabilityClass as V,
)

from sc_sentry import audit as sc_audit
from sc_sentry.briefs import BRIEFS
from sc_sentry.checks import CHECKS, Check, Span, parse
from sc_sentry.classes import VulnClass
from sc_sentry.static import static_findings

__all__ = ["SENTRY_DETECTORS", "STATIC_DETECTORS", "to_benchmark_findings"]


def to_benchmark_findings(
    detector_id: str, path: str, findings: Sequence[sc_audit.Finding]
) -> tuple[Finding, ...]:
    """The harness's findings as the benchmark's, scored by position.

    The list is already in the order the harness stands behind, so a finding's score is how far
    from the end it sits. That keeps the order for a round ranked on bpref, which needs a score on
    every finding of a class, without inventing a confidence the harness never had for the findings
    no model looked at.
    """
    count = len(findings)
    return tuple(
        Finding(
            detector_id=detector_id,
            locator=Locator(
                file=path,
                contract=f.contract,
                function=f.function,
                start_line=f.start_line,
                end_line=max(f.end_line, f.start_line),
            ),
            quote=f.quote,
            reasoning=f.reasoning,
            score=float(count - index),
        )
        for index, f in enumerate(findings)
    )


class _Base(Detector):
    """Shared plumbing, which deliberately declares none of the three identity fields.

    `detector_id`, `class_id` and `api_version` are declared all together or not at all, and this
    class is not an entry point, so it declares none. It does not declare `level` either: that is a
    property derived from `class_id`, and a class attribute here would shadow it and report every
    class at one level.
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

        `None` when `evidence()` found nothing to reason about: a call not made is budget left for
        the next unit, and a planner asked to audit a file with no sites of the class will invent
        one.
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


class _Static(_Base):
    """The same checks with no model: `propose()` asserts the candidate functions.

    This is the harness's own control group. It asks for no model (`plan()` returns `None`), so
    `contract-assay run` needs no caller, and it scores what the checks find and how they order it,
    at the benchmark's default cap. A figure from the model-backed detectors means something only
    beside this one.
    """

    def plan(self, ctx: AnalysisContext, evidence: Sequence[EvidenceRef]) -> ModelTaskSpec | None:
        return None

    def propose(self, ctx: AnalysisContext, evidence: Sequence[EvidenceRef]) -> Sequence[Finding]:
        found = static_findings(
            VulnClass(self.class_id.value), ctx.source, ctx.path, limit=DEFAULT_PREDICTIONS_PER_UNIT
        )
        return to_benchmark_findings(self.detector_id, ctx.path, found)


class StaticAccessControl(_Static, AccessControl):
    detector_id = "sentry-static-access-control"


class StaticReentrancy(_Static, Reentrancy):
    detector_id = "sentry-static-reentrancy"


class StaticUncheckedExternalCall(_Static, UncheckedExternalCall):
    detector_id = "sentry-static-unchecked-external-call"


class StaticOracleIntegrity(_Static, OracleIntegrity):
    detector_id = "sentry-static-oracle-integrity"


class StaticArithmeticRounding(_Static, ArithmeticRounding):
    detector_id = "sentry-static-arithmetic-rounding"


class StaticSlippage(_Static, Slippage):
    detector_id = "sentry-static-slippage"


class StaticDenialOfService(_Static, DenialOfService):
    detector_id = "sentry-static-denial-of-service"


class StaticInsecureRandomness(_Static, InsecureRandomness):
    detector_id = "sentry-static-insecure-randomness"


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

STATIC_DETECTORS: tuple[type[Detector], ...] = (
    StaticAccessControl,
    StaticArithmeticRounding,
    StaticDenialOfService,
    StaticInsecureRandomness,
    StaticOracleIntegrity,
    StaticReentrancy,
    StaticSlippage,
    StaticUncheckedExternalCall,
)
