"""The submission side: eight detectors, one per class the corpus can score.

A detector is the part of a harness the benchmark scores *through*. It does not
call a model -- `plan()` says what to ask and the runner asks -- so what lives
here is the deterministic half:

- `evidence()` establishes what is true of the source, and is recorded whatever
  the model concludes;
- `verdict()` rejects what the class definition does not cover, by **asking the
  evidence** rather than re-deriving the observation. That rule is not stylistic:
  a decision that re-derives what an observation established will eventually
  derive it differently, and the two layers then disagree silently.

Verdicts here are deliberately narrow in what they reject. A verdict is a
judgement the run still measures, so rejecting a true finding costs recall with
no compensating signal; rejecting a false one costs an adjudication somebody
would otherwise pay for. Each rejection below is one the class definition
settles, not one about likelihood.
"""

from __future__ import annotations

from collections.abc import Sequence
from functools import lru_cache

from contract_assay.detectors.base import AnalysisContext, Detector, ModelTaskSpec
from contract_assay.evidence.syntax import Site, Syntax
from contract_assay.models import (
    EvidenceRef,
    FailedCheck,
    Finding,
    RejectionKind,
)
from contract_assay.models import (
    VulnerabilityClass as V,
)

from sc_sentry.briefs import BRIEFS


@lru_cache(maxsize=32)
def _syntax(source: str) -> Syntax | None:
    """Parsed once per unit, not once per verdict.

    `evidence()` runs once and `verdict()` runs per finding, so re-parsing for
    each of twenty findings is a cost that only appears under a budget.
    """
    return Syntax.of(source)


def _ref(predicate: str, site: Site, ctx: AnalysisContext, **detail: object) -> EvidenceRef:
    return EvidenceRef(
        predicate=predicate,
        tier=ctx.tier,
        locator=site.locator(ctx.path),
        detail={k: v for k, v in detail.items() if isinstance(v, str | int | float | bool)},
    )


def _covers(
    evidence: Sequence[EvidenceRef], finding: Finding, predicate: str | None = None
) -> bool:
    """Whether the evidence established something at the finding's lines.

    The one question every verdict here asks. Line overlap rather than equality,
    because a model citing a whole statement where the predicate fired on one
    expression inside it has cited the same thing.
    """
    cited = range(finding.locator.start_line, finding.locator.end_line + 1)
    for ref in evidence:
        if predicate is not None and ref.predicate != predicate:
            continue
        if ref.locator.start_line <= cited.stop - 1 and cited.start <= ref.locator.end_line:
            return True
    return False


class _Base(Detector):
    """Shared plumbing, and it really does declare none of the three fields.

    `detector_id`, `class_id` and `api_version` are declared all together or not
    at all, and this class is not an entry point, so it declares none. It also
    does not declare `level`: that is a property derived from `class_id`, and a
    class attribute here would shadow it and report every class at one level.
    """

    def plan(self, ctx: AnalysisContext, evidence: Sequence[EvidenceRef]) -> ModelTaskSpec | None:
        """The brief for this class, or nothing when the unit holds no candidates.

        `None` when `evidence()` found nothing to reason about: a call not made
        is budget left for the next unit, and a planner asked to audit a file
        with no sites of the class will invent one.
        """
        if not evidence:
            return None
        return ModelTaskSpec(instruction=BRIEFS[self.class_id], max_steps=6)

    def _not_established(self, what: str) -> FailedCheck:
        return FailedCheck(
            check=f"{what}_established_here",
            kind=RejectionKind.VERDICT,
            detail=f"evidence() established no {what.replace('_', ' ')} at the cited lines",
        )


class AccessControl(_Base):
    """A state-changing path with nothing establishing the caller's right to it."""

    detector_id = "sentry-access-control"
    class_id = V.ACCESS_CONTROL
    api_version = "1.1"

    def evidence(self, ctx: AnalysisContext) -> Sequence[EvidenceRef]:
        parsed = _syntax(ctx.source)
        if parsed is None:
            return []
        reachable = {
            fn.site.host.function
            for fn in parsed.functions
            if fn.is_externally_reachable and not fn.is_read_only
        }
        out: list[EvidenceRef] = []
        for w in parsed.writes:
            if w.site.host.function not in reachable:
                continue
            out.append(
                _ref(
                    "state_write_on_an_externally_reachable_path",
                    w.site,
                    ctx,
                    target=w.target_root or "",
                    function=w.site.host.function or "",
                )
            )
        return out

    def verdict(
        self, ctx: AnalysisContext, finding: Finding, evidence: Sequence[EvidenceRef]
    ) -> Sequence[FailedCheck]:
        if not _covers(evidence, finding):
            # Either not a state write, or not on an externally reachable path.
            # Both are settled by the class definition rather than by likelihood.
            return [self._not_established("reachable_state_write")]
        return []


class Reentrancy(_Base):
    """A state write after an external call in the same function."""

    detector_id = "sentry-reentrancy"
    class_id = V.REENTRANCY
    api_version = "1.1"

    def evidence(self, ctx: AnalysisContext) -> Sequence[EvidenceRef]:
        parsed = _syntax(ctx.source)
        if parsed is None:
            return []
        first_call: dict[str | None, int] = {}
        for c in parsed.calls:
            fn = c.site.host.function
            first_call[fn] = min(first_call.get(fn, 10**9), c.site.start_line)
        out: list[EvidenceRef] = []
        for c in parsed.calls:
            out.append(_ref("external_call", c.site, ctx, callee=c.callee or ""))
        for w in parsed.writes:
            after = first_call.get(w.site.host.function)
            if after is not None and w.site.start_line > after:
                out.append(
                    _ref(
                        "state_write_after_an_external_call",
                        w.site,
                        ctx,
                        call_line=after,
                        target=w.target_root or "",
                    )
                )
        return out

    def verdict(
        self, ctx: AnalysisContext, finding: Finding, evidence: Sequence[EvidenceRef]
    ) -> Sequence[FailedCheck]:
        # Either end of the pair is a legitimate citation: the call is what has
        # to move, and the write is what has to move before it. Asking for one
        # specific end would reject a true finding for choosing the other.
        if _covers(evidence, finding, "state_write_after_an_external_call") or _covers(
            evidence, finding, "external_call"
        ):
            return []
        return [self._not_established("call_or_write")]


class UncheckedExternalCall(_Base):
    """A call whose failure is discarded."""

    detector_id = "sentry-unchecked-external-call"
    class_id = V.UNCHECKED_EXTERNAL_CALL
    api_version = "1.1"

    def evidence(self, ctx: AnalysisContext) -> Sequence[EvidenceRef]:
        parsed = _syntax(ctx.source)
        if parsed is None:
            return []
        out: list[EvidenceRef] = []
        for c in parsed.calls:
            if c.is_low_level and not c.bound_names:
                out.append(
                    _ref("low_level_call_with_no_bound_result", c.site, ctx, callee=c.callee or "")
                )
            elif c.is_bare_statement:
                # The shape with no symptom at the call site: an interface call
                # returning a discardable bool, used as a statement.
                out.append(
                    _ref("call_result_used_as_a_statement", c.site, ctx, callee=c.callee or "")
                )
        return out

    def verdict(
        self, ctx: AnalysisContext, finding: Finding, evidence: Sequence[EvidenceRef]
    ) -> Sequence[FailedCheck]:
        if not _covers(evidence, finding):
            return [self._not_established("discarded_call_result")]
        return []


class OracleIntegrity(_Base):
    """A value read from outside and used without establishing that it can be trusted."""

    detector_id = "sentry-oracle-integrity"
    class_id = V.ORACLE_INTEGRITY
    api_version = "1.1"
    _READS = (
        "latestRoundData",
        "latestAnswer",
        "latestRound",
        "getReserves",
        "slot0",
        "getAmountsOut",
        "quote",
        "getPrice",
        "price",
        "consult",
        "observe",
        "getPriceUnsafe",
        "getPriceNoOlderThan",
    )

    def evidence(self, ctx: AnalysisContext) -> Sequence[EvidenceRef]:
        parsed = _syntax(ctx.source)
        if parsed is None:
            return []
        out: list[EvidenceRef] = []
        for c in parsed.calls:
            if c.callee in self._READS:
                out.append(_ref("external_value_read", c.site, ctx, callee=c.callee))
        for site, _obj, member in parsed.member_reads:
            if member in self._READS:
                out.append(_ref("external_value_read", site, ctx, member=member))
        return out

    def verdict(
        self, ctx: AnalysisContext, finding: Finding, evidence: Sequence[EvidenceRef]
    ) -> Sequence[FailedCheck]:
        # The skill tells the model to cite the line that USES the value, which
        # may be below the read. So the function is the unit of agreement here,
        # not the line -- asking for line overlap would reject exactly the
        # citation the skill asks for.
        parsed = _syntax(ctx.source)
        if parsed is None:
            return []
        cited = parsed.callable_at(finding.locator.start_line)
        named = {ref.locator.function for ref in evidence}
        if cited is not None and cited.names and cited.names[0] in named:
            return []
        if _covers(evidence, finding):
            return []
        return [self._not_established("external_value_read_in_this_function")]


class ArithmeticRounding(_Base):
    """Arithmetic whose result is wrong in a direction that matters."""

    detector_id = "sentry-arithmetic-rounding"
    class_id = V.ARITHMETIC_ROUNDING
    api_version = "1.1"

    def evidence(self, ctx: AnalysisContext) -> Sequence[EvidenceRef]:
        parsed = _syntax(ctx.source)
        if parsed is None:
            return []
        out: list[EvidenceRef] = []
        for a in parsed.arithmetic:
            if a.divides_then_scales:
                out.append(_ref("division_before_scaling", a.site, ctx, operator=a.operator or ""))
            elif "/" in (a.operand_operators or ()) or a.operator == "/":
                out.append(_ref("division", a.site, ctx, operator=a.operator or ""))
        return out

    def verdict(
        self, ctx: AnalysisContext, finding: Finding, evidence: Sequence[EvidenceRef]
    ) -> Sequence[FailedCheck]:
        if not _covers(evidence, finding):
            return [self._not_established("division")]
        return []


class Slippage(_Base):
    """An exchange with no enforced bound on what comes back."""

    detector_id = "sentry-slippage"
    class_id = V.SLIPPAGE
    api_version = "1.1"
    _SWAPS = (
        "swap",
        "swapExactTokensForTokens",
        "swapTokensForExactTokens",
        "swapExactETHForTokens",
        "swapExactTokensForETH",
        "exactInputSingle",
        "exactInput",
        "exactOutputSingle",
        "addLiquidity",
        "removeLiquidity",
        "addLiquidityETH",
        "removeLiquidityETH",
        "exchange",
        "swapExactTokensForTokensSupportingFeeOnTransferTokens",
    )

    def evidence(self, ctx: AnalysisContext) -> Sequence[EvidenceRef]:
        parsed = _syntax(ctx.source)
        if parsed is None:
            return []
        out: list[EvidenceRef] = []
        for c in parsed.calls:
            if c.callee in self._SWAPS or (c.callee or "").startswith("swap"):
                zeros = [a.text for a in c.arguments if a.is_zero_literal]
                out.append(
                    _ref(
                        "exchange_call",
                        c.site,
                        ctx,
                        callee=c.callee or "",
                        zero_arguments=len(zeros),
                    )
                )
        return out

    def verdict(
        self, ctx: AnalysisContext, finding: Finding, evidence: Sequence[EvidenceRef]
    ) -> Sequence[FailedCheck]:
        parsed = _syntax(ctx.source)
        if parsed is not None:
            cited = parsed.callable_at(finding.locator.start_line)
            named = {ref.locator.function for ref in evidence}
            if cited is not None and cited.names and cited.names[0] in named:
                # The bound may be computed above the call, and the skill says to
                # cite the computation. Same function is the agreement.
                return []
        if _covers(evidence, finding):
            return []
        return [self._not_established("exchange_call_in_this_function")]


class DenialOfService(_Base):
    """A path an outsider can make permanently unusable for somebody else."""

    detector_id = "sentry-denial-of-service"
    class_id = V.DENIAL_OF_SERVICE
    api_version = "1.1"

    def evidence(self, ctx: AnalysisContext) -> Sequence[EvidenceRef]:
        parsed = _syntax(ctx.source)
        if parsed is None:
            return []
        out: list[EvidenceRef] = []
        for ls in parsed.loops:
            out.append(
                _ref(
                    "loop",
                    ls.site,
                    ctx,
                    bound_on=",".join(ls.bound_identifiers or ()),
                )
            )
        loop_spans = [(ls.site.start_line, ls.site.end_line) for ls in parsed.loops]
        for c in parsed.calls:
            if any(a <= c.site.start_line <= b for a, b in loop_spans):
                out.append(_ref("external_call_inside_a_loop", c.site, ctx, callee=c.callee or ""))
        for g in parsed.guards:
            out.append(_ref("revert_condition", g.site, ctx))
        return out

    def verdict(
        self, ctx: AnalysisContext, finding: Finding, evidence: Sequence[EvidenceRef]
    ) -> Sequence[FailedCheck]:
        if not _covers(evidence, finding):
            return [self._not_established("loop_call_or_revert")]
        return []


class InsecureRandomness(_Base):
    """A value used as unpredictable that somebody can influence."""

    detector_id = "sentry-insecure-randomness"
    class_id = V.INSECURE_RANDOMNESS
    api_version = "1.1"
    _SOURCES = ("timestamp", "number", "prevrandao", "difficulty", "coinbase", "blockhash")

    def evidence(self, ctx: AnalysisContext) -> Sequence[EvidenceRef]:
        parsed = _syntax(ctx.source)
        if parsed is None:
            return []
        out: list[EvidenceRef] = []
        for site, obj, member in parsed.member_reads:
            if obj == "block" and member in self._SOURCES:
                out.append(_ref("chain_state_read", site, ctx, member=member))
        for c in parsed.calls:
            if c.callee in {"keccak256", "blockhash", "sha256"}:
                out.append(_ref("hash_of_chain_state", c.site, ctx, callee=c.callee))
        return out

    def verdict(
        self, ctx: AnalysisContext, finding: Finding, evidence: Sequence[EvidenceRef]
    ) -> Sequence[FailedCheck]:
        if not _covers(evidence, finding):
            return [self._not_established("influenceable_value")]
        return []


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
