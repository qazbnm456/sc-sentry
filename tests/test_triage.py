"""Triage under a budget: what a file costs when a host meters it from outside.

The model is never called. `triage.ask` is replaced by a stand-in that records what it was
asked and how, which is what a budget changes: which classes get a call, how many candidates
each sends, how long the file waits, and what a class that was not answered looks like.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Mapping
from typing import Any

import pytest

from sc_sentry import triage
from sc_sentry.audit import ClassResult, audit
from sc_sentry.checks import CHECKS, parse
from sc_sentry.classes import VulnClass

SWAPS = "\n".join(
    f"""    function sell{i}(address router, uint256 amount) external {{
        IRouter(router).swapExactTokensForTokens(amount, 0, path(), msg.sender, block.timestamp);
        total += amount;
    }}"""
    for i in range(6)
)
SETTERS = "\n".join(
    f"""    function set{i}(uint256 v) external {{
        total = v + {i};
    }}"""
    for i in range(4)
)
HEAD = "pragma solidity ^0.8.20;\ncontract Vault {\n    uint256 public total;\n"
SOURCE = f"{HEAD}{SWAPS}\n{SETTERS}\n}}\n"
SLIPPAGE, ACCESS = VulnClass.SLIPPAGE, VulnClass.ACCESS_CONTROL


class Model:
    """A stand-in for `triage.ask` that says every candidate is an instance."""

    def __init__(self, delay: float = 0.0, hold: threading.Event | None = None) -> None:
        self.delay, self.hold = delay, hold
        self.calls: list[tuple[str, int, Mapping[str, Any]]] = []

    def __call__(
        self, definition: str, table: str, *, count: int, config: Mapping[str, Any] | None = None
    ) -> triage.TriageAnswer:
        self.calls.append((definition.split(".")[0], count, dict(config or {})))
        if self.hold is not None:
            self.hold.wait(10)
        time.sleep(self.delay)
        verdicts = {
            n: triage.Verdict(id=n, instance=True, confidence=5, reasoning="r")
            for n in range(1, count + 1)
        }
        return triage.TriageAnswer(verdicts=verdicts, tokens=10, seconds=self.delay)


def result_of(report_results: tuple[ClassResult, ...], vuln: VulnClass) -> ClassResult:
    return next(r for r in report_results if r.vuln is vuln)


def test_the_fixture_has_more_candidate_functions_in_one_class_than_the_other() -> None:
    parsed = parse(SOURCE)
    assert parsed is not None
    assert len(CHECKS[SLIPPAGE].functions(SOURCE)) == 6
    assert len(CHECKS[ACCESS].functions(SOURCE)) == 10


class TestTheCallsAreSpentWhereThereIsMostToOrder:
    def test_a_call_budget_goes_to_the_class_with_the_most_candidate_functions(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        model = Model()
        monkeypatch.setattr(triage, "ask", model)
        report = audit(
            SOURCE, "V.sol", [SLIPPAGE, ACCESS], mode="triage", budget=triage.Budget(calls=1)
        )
        assert [name for name, _, _ in model.calls] == ["Class: access_control"]
        assert result_of(report.results, ACCESS).asked
        slippage = result_of(report.results, SLIPPAGE)
        assert not slippage.asked and slippage.failed is None
        # The class the budget did not reach is not lost: it keeps its static order.
        assert slippage.findings and {f.origin for f in slippage.findings} == {"static"}

    def test_a_budget_of_no_calls_leaves_every_class_static(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        model = Model()
        monkeypatch.setattr(triage, "ask", model)
        report = audit(
            SOURCE, "V.sol", [SLIPPAGE, ACCESS], mode="triage", budget=triage.Budget(calls=0)
        )
        assert model.calls == []
        assert {f.origin for f in report.findings} == {"static"}

    def test_no_budget_is_the_unbounded_path_and_passes_the_call_no_config(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: list[int] = []

        def ask(definition: str, table: str, *, count: int) -> triage.TriageAnswer:
            seen.append(count)
            return triage.TriageAnswer(verdicts={}, tokens=0, seconds=0.0)

        monkeypatch.setattr(triage, "ask", ask)
        audit(SOURCE, "V.sol", [SLIPPAGE, ACCESS], mode="triage")
        assert seen == [6, 10]
        audit(SOURCE, "V.sol", [SLIPPAGE], mode="triage", budget=triage.Budget())
        assert seen == [6, 10, 6]


class TestTheTokensAreShared:
    def prompt_for(self, vuln: VulnClass, shown: int) -> int:
        parsed = parse(SOURCE)
        assert parsed is not None
        entries = CHECKS[vuln].functions(SOURCE)[:shown]
        text = triage.INSTRUCTIONS + triage.class_definition(vuln) + triage.render(entries, parsed)
        return triage._tokens(text) + triage.FORMAT_OVERHEAD_TOKENS

    def test_candidates_are_trimmed_until_the_answer_has_room(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        model = Model()
        monkeypatch.setattr(triage, "ask", model)
        share = self.prompt_for(SLIPPAGE, triage.MIN_CANDIDATES) + triage.MIN_COMPLETION_TOKENS
        audit(SOURCE, "V.sol", [SLIPPAGE], mode="triage", budget=triage.Budget(tokens=share))
        [(_, count, config)] = model.calls
        assert count == triage.MIN_CANDIDATES
        assert config["max_tokens"] == triage.MIN_COMPLETION_TOKENS

    def test_the_tokens_are_split_equally_between_the_calls(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        model = Model()
        monkeypatch.setattr(triage, "ask", model)
        share = self.prompt_for(ACCESS, 10) + triage.MIN_COMPLETION_TOKENS + 5000
        audit(
            SOURCE,
            "V.sol",
            [SLIPPAGE, ACCESS],
            mode="triage",
            budget=triage.Budget(tokens=share * 2),
        )
        assert sorted(count for _, count, _ in model.calls) == [6, 10]
        for _, _, config in model.calls:
            assert config["max_tokens"] >= triage.MIN_COMPLETION_TOKENS
            assert config["max_tokens"] <= share

    def test_a_class_that_cannot_fit_even_its_fewest_candidates_is_not_asked(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        model = Model()
        monkeypatch.setattr(triage, "ask", model)
        report = audit(SOURCE, "V.sol", [SLIPPAGE], mode="triage", budget=triage.Budget(tokens=100))
        assert model.calls == []
        assert {f.origin for f in report.findings} == {"static"}


class TestTheDeadline:
    def test_the_calls_run_side_by_side_so_a_file_costs_the_slowest_not_the_sum(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(triage, "MIN_SECONDS", 0.0)
        model = Model(delay=0.4)
        monkeypatch.setattr(triage, "ask", model)
        started = time.monotonic()
        report = audit(
            SOURCE, "V.sol", [SLIPPAGE, ACCESS], mode="triage", budget=triage.Budget(seconds=5)
        )
        assert len(model.calls) == 2
        assert time.monotonic() - started < 0.75
        assert all(r.asked for r in report.results)

    def test_a_class_that_has_not_answered_at_the_deadline_keeps_its_static_order(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(triage, "MIN_SECONDS", 0.0)
        release = threading.Event()
        monkeypatch.setattr(triage, "ask", Model(hold=release))
        started = time.monotonic()
        try:
            report = audit(
                SOURCE, "V.sol", [SLIPPAGE], mode="triage", budget=triage.Budget(seconds=0.3)
            )
        finally:
            release.set()
        assert time.monotonic() - started < 2
        result = result_of(report.results, SLIPPAGE)
        assert result.failed is not None and "no answer within" in result.failed
        assert result.findings and {f.origin for f in result.findings} == {"static"}

    def test_the_call_is_given_the_time_that_is_left_as_its_timeout(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(triage, "MIN_SECONDS", 0.0)
        model = Model()
        monkeypatch.setattr(triage, "ask", model)
        audit(SOURCE, "V.sol", [SLIPPAGE], mode="triage", budget=triage.Budget(seconds=20))
        [(_, _, config)] = model.calls
        assert 0 < config["timeout"] <= 20

    def test_too_little_time_to_answer_is_no_call_at_all(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        model = Model()
        monkeypatch.setattr(triage, "ask", model)
        report = audit(
            SOURCE, "V.sol", [SLIPPAGE], mode="triage", budget=triage.Budget(seconds=1.0)
        )
        assert model.calls == []
        assert {f.origin for f in report.findings} == {"static"}


class TestTheCommand:
    def test_a_budget_is_refused_with_a_mode_it_does_not_apply_to(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from sc_sentry import cli

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("RLM_MAIN_MODEL", "m")
        target = tmp_path / "V.sol"
        target.write_text(SOURCE)
        argv = ["audit", str(target), "--mode", "static", "--budget-calls", "2"]
        assert cli.main(argv) == 2
        assert "triage only" in capsys.readouterr().err
