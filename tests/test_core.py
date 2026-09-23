"""The harness on its own: no benchmark installed, no model called.

Each test pins something a model run depends on and would hide if it broke: a
class with no check is a class that is never looked for, a candidate missed is
a question never asked, and a rejected finding dropped from the report is a
screen nobody can audit.
"""

from __future__ import annotations

import subprocess
import sys
from typing import Any

import pytest

from sc_sentry import audit as audit_module
from sc_sentry.audit import Answer, audit
from sc_sentry.briefs import BRIEFS
from sc_sentry.checks import CHECKS
from sc_sentry.classes import VulnClass
from sc_sentry.report import to_json, to_sarif
from sc_sentry.task import Proposal

VAULT = """pragma solidity ^0.8.20;
contract Vault {
    uint256 public total;
    function sell(address router, uint256 amount) external {
        IRouter(router).swapExactTokensForTokens(amount, 0, path(), msg.sender, block.timestamp);
        total += amount;
    }
    function set(uint256 v) external {
        total = v;
    }
}
"""


def a_proposal(line: int, confidence: int, function: str = "sell") -> Proposal:
    return Proposal(
        start_line=line,
        end_line=line,
        quote=VAULT.splitlines()[line - 1].strip(),
        reasoning="the minimum out is the literal zero",
        function=function,
        confidence=confidence,
    )


class TestTheClasses:
    def test_every_class_has_a_check_and_a_brief(self) -> None:
        assert set(CHECKS) == set(VulnClass)
        assert set(BRIEFS) == set(VulnClass)

    def test_the_core_needs_no_benchmark(self) -> None:
        # The whole point of the split: a person auditing a contract installs
        # the harness, not a benchmark.
        code = (
            "import sys, sc_sentry.cli, sc_sentry.audit, sc_sentry.report, sc_sentry.checks;"
            "sys.exit('contract_assay' in sys.modules)"
        )
        assert subprocess.run([sys.executable, "-c", code], check=False).returncode == 0


class TestCandidates:
    def test_an_exchange_call_is_a_slippage_candidate(self) -> None:
        found = CHECKS[VulnClass.SLIPPAGE].find(VAULT)
        assert [(c.predicate, c.site.start_line, c.detail["zero_arguments"]) for c in found] == [
            ("exchange_call", 5, 1)
        ]

    def test_a_file_that_does_not_parse_has_no_candidates(self) -> None:
        assert CHECKS[VulnClass.REENTRANCY].find("") == []


class TestTheAudit:
    def test_a_class_with_no_candidates_is_never_asked(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asked: list[str] = []

        def ask(source: str, brief: str) -> Answer:
            asked.append(brief)
            return Answer(proposals=(), tokens=0, seconds=0.0)

        monkeypatch.setattr(audit_module, "ask", ask)
        report = audit(VAULT, "Vault.sol", [VulnClass.SLIPPAGE, VulnClass.INSECURE_RANDOMNESS])
        by_class = {r.vuln: r for r in report.results}
        assert by_class[VulnClass.SLIPPAGE].asked
        # `block.timestamp` is a chain-state read, so randomness has a candidate
        # too; the class asked about with none is checked below.
        assert asked == [BRIEFS[VulnClass.SLIPPAGE], BRIEFS[VulnClass.INSECURE_RANDOMNESS]]
        # No price or reserve is read anywhere in VAULT: nothing to ask about.
        report = audit(VAULT, "Vault.sol", [VulnClass.ORACLE_INTEGRITY])
        assert (report.results[0].candidates, report.results[0].asked) == (0, False)
        assert len(asked) == 2

    def test_a_citation_outside_the_class_is_kept_and_marked(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def ask(source: str, brief: str) -> Answer:
            return Answer(
                proposals=(a_proposal(5, 5), a_proposal(9, 2, function="set")),
                tokens=100,
                seconds=1.0,
            )

        monkeypatch.setattr(audit_module, "ask", ask)
        [result] = audit(VAULT, "Vault.sol", [VulnClass.SLIPPAGE]).results
        assert [(f.start_line, f.confidence, f.rejected) for f in result.findings] == [
            (5, 5, None),
            (9, 2, "exchange_call_in_this_function"),
        ]


class TestTheReport:
    def a_report(self, monkeypatch: pytest.MonkeyPatch) -> Any:
        monkeypatch.setattr(
            audit_module,
            "ask",
            lambda source, brief: Answer(
                proposals=(a_proposal(5, 5), a_proposal(9, 2, function="set")),
                tokens=100,
                seconds=1.0,
            ),
        )
        return audit(VAULT, "Vault.sol", [VulnClass.SLIPPAGE])

    def test_sarif_suppresses_a_rejected_finding_rather_than_dropping_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        document = to_sarif([self.a_report(monkeypatch)])
        assert document["version"] == "2.1.0"
        [run] = document["runs"]
        assert {rule["id"] for rule in run["tool"]["driver"]["rules"]} == {
            c.value for c in VulnClass
        }
        standing, rejected = run["results"]
        assert standing["ruleId"] == "slippage"
        assert standing["rank"] == 100.0
        assert "suppressions" not in standing
        region = standing["locations"][0]["physicalLocation"]["region"]
        assert (region["startLine"], region["endLine"]) == (5, 5)
        assert rejected["suppressions"][0]["kind"] == "external"

    def test_json_keeps_every_class_asked_and_what_it_cost(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        [file] = to_json([self.a_report(monkeypatch)])["files"]
        [cls] = file["classes"]
        assert (cls["class"], cls["candidates"], cls["tokens"]) == ("slippage", 1, 100)
        assert [f["rejected"] for f in cls["findings"]] == [None, "exchange_call_in_this_function"]


class TestTheAsk:
    def test_proposals_come_back_most_confident_first(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from sc_sentry.task import Proposals

        class Task:
            def run(self, **_: Any) -> Proposals:
                return Proposals(findings=[a_proposal(5, 2), a_proposal(5, 5), a_proposal(5, 3)])

        monkeypatch.setattr(audit_module, "audit_task", lambda source, tools: Task())
        monkeypatch.setattr(audit_module, "tools_for", lambda source: [])
        answer = audit_module.ask(VAULT, BRIEFS[VulnClass.SLIPPAGE])
        assert answer.failed is None
        assert [p.confidence for p in answer.proposals] == [5, 3, 2]


class TestTheCommand:
    def test_classes_may_be_comma_separated_and_repeated(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
    ) -> None:
        from sc_sentry import cli

        seen: list[Any] = []
        monkeypatch.setenv("RLM_MAIN_MODEL", "m")
        monkeypatch.setattr(audit_module, "configure_once", lambda **_: None)
        monkeypatch.setattr(
            audit_module,
            "audit",
            lambda source, path, classes: (
                seen.append(classes) or audit_module.Report(file=path, model="m")
            ),
        )
        target = tmp_path / "Vault.sol"
        target.write_text(VAULT)
        argv = ["audit", str(target), "--class", "slippage,reentrancy", "--class", "slippage"]
        assert cli.main([*argv, "--out", str(tmp_path / "r.json")]) == 0
        assert seen == [[VulnClass.SLIPPAGE, VulnClass.REENTRANCY]]
        assert cli.main(["audit", str(target), "--class", "nonsense"]) == 2
