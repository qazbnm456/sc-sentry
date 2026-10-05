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
    def test_an_exchange_with_a_zero_minimum_is_a_slippage_candidate(self) -> None:
        found = CHECKS[VulnClass.SLIPPAGE].find(VAULT)
        assert [(c.predicate, c.site.start_line, c.detail["zero_args"]) for c in found] == [
            ("zero_bound", 5, 1)
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


class TestTheFindingsNeedNoModel:
    """`--mode static`: the candidates, one per function, as the control group for the model."""

    def test_a_function_with_several_candidates_is_one_entry(self) -> None:
        # `sell` holds the call and the write after it, and a cap counts findings, so the
        # function must cost one.
        [entry] = CHECKS[VulnClass.REENTRANCY].functions(VAULT)
        assert (entry.contract, entry.function) == ("Vault", "sell")
        assert len(entry.candidates) > 1
        assert {c.predicate for c in entry.candidates} == {
            "external_call",
            "state_write_after_an_external_call",
        }
        assert entry.best is entry.candidates[0]  # the earliest, with no priority

    def test_priority_chooses_the_site_that_stands_for_the_function(self) -> None:
        from sc_sentry.checks import group_by_function

        candidates = CHECKS[VulnClass.REENTRANCY].find(VAULT)
        [entry] = group_by_function(
            candidates, lambda c: 1.0 if c.predicate.startswith("state_write") else 0.0
        )
        assert entry.best.predicate == "state_write_after_an_external_call"

    def test_functions_come_out_likeliest_first(self) -> None:
        from sc_sentry.checks import group_by_function

        candidates = CHECKS[VulnClass.ACCESS_CONTROL].find(VAULT)
        assert [e.function for e in group_by_function(candidates)] == ["sell", "set"]
        ranked = group_by_function(
            candidates, lambda c: 1.0 if c.site.host.function == "set" else 0.0
        )
        assert [e.function for e in ranked] == ["set", "sell"]

    def test_a_finding_quotes_whole_lines_and_says_no_model_reviewed_it(self) -> None:
        from sc_sentry.static import static_findings

        [finding] = static_findings(VulnClass.SLIPPAGE, VAULT, "src/Vault.sol")
        assert finding.origin == "static"
        assert finding.quote == VAULT.splitlines()[finding.start_line - 1]
        assert (finding.contract, finding.function) == ("Vault", "sell")
        assert "not reviewed by a model" in finding.reasoning

    def test_the_limit_keeps_the_first_functions(self) -> None:
        from sc_sentry.static import static_findings

        both = static_findings(VulnClass.ACCESS_CONTROL, VAULT, "src/Vault.sol")
        one = static_findings(VulnClass.ACCESS_CONTROL, VAULT, "src/Vault.sol", limit=1)
        assert len(both) == 2 and one == both[:1]

    def test_a_static_audit_never_reaches_the_model(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def never(source: str, brief: str) -> Answer:
            raise AssertionError("static mode must not ask a model")

        monkeypatch.setattr(audit_module, "ask", never)
        report = audit(VAULT, "src/Vault.sol", [VulnClass.SLIPPAGE], mode="static")
        [result] = report.results
        assert (result.asked, result.candidates, len(result.findings)) == (False, 1, 1)

    def test_the_command_needs_no_model_for_it(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
    ) -> None:
        import json

        from sc_sentry import cli

        monkeypatch.chdir(tmp_path)  # never the repository's own .env
        monkeypatch.delenv("RLM_MAIN_MODEL", raising=False)
        target = tmp_path / "Vault.sol"
        target.write_text(VAULT)
        out = tmp_path / "r.json"
        assert (
            cli.main(
                ["audit", str(target), "--mode", "static", "--class", "slippage", "--out", str(out)]
            )
            == 0
        )
        [file] = json.loads(out.read_text())["files"]
        assert [f["origin"] for f in file["classes"][0]["findings"]] == ["static"]
        # Without --mode static the same command still refuses to start with no model named.
        assert cli.main(["audit", str(target), "--class", "slippage"]) == 2


class TestWhatTheAskCost:
    def test_usage_is_kept_per_model_with_its_calls_and_tokens(self) -> None:
        usage = audit_module.usage_of(
            {
                "openai/main": [
                    {"total_tokens": 100},
                    {"prompt_tokens": 20, "completion_tokens": 5},
                ],
                "openai/sub": [{"total_tokens": 7}],
            }
        )
        assert usage == (("openai/main", 2, 125), ("openai/sub", 1, 7))

    def test_a_failed_planner_still_reports_what_it_spent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A cost that counted only the runs that succeeded would let a sweep that kept
        # failing report that it had cost nothing.
        import contextlib

        import dspy

        class Tracker:
            def __init__(self) -> None:
                self.usage_data = {"m": [{"total_tokens": 321}]}

        class Task:
            def run(self, **_: Any) -> None:
                raise RuntimeError("the endpoint went away")

        monkeypatch.setattr(dspy, "track_usage", lambda: contextlib.nullcontext(Tracker()))
        monkeypatch.setattr(audit_module, "audit_task", lambda source, tools: Task())
        monkeypatch.setattr(audit_module, "tools_for", lambda source: [])
        answer = audit_module.ask(VAULT, BRIEFS[VulnClass.SLIPPAGE])
        assert answer.failed == "RuntimeError: the endpoint went away"
        assert (answer.tokens, answer.usage) == (321, (("m", 1, 321),))


class TestTheCommand:
    def test_classes_may_be_comma_separated_and_repeated(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
    ) -> None:
        from sc_sentry import cli

        seen: list[Any] = []
        monkeypatch.chdir(tmp_path)  # never the repository's own .env
        monkeypatch.setenv("RLM_MAIN_MODEL", "m")
        monkeypatch.setattr(audit_module, "configure_once", lambda **_: None)
        monkeypatch.setattr(
            audit_module,
            "audit",
            lambda source, path, classes, **_: (
                seen.append(classes) or audit_module.Report(file=path, model="m")
            ),
        )
        target = tmp_path / "Vault.sol"
        target.write_text(VAULT)
        argv = ["audit", str(target), "--class", "slippage,reentrancy", "--class", "slippage"]
        assert cli.main([*argv, "--out", str(tmp_path / "r.json")]) == 0
        assert seen == [[VulnClass.SLIPPAGE, VulnClass.REENTRANCY]]
        assert cli.main(["audit", str(target), "--class", "nonsense"]) == 2


class TestTheEnvironment:
    def test_env_file_fills_only_what_is_unset(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
    ) -> None:
        from sc_sentry import dotenv

        env = tmp_path / ".env"
        env.write_text(
            "# comment\nRLM_MAIN_MODEL='from-file'\nexport RLM_SUB_MODEL=\"sub\"\n"
            "RLM_BASE_URL=http://x\nnot a line\n"
        )
        monkeypatch.setenv("RLM_BASE_URL", "http://already")
        monkeypatch.setenv("RLM_MAIN_MODEL", "")  # restored afterwards, whatever load() sets
        monkeypatch.delenv("RLM_MAIN_MODEL")
        monkeypatch.setenv("RLM_SUB_MODEL", "")  # restored afterwards, whatever load() sets
        monkeypatch.delenv("RLM_SUB_MODEL")
        assert dotenv.load(env) == ["RLM_MAIN_MODEL", "RLM_SUB_MODEL"]
        import os

        assert os.environ["RLM_MAIN_MODEL"] == "from-file"
        assert os.environ["RLM_SUB_MODEL"] == "sub"
        assert os.environ["RLM_BASE_URL"] == "http://already"
        assert dotenv.load(tmp_path / "absent") == []

    def test_the_command_reads_env_from_the_working_directory(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
    ) -> None:
        from sc_sentry import cli

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("RLM_MAIN_MODEL", "")  # restored afterwards, whatever load() sets
        monkeypatch.delenv("RLM_MAIN_MODEL")
        target = tmp_path / "Vault.sol"
        target.write_text(VAULT)
        assert cli.main(["audit", str(target)]) == 2
        (tmp_path / ".env").write_text("RLM_MAIN_MODEL=m\n")
        monkeypatch.setattr(audit_module, "configure_once", lambda **_: None)
        monkeypatch.setattr(
            audit_module,
            "audit",
            lambda source, path, classes, **_: audit_module.Report(file=path, model="m"),
        )
        assert cli.main(["audit", str(target), "--out", str(tmp_path / "r.json")]) == 0

    def test_max_tokens_flag_then_environment_then_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from sc_sentry.audit import DEFAULT_MAX_TOKENS, resolve_max_tokens

        monkeypatch.delenv("RLM_MAX_TOKENS", raising=False)
        assert resolve_max_tokens(None) == DEFAULT_MAX_TOKENS
        monkeypatch.setenv("RLM_MAX_TOKENS", "")
        assert resolve_max_tokens(None) == DEFAULT_MAX_TOKENS
        monkeypatch.setenv("RLM_MAX_TOKENS", "4096")
        assert resolve_max_tokens(None) == 4096
        assert resolve_max_tokens(1000) == 1000

    def test_cache_says_the_cost_means_nothing(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from sc_sentry import cli

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("RLM_MAIN_MODEL", "m")
        monkeypatch.setattr(audit_module, "configure_once", lambda **_: None)
        monkeypatch.setattr(
            audit_module,
            "audit",
            lambda source, path, classes, **_: audit_module.Report(file=path, model="m"),
        )
        target = tmp_path / "Vault.sol"
        target.write_text(VAULT)
        assert cli.main(["audit", str(target), "--cache", "--out", str(tmp_path / "r.json")]) == 0
        assert "CACHE ON" in capsys.readouterr().err
