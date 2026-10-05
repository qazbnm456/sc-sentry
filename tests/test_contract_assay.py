"""The contract-assay adapter: the same checks, restated in the benchmark's types.

Skipped when the benchmark is not installed -- it is an optional extra.
"""

from __future__ import annotations

import hashlib
import importlib
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

pytest.importorskip("contract_assay")

from contract_assay.detectors.base import AnalysisContext, SubmissionLimits
from contract_assay.detectors.loading import SubmissionManifest, load_detector
from contract_assay.harness import SourceUnit, run_submission
from contract_assay.models import (
    CitationStatus,
    EvidenceTier,
    InvalidReason,
    ModelRole,
    Outcome,
)

from sc_sentry import triage
from sc_sentry.audit import Answer
from sc_sentry.briefs import BRIEFS
from sc_sentry.checks import CHECKS
from sc_sentry.classes import VulnClass
from sc_sentry.contract_assay import slices
from sc_sentry.contract_assay.detectors import (
    SENTRY_DETECTORS,
    STATIC_DETECTORS,
    AccessControl,
    Slippage,
    StaticAccessControl,
)
from sc_sentry.task import Proposal

from .test_core import VAULT, a_proposal

MANIFESTS = (
    Path(__file__).resolve().parents[1] / "src" / "sc_sentry" / "contract_assay" / "manifests"
)


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


@pytest.fixture
def caller(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> ModuleType:
    """`sc_sentry.contract_assay.caller`, imported with a model named and no real `.env` read.

    The module reads its model when it is imported, so the environment is set first and the
    module is reloaded for each test. The working directory is a temporary one because the
    module loads `.env` from it, and a test must never read the real one.
    """
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("RLM_MAIN_MODEL", "main-m")
    monkeypatch.setenv("RLM_SUB_MODEL", "sub-m")
    monkeypatch.setenv("SC_SENTRY_MODE", "explore")
    module = importlib.import_module("sc_sentry.contract_assay.caller")
    module = importlib.reload(module)
    monkeypatch.setattr(module, "configure_once", lambda **_: None)
    return module


def an_answer(*proposals: Proposal, usage: tuple[tuple[str, int, int], ...] = ()) -> Answer:
    return Answer(
        proposals=proposals,
        tokens=sum(t for _, _, t in usage),
        seconds=1.0,
        usage=usage,
    )


def a_unit() -> SourceUnit:
    return SourceUnit(
        source_id="commit:vault@aaa:src/Vault.sol", path="src/Vault.sol", source=VAULT
    )


class TestTheManifests:
    def test_there_is_one_per_class_and_each_resolves_through_the_real_loader(self) -> None:
        loaded = []
        for path in sorted(MANIFESTS.glob("*.manifest.json")):
            manifest = SubmissionManifest.model_validate_json(path.read_text(encoding="utf-8"))
            detector = load_detector(manifest, search_path=MANIFESTS)
            assert detector.class_id.value == path.name.removesuffix(".manifest.json")
            loaded.append(type(detector))
        assert set(loaded) == set(SENTRY_DETECTORS)


class TestTheCaller:
    def test_a_missing_model_ends_the_import_with_one_clear_error(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("RLM_MAIN_MODEL", "main-m")
        module = importlib.import_module("sc_sentry.contract_assay.caller")
        monkeypatch.delenv("RLM_MAIN_MODEL")
        with pytest.raises(RuntimeError, match="RLM_MAIN_MODEL"):
            importlib.reload(module)

    def test_findings_carry_the_confidence_as_the_score(self, caller: ModuleType) -> None:
        """A round ranked on bpref needs a score on every finding of a class.

        The confidence was used to sort and then dropped, so every finding reached the scorer
        unscored and every bpref round left the harness unrankable.
        """
        detector = Slippage()
        ctx = a_context(detector)
        findings = caller.to_findings(
            detector, ctx, [a_proposal(5, 5), a_proposal(5, 3), a_proposal(5, 2)]
        )
        assert [f.score for f in findings] == [5.0, 3.0, 2.0]
        assert {f.detector_id for f in findings} == {"sentry-slippage"}
        assert findings[0].locator.file == "src/Vault.sol"

    def test_a_backwards_span_collapses_to_its_start(self, caller: ModuleType) -> None:
        detector = Slippage()
        proposal = Proposal(
            start_line=6, end_line=5, quote="x", reasoning="r", function="sell", confidence=3
        )
        [finding] = caller.to_findings(detector, a_context(detector), [proposal])
        assert (finding.locator.start_line, finding.locator.end_line) == (6, 6)

    def test_each_model_is_charged_as_its_own_role_with_its_real_calls(
        self, caller: ModuleType
    ) -> None:
        used = caller.models_used(
            [("openai/main-m", 3, 900), ("openai/sub-m", 2, 100)], main="main-m", sub="sub-m"
        )
        by_role = {u.role: u for u in used}
        assert (by_role[ModelRole.MAIN].calls, by_role[ModelRole.MAIN].tokens) == (3, 900)
        assert (by_role[ModelRole.SUB].calls, by_role[ModelRole.SUB].tokens) == (2, 100)
        assert by_role[ModelRole.SUB].model_id == "sub-m"

    def test_a_model_it_does_not_recognise_is_charged_to_the_main_one_and_not_lost(
        self, caller: ModuleType
    ) -> None:
        [used] = caller.models_used([("something-else", 1, 7)], main="main-m", sub="sub-m")
        assert (used.role, used.model_id, used.tokens) == (ModelRole.MAIN, "main-m", 7)

    def test_a_provider_that_reports_nothing_still_names_one_call_and_no_tokens(
        self, caller: ModuleType
    ) -> None:
        [used] = caller.models_used([], main="main-m", sub="sub-m")
        assert (used.calls, used.tokens) == (1, 0)

    def test_through_the_benchmark_a_verified_finding_makes_the_run_vulnerable(
        self, caller: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asked: list[str] = []

        def ask(source: str, brief: str) -> Answer:
            asked.append(brief)
            return an_answer(a_proposal(5, 4), usage=(("main-m", 3, 1200),))

        monkeypatch.setattr(caller, "ask", ask)
        [run] = run_submission([Slippage()], [a_unit()], model=caller.call)
        assert run.outcome is Outcome.VULNERABLE
        assert asked == [BRIEFS[VulnClass.SLIPPAGE]]
        assert [(u.role, u.calls, u.tokens) for u in run.models] == [(ModelRole.MAIN, 3, 1200)]
        assert run.findings[0].finding.score == 4.0

    def test_a_class_with_no_candidate_sites_is_never_asked(
        self, caller: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The harness's own saving: no call is made for a class the file cannot hold, which
        # is cheaper and the only way to avoid an invented finding.
        def never(source: str, brief: str) -> Answer:
            raise AssertionError("a class with no candidate sites must not reach the planner")

        monkeypatch.setattr(caller, "ask", never)
        setter = (
            "contract E {\n    uint256 x;\n    function set(uint256 v) external {\n"
            "        x = v;\n    }\n}\n"
        )
        unit = SourceUnit(source_id="commit:e@aaa:src/E.sol", path="src/E.sol", source=setter)
        [run] = run_submission([Slippage()], [unit], model=caller.call)
        assert run.outcome is Outcome.CLEAN

    def test_a_failed_planner_is_an_invalid_run_that_keeps_what_it_spent(
        self, caller: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        failed = Answer(
            proposals=(),
            tokens=500,
            seconds=2.0,
            failed="ValueError: no valid findings after 3 attempts",
            usage=(("main-m", 3, 500),),
        )
        monkeypatch.setattr(caller, "ask", lambda source, brief: failed)
        causes: list[str] = []
        [run] = run_submission(
            [Slippage()],
            [a_unit()],
            model=caller.call,
            on_failure=lambda unit, detector, cause: causes.append(cause),
        )
        assert run.invalid_reason is InvalidReason.TRANSPORT_FAILURE
        assert causes == ["ValueError: no valid findings after 3 attempts"]
        assert [(u.calls, u.tokens) for u in run.models] == [(3, 500)]


@pytest.fixture
def triage_caller(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> ModuleType:
    """The caller in its default mode, where the model reviews the harness's candidate functions."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("RLM_MAIN_MODEL", "main-m")
    monkeypatch.setenv("SC_SENTRY_MODE", "triage")
    module = importlib.reload(importlib.import_module("sc_sentry.contract_assay.caller"))
    monkeypatch.setattr(module, "configure_once", lambda **_: None)
    return module


def a_verdict(number: int, *, instance: bool, confidence: int = 4) -> triage.Verdict:
    return triage.Verdict(id=number, instance=instance, confidence=confidence, reasoning="because")


class TestTheTriageCaller:
    def test_the_models_pick_comes_first_and_the_run_names_what_it_cost(
        self, triage_caller: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Two candidate functions in static order (`set`, then `sell`). The model says the second
        # is the instance and the first is not, so `sell` leads and `set` stays below it.
        seen: list[str] = []

        def fake(definition: str, table: str, *, count: int) -> triage.TriageAnswer:
            seen.append(table)
            return triage.TriageAnswer(
                verdicts={
                    1: a_verdict(1, instance=False),
                    2: a_verdict(2, instance=True, confidence=5),
                },
                tokens=900,
                seconds=2.0,
                usage=(("main-m", 1, 900),),
            )

        monkeypatch.setattr(triage, "ask", fake)
        [run] = run_submission([AccessControl()], [a_unit()], model=triage_caller.call)
        assert [f.finding.locator.function for f in run.findings] == ["sell", "set"]
        assert [f.finding.score for f in run.findings] == [2.0, 1.0]
        assert all(f.status is CitationStatus.VERIFIED for f in run.findings)
        assert [(u.calls, u.tokens) for u in run.models] == [(1, 900)]
        # One call for the class, and the candidates reach the model as numbered code.
        assert len(seen) == 1 and "#1 " in seen[0] and "#2 " in seen[0]

    def test_a_failed_call_costs_the_judgement_and_not_the_findings(
        self,
        triage_caller: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        failed = triage.TriageAnswer(
            verdicts={},
            tokens=400,
            seconds=1.0,
            failed="ValueError: the reply was not JSON",
            usage=(("main-m", 2, 400),),
        )
        monkeypatch.setattr(triage, "ask", lambda definition, table, *, count: failed)
        [run] = run_submission([AccessControl()], [a_unit()], model=triage_caller.call)
        assert [f.finding.locator.function for f in run.findings] == ["set", "sell"]
        assert [(u.calls, u.tokens) for u in run.models] == [(2, 400)]
        assert "triage failed (ValueError: the reply was not JSON)" in capsys.readouterr().err

    def test_a_class_with_no_candidates_is_never_asked(
        self, triage_caller: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def never(definition: str, table: str, *, count: int) -> triage.TriageAnswer:
            raise AssertionError("a class with no candidates must not reach the model")

        monkeypatch.setattr(triage, "ask", never)
        setter = "contract E {\n    uint256 x;\n    function f() external pure {\n    }\n}\n"
        unit = SourceUnit(source_id="commit:e@aaa:src/E.sol", path="src/E.sol", source=setter)
        [run] = run_submission([Slippage()], [unit], model=triage_caller.call)
        assert run.outcome is Outcome.CLEAN


class TestTheStaticDetectors:
    """The control group: the same checks with no model, so `contract-assay run` needs no caller."""

    def test_there_is_one_per_class_and_each_resolves_through_the_real_loader(self) -> None:
        loaded = []
        for path in sorted((MANIFESTS / "static").glob("*.manifest.json")):
            manifest = SubmissionManifest.model_validate_json(path.read_text(encoding="utf-8"))
            detector = load_detector(manifest, search_path=path.parent)
            assert detector.class_id.value == path.name.removesuffix(".manifest.json")
            loaded.append(type(detector))
        assert set(loaded) == set(STATIC_DETECTORS)

    def test_they_ask_for_no_model_and_assert_their_candidates_in_the_harnesss_order(self) -> None:
        # No `model=`: a detector that asked for one would come back `model_not_permitted`.
        [run] = run_submission([StaticAccessControl()], [a_unit()])
        assert run.outcome is Outcome.VULNERABLE and run.produced_without_a_model
        assert [f.finding.locator.function for f in run.findings] == ["set", "sell"]
        assert [f.finding.score for f in run.findings] == [2.0, 1.0]
        assert all(f.status is CitationStatus.VERIFIED for f in run.findings)

    def test_the_sweep_needs_no_model_in_static_mode(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        from sc_sentry.contract_assay import run

        monkeypatch.chdir(tmp_path)  # never the repository's own .env
        monkeypatch.delenv("RLM_MAIN_MODEL", raising=False)
        records, root = TestTheSlice().a_corpus(tmp_path, {})
        out = tmp_path / "runs.jsonl"
        argv = ["--mode", "static", "--units", "0", "--out", str(out)]
        argv += ["--corpus", str(records), "--source-root", str(root)]
        assert run.main(argv) == 0
        written = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
        assert {r["class_id"] for r in written} >= {"slippage", "reentrancy"}
        assert all(r["models"] == [] for r in written)


class TestTheSlice:
    def a_corpus(self, tmp_path: Path, files: dict[str, str]) -> tuple[Path, Path]:
        """Two units and two classes, one record each; `files` is what is on disk for each."""
        records, root = tmp_path / "records", tmp_path / "checkout"
        records.mkdir()
        (root / "src").mkdir(parents=True)
        for name, cls in (("A", "slippage"), ("B", "reentrancy")):
            path = f"src/{name}.sol"
            (root / path).write_text(files.get(name, VAULT), encoding="utf-8")
            (records / f"{name}.json").write_text(
                json.dumps(
                    {
                        "record_id": f"{name.lower()}-{cls}-1",
                        "split": "public",
                        "pin": {
                            "kind": "commit",
                            "repo_url": f"https://github.com/example/{name.lower()}",
                            "commit": "a" * 40,
                            "path": path,
                            "sha256": hashlib.sha256(VAULT.encode()).hexdigest(),
                        },
                        "locator": {
                            "file": path,
                            "contract": "Vault",
                            "function": "sell",
                            "start_line": 4,
                            "end_line": 7,
                        },
                        "population": "audit_review",
                        "locator_provenance": "stated",
                        "classes": [cls],
                        "provenance": {"platform": "p", "report_url": "https://example.invalid/r"},
                    }
                ),
                encoding="utf-8",
            )
        return records, root

    def test_every_class_is_covered_before_any_class_twice(self, tmp_path: Path) -> None:
        records, root = self.a_corpus(tmp_path, {})
        units, missing = slices.slice_of(records, root, 2)
        assert missing == []
        assert sorted(u.path for u in units) == ["src/A.sol", "src/B.sol"]

    def test_a_file_that_no_longer_matches_its_digest_is_left_out_and_named(
        self, tmp_path: Path
    ) -> None:
        # Scoring a record's locator against different text is a real number about the wrong
        # source, so a drifted checkout shortens the slice and says so.
        records, root = self.a_corpus(tmp_path, {"A": VAULT + "// edited\n"})
        units, missing = slices.slice_of(records, root, 0)
        assert [u.path for u in units] == ["src/B.sol"]
        assert len(missing) == 1


class TestTheSweep:
    def test_it_writes_what_the_benchmark_scores_without_a_loop_of_its_own(
        self, caller: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        from sc_sentry.contract_assay import run

        records, root = TestTheSlice().a_corpus(tmp_path, {})
        monkeypatch.setattr(
            caller,
            "ask",
            lambda source, brief: an_answer(a_proposal(5, 4), usage=(("main-m", 2, 800),)),
        )
        monkeypatch.setattr(run, "configure_once", lambda **_: None)
        out = tmp_path / "runs.jsonl"
        code = run.main(
            [
                "--mode",
                "explore",
                "--units",
                "0",
                "--only",
                "slippage",
                "--out",
                str(out),
                "--corpus",
                str(records),
                "--source-root",
                str(root),
            ]
        )
        assert code == 0
        written = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
        assert len(written) == 2
        assert {r["class_id"] for r in written} == {"slippage"}
        assert all(r["outcome"] == "vulnerable" for r in written)
        assert sum(m["calls"] for r in written for m in r["models"]) == 4

    def test_it_stops_at_once_when_no_model_is_named(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from sc_sentry.contract_assay import run

        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("RLM_MAIN_MODEL", raising=False)
        records, root = TestTheSlice().a_corpus(tmp_path, {})
        code = run.main(
            [
                "--out",
                str(tmp_path / "r.jsonl"),
                "--corpus",
                str(records),
                "--source-root",
                str(root),
            ]
        )
        assert code == 2
        assert "RLM_MAIN_MODEL is not set" in capsys.readouterr().err


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
