"""The command ends when it has reported, whatever other libraries left running at exit.

Seen in the dry run: a unit's report was written in full and the process then waited on a lock
until the host killed it at its wall clock, so the whole unit was recorded as a timeout. The
interpreter's shutdown runs handlers other libraries register, and the fix is not to run them.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from sc_sentry import cli

BLOCKS_AT_EXIT = textwrap.dedent(
    """
    import atexit, threading
    atexit.register(threading.Event().wait)  # an exit handler that never returns
    """
)


class _Left(Exception):
    def __init__(self, code: int) -> None:
        self.code = code


def test_run_exits_with_main_s_code_after_flushing(monkeypatch: pytest.MonkeyPatch) -> None:
    flushed: list[str] = []

    class Stream:
        def __init__(self, name: str) -> None:
            self.name = name

        def flush(self) -> None:
            flushed.append(self.name)

    def leave(code: int) -> None:
        raise _Left(code)

    monkeypatch.setattr(cli, "main", lambda: 3)
    monkeypatch.setattr(cli.os, "_exit", leave)
    monkeypatch.setattr(cli.sys, "stdout", Stream("out"))
    monkeypatch.setattr(cli.sys, "stderr", Stream("err"))
    with pytest.raises(_Left) as left:
        cli.run()
    assert left.value.code == 3
    assert flushed == ["out", "err"]


def test_run_keeps_the_code_of_an_exit_the_parser_asks_for(monkeypatch: pytest.MonkeyPatch) -> None:
    def usage_error() -> int:
        raise SystemExit(2)

    def leave(code: int) -> None:
        raise _Left(code)

    monkeypatch.setattr(cli, "main", usage_error)
    monkeypatch.setattr(cli.os, "_exit", leave)
    with pytest.raises(_Left) as left:
        cli.run()
    assert left.value.code == 2


def _child(*, through_run: bool) -> str:
    leaving = "cli.run()" if through_run else "raise SystemExit(cli.main())"
    return BLOCKS_AT_EXIT + f"from sc_sentry import cli\ncli.main = lambda: 0\n{leaving}\n"


def test_a_handler_that_blocks_at_exit_does_not_keep_the_process() -> None:
    done = subprocess.run([sys.executable, "-c", _child(through_run=True)], timeout=30)
    assert done.returncode == 0


def test_without_run_the_same_process_is_kept() -> None:
    # The control: the test above passes because of `run`, not because nothing blocks.
    with pytest.raises(subprocess.TimeoutExpired):
        subprocess.run([sys.executable, "-c", _child(through_run=False)], timeout=3)


def test_the_module_still_audits_and_reports(tmp_path: Path) -> None:
    source = tmp_path / "Vault.sol"
    source.write_text("contract Vault { function f() external {} }\n", encoding="utf-8")
    out = tmp_path / "report.json"
    done = subprocess.run(
        [
            sys.executable,
            "-m",
            "sc_sentry.cli",
            "audit",
            str(source),
            "--mode",
            "static",
            "--out",
            str(out),
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert done.returncode == 0, done.stderr
    assert out.is_file() and "wrote" in done.stderr
