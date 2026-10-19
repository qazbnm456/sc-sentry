# sc-sentry

A standalone harness that hunts Solidity vulnerabilities and writes JSON or SARIF (`sc-sentry audit FILE --class a,b --format sarif`). Code finds the candidate functions of a class and a model triages them, or none does with `--mode static`. Scoring it with contract-assay is one use of it, installed as the optional `[contract-assay]` extra.

## Setup and the gate

```console
$ pip install -e ".[dev]"
$ pip install -e ".[dev,contract-assay]"                         # the adapter too, from PyPI
$ ruff check src tests && ruff format --check src tests
$ mypy src --exclude 'sc_sentry/contract_assay'                   # without the extra
$ mypy src                                                        # with it
$ pytest
```

CI runs both: the harness without contract-assay, which proves it needs none, and once more with the extra, which type-checks and tests the adapter. The adapter's tests build their own corpus, so neither needs a clone of contract-assay; a real run does, for its records. A change is done when the local gate and the remote CI run are both green.

A release is a GitHub Release `vX.Y.Z`, cut from a green `main`. A tag push alone publishes nothing. The version in `pyproject.toml` and `__version__` in `src/sc_sentry/__init__.py` have to match the tag first. Publishing the Release starts `release.yml`, which checks the versions, builds, runs the gate against the installed wheel, and then waits for a maintainer to approve the `pypi` environment before it uploads by Trusted Publishing. A version can never be uploaded to PyPI twice, so a bad release is fixed with a new version. Run the workflow by hand to rehearse a release from any ref; it publishes nothing.

## Rules that are easy to break

- **The core never imports `contract_assay`.** Only the `sc_sentry.contract_assay` subpackage may; a test asserts it, and CI would fail on the import anyway.
- **The adapter adds no judgement.** Its detectors, model-backed and `Static*` alike, restate the core class checks; a change to a check changes both, identically.
- **The finders are developed on the public corpus and nothing else.** `candidates/<class>.py` is fitted to it, so a figure over it is a fit and says so (see `docs/benchmark.md`). Never read, copy or derive anything from records or locators outside it, and never use a record's id or location as a feature.
- **A refactor of a finder leaves its candidates byte for byte as they were.** Dump what a finder returns over the corpus before and after, and compare the two, because a typing or tidying change that moves a candidate moves a published figure.
- **A citation is whole lines the benchmark can check.** A single-line site goes through `candidates/citable.py`, since the benchmark refuses a quote too short to be told from any other.
- **A budget is kept by doing less, never by failing.** Under `--budget-*` a class that is over the allowance or past the deadline keeps its static order and the report is still written, because a host that stops the process discards it. `triage.ask` never raises and the deadline never waits on a thread.
- **The model's "not an instance" is never a withdrawal by default.** A candidate it ruled out stays in the report below the rest, and `--withdraw` is the opt-in. A round ranked on bpref is driven by recall, and withdrawing costs most of the matches: with `qwen38-flash-next`, counted over every unit as the benchmark counts, it leaves 36 of 83 matches on the validation part and 95 of 292 on the development part. It raises the F1 at the function floor at a cap of 9 (0.141 to 0.204 on the validation part) but not the macro F1 over the three ranked classes (0.318 against 0.337 for the model's order at a cap of 3 on the validation part, and 0.288 against 0.353 at a cap of 9 on the development part). A judged sample of 54 unknown candidates (4 of 26 kept and 1 of 28 ruled out were real) cannot separate the two lists on F1, because the 95 percent interval of withdrawing minus ordering spans zero. Change the default only on a sample that can separate them, for example every unknown candidate in the three ranked classes, which is 265 on the validation part. The `docs/benchmark.md` section "What the model adds" has the full figures.
- **Precision is counted over every unit of the part, as the benchmark counts it.** Scoring against the records of one class alone counts only the predictions in units that hold a record of it, which is about a third of them, and overstates precision threefold. An F1 from that population is not a figure.
- **The model never chooses a citation in `triage` or `static`.** It decides which candidate is an instance, and the code cites it. The mode that lets the model pick lines is `explore`, and its quotes are the ones that fail verification.
- **The adapter has no loop of its own.** `caller.py` supplies a `ModelCaller` and the benchmark's `run_submission` does the rest: reading units, running detectors, verifying citations and writing runs. A second copy of that loop drifts from the benchmark's, for example by reading files without checking their digests.
- **What the model reads is part of every published model figure.** The skills, `triage.INSTRUCTIONS`, the `Verdict` and `Verdicts` schemas, the check summaries, `briefs.BRIEFS`, `task.DISCIPLINE` and the docstrings of the tools in `sites.tools_for` all reach the model. Editing any of them, wording included, means the triage or explore figures describe a prompt the harness no longer sends, so a change there is a measured change and `docs/benchmark.md` has to say so.
- **The Solidity parser is adapted from contract-assay's evidence parser.** A parse bug found in one is likely in the other; check both.
- **The model endpoint and key are read from `.env` in the working directory** (`sc_sentry/dotenv.py`; an exported variable wins), which is outside git. Tests that call a command `chdir` to a temporary directory so they never read the real one. Never print it, echo it, or put its values in a test, a log or a commit.

## Writing

Documentation, comments and docstrings state what the code does now and why, not the history of how it got there; the history belongs in commit messages. Write complete sentences and paragraphs, with no dashes used as punctuation. In Markdown, YAML and TOML a paragraph is one line, because nothing limits their line length. In Python, ruff enforces 100 columns, so comments and docstrings fill lines up to that limit and break only between words.

## Where to read more

- What each command does and how to point it at a model: `README.md`.
- How it works, what it scores, and how to develop it: the `docs/` directory, indexed from `README.md`.
- The adapter's commands: `sc-sentry-contract-assay --help`.
