# sc-sentry

A standalone harness that hunts Solidity vulnerabilities and writes JSON or SARIF (`sc-sentry audit FILE --class a,b --format sarif`). Code finds the candidate functions of a class and a model triages them, or none does with `--mode static`. Scoring it with contract-assay is one use of it, installed as the optional `[contract-assay]` extra.

## Setup and the gate

```console
$ pip install -e ".[dev]"
$ pip install -e ../contract-assay -e ".[dev,contract-assay]"   # the adapter too: a clone of contract-assay first
$ ruff check src tests && ruff format --check src tests
$ mypy src --exclude 'sc_sentry/contract_assay'
$ pytest
```

CI runs exactly this, without contract-assay installed (its repository is private). With it installed, also run `mypy src` so the adapter is type-checked. A change is done when the local gate and the remote CI run are both green.

## Rules that are easy to break

- **The core never imports `contract_assay`.** Only the `sc_sentry.contract_assay` subpackage may; a test asserts it, and CI would fail on the import anyway.
- **The adapter adds no judgement.** Its detectors, model-backed and `Static*` alike, restate the core class checks; a change to a check changes both, identically.
- **The finders are developed on the public corpus and nothing else.** `candidates/<class>.py` is fitted to it, so a figure over it is a fit and says so (see the README). Never read, copy or derive anything from records or locators outside it, and never use a record's id or location as a feature.
- **A refactor of a finder leaves its candidates byte for byte as they were.** Dump what a finder returns over the corpus before and after, and compare the two, because a typing or tidying change that moves a candidate moves a published figure.
- **A citation is whole lines the benchmark can check.** A single-line site goes through `candidates/citable.py`, since the benchmark refuses a quote too short to be told from any other.
- **The model never chooses a citation in `triage` or `static`.** It decides which candidate is an instance, and the code cites it. A mode that lets the model pick lines is `explore`, and it is the one whose quotes failed.
- **The adapter has no loop of its own.** `caller.py` supplies a `ModelCaller` and the benchmark's `run_submission` does the rest: reading units, running detectors, verifying citations and writing runs. A second copy of that loop drifts from the benchmark's, which is how the first one came to read files without checking their digests.
- **The Solidity parser is adapted from contract-assay's evidence parser.** A parse bug found in one is likely in the other; check both.
- **The model endpoint and key are read from `.env` in the working directory** (`sc_sentry/dotenv.py`; an exported variable wins), which is outside git. Tests that call a command `chdir` to a temporary directory so they never read the real one. Never print it, echo it, or put its values in a test, a log or a commit.

## Where to read more

- What each command does and how to point it at a model: `README.md`.
- The adapter's commands: `sc-sentry-contract-assay --help`.
