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
- **A budget is kept by doing less, never by failing.** Under `--budget-*` a class that is over the allowance or past the deadline keeps its static order and the report is still written, because a host that stops the process discards it. `triage.ask` never raises and the deadline never waits on a thread.
- **The model's "not an instance" is never a withdrawal by default.** A candidate it ruled out stays in the report below the rest, because withdrawing them cost two thirds of the corpus matches on the validation part, and a round ranked on bpref is driven by recall. `--withdraw` is the opt-in. Measured in the benchmark's own population with `qwen38-flash-next`, withdrawing leaves 36 of the 83 matches on the validation part (recall 0.31 against 0.72) and lifts the F1 at the function floor from 0.141 to 0.204 at a cap of 9, but not the macro F1 over the ranked classes at a cap of 3 (0.318 against 0.337 for the model's order alone). On the development part withdrawing leaves 95 of 292 matches and lowers the macro F1 over the ranked classes from 0.353 to 0.288, and the model's order matches what the static list does at caps of 9 and 3. Those figures count every prediction the corpus does not know as wrong. Once 54 unknown candidates were judged for this model (4 of 26 kept and 1 of 28 ruled out were real), the F1 over judged instances could not separate the two lists: the 95 percent interval of withdrawing minus ordering spans zero, over all classes and over the three ranked ones. Change the default only on a sample that can separate them, for example every unknown candidate in the three ranked classes, 265 on the validation part.
- **Precision is counted over every unit of the part, as the benchmark counts it.** Scoring against the records of one class alone counts only the predictions in units that hold a record of it, which is about a third of them, and overstates precision threefold. An F1 from that population is not a figure.
- **The model never chooses a citation in `triage` or `static`.** It decides which candidate is an instance, and the code cites it. A mode that lets the model pick lines is `explore`, and it is the one whose quotes failed.
- **The adapter has no loop of its own.** `caller.py` supplies a `ModelCaller` and the benchmark's `run_submission` does the rest: reading units, running detectors, verifying citations and writing runs. A second copy of that loop drifts from the benchmark's, which is how the first one came to read files without checking their digests.
- **The Solidity parser is adapted from contract-assay's evidence parser.** A parse bug found in one is likely in the other; check both.
- **The model endpoint and key are read from `.env` in the working directory** (`sc_sentry/dotenv.py`; an exported variable wins), which is outside git. Tests that call a command `chdir` to a temporary directory so they never read the real one. Never print it, echo it, or put its values in a test, a log or a commit.

## Where to read more

- What each command does and how to point it at a model: `README.md`.
- The adapter's commands: `sc-sentry-contract-assay --help`.
