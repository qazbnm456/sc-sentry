# sc-sentry

A standalone harness that hunts Solidity vulnerabilities with a model and writes JSON or SARIF (`sc-sentry audit FILE --class a,b --format sarif`). Scoring it with contract-assay is one use of it, installed as the optional `[contract-assay]` extra.

## Setup and the gate

```console
$ pip install -e ".[dev]"                     # add ,contract-assay for the adapter
$ ruff check src tests && ruff format --check src tests
$ mypy src --exclude 'sc_sentry/contract_assay'
$ pytest
```

CI runs exactly this, without contract-assay installed. A change is done when the local gate and the remote CI run are both green.

## Rules that are easy to break

- **The core never imports `contract_assay`.** Only the `sc_sentry.contract_assay` subpackage may; a test asserts it, and CI would fail on the import anyway.
- **The adapter adds no judgement.** Its detectors restate the core class checks; a change to a check changes both, identically.
- **The Solidity parser is adapted from contract-assay's evidence parser.** A parse bug found in one is likely in the other; check both.
- **The model endpoint and key are read from `.env`**, which is outside git. Never print it, echo it, or put its values in a test, a log or a commit.

## Where to read more

- What each command does and how to point it at a model: `README.md`.
- The adapter's commands: `sc-sentry-contract-assay --help`.
