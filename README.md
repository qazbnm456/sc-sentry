# sc-sentry

Smart Contract Sentry: an RLM harness that hunts vulnerabilities in Solidity and cites the exact lines it found them at.

Give it a `.sol` file and the classes to look for. For each class, code first finds the functions where the class could be, and a model then decides which of them are the real thing. A class with no candidate in the file costs nothing. Every finding comes back with the whole lines it cites, a confidence, and whether the class's own definition lets it stand. The lines are always the ones the code chose, never the model's. Output is JSON, or SARIF 2.1.0 for anything that reads static-analysis results, GitHub code scanning among them.

```console
$ sc-sentry audit Vault.sol --class slippage --format sarif --out vault.sarif
auditing Vault.sol
  slippage                   1 candidate(s), 1 finding(s) standing of 1
wrote vault.sarif
```

## Install

```bash
python -m venv .venv && . .venv/bin/activate
pip install sc-sentry
$EDITOR .env   # where the model lives: the variables are below
```

To work on it, install from a clone instead. The clone also holds `.env.example`, which names every variable:

```bash
git clone https://github.com/qazbnm456/sc-sentry
python -m venv .venv && . .venv/bin/activate
pip install -e "./sc-sentry[dev]"
cp sc-sentry/.env.example .env && $EDITOR .env
```

Both commands read `.env` from the directory you run them in, and a variable already exported wins over the file, so `RLM_MAIN_MODEL=x sc-sentry audit ...` overrides it for one run. `RLM_MAIN_MODEL`, `RLM_SUB_MODEL`, `RLM_BASE_URL`, `RLM_API_KEY` and `RLM_ADAPTER` say where the model is. `RLM_MAX_TOKENS` and `SC_SENTRY_TEMPERATURE` are optional (see the `--max-tokens` option below and [Three defaults that are measurements](docs/development.md#three-defaults-that-are-measurements-not-taste)). `--mode static` needs none of them.

## Use

```bash
sc-sentry classes                                  # the eight classes it hunts
sc-sentry audit contracts/*.sol                    # every class, JSON to stdout
sc-sentry audit Pool.sol --class reentrancy --class oracle_integrity \
    --format sarif --out pool.sarif
sc-sentry audit Pool.sol --mode static             # no model, no .env
```

| option | default | |
|---|---|---|
| `--class` | every class | one class, or several comma-separated; repeatable |
| `--format` | `json` | or `sarif` |
| `--out` | stdout | |
| `--mode` | `triage` | `triage`, `explore` or `static`; see [How it works](#how-it-works) |
| `--limit` | 9 | findings kept per class in `triage` and `static`, which is the benchmark's cap |
| `--candidates` | 20 | candidate functions sent to the model per class in `triage` |
| `--budget-seconds` | none | `triage` only: what a file may take from the command's start; see [Running under a budget](docs/how-it-works.md#running-under-a-budget) |
| `--budget-calls` | none | `triage` only: the most model calls for a file |
| `--budget-tokens` | none | `triage` only: the most tokens for a file |
| `--budget-parallel` | off | `triage` only: with a budget, send the classes' calls side by side |
| `--withdraw` | off | `triage` only: mark what the model ruled out as rejected, which a SARIF reader suppresses |
| `--max-tokens` | `RLM_MAX_TOKENS`, else 32768 | per-call generation cap |
| `--max-calls` | 4 | model calls per class |
| `--max-iterations` | 6 | planner turns per class, in `explore` |
| `--cache` | off | see [Three defaults](docs/development.md#three-defaults-that-are-measurements-not-taste) |

A finding the class definition rejects (say, a slippage citation in a function that makes no exchange call) is kept and marked: `rejected` in JSON, and a suppressed result with the reason in SARIF. Whoever reads the report decides whether the screen was right, which they could not do if it silently dropped the finding. JSON also says where each finding came from: `origin` is `model` when a model decided it, and `static` when the harness cited it and no model reviewed it.

## How it works

The harness has two halves. For each class, code (`candidates/<class>.py`, built on tree-sitter, so a single file works whether or not its project builds) finds the functions where the class could be and ranks them; a model then decides which are the real thing. The lines a finding cites are always the ones the code chose, never the model's.

It runs in one of three modes, chosen with `--mode`:

- **`triage`** (the default) shows the model the candidate functions for one class, each with its code and the class's definition, and takes a verdict on each. The model can move a function up the report but cannot hide one.
- **`static`** asks no model and needs no `.env`. The candidates are the findings, likeliest first. It is the control group for everything the model adds.
- **`explore`** gives a planner the file, the class and a set of tools and lets it investigate. It is kept only as a comparison with `triage` and costs far more.

[docs/how-it-works.md](docs/how-it-works.md) has the full behaviour of each mode, [running under a budget](docs/how-it-works.md#running-under-a-budget), and what the package holds.

## Documentation

- [How it works](docs/how-it-works.md): the three modes in full, running under a budget, and what the package holds.
- [What it scores](docs/benchmark.md): recall on the public corpus, why that figure is a fit, what the model adds, and how to choose a cap. The figures here are fits to a public corpus, and the document says so.
- [Development](docs/development.md): editing a class, and the defaults that are measurements rather than taste.
- [Scoring it with contract-assay](docs/contract-assay.md): the optional adapter that lets the [contract-assay](https://github.com/qazbnm456/contract-assay) benchmark measure this harness.

## Licence

MIT. See [LICENSE](LICENSE).
