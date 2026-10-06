# sc-sentry

Smart Contract Sentry: an RLM harness that hunts vulnerabilities in Solidity and cites the exact lines it found them at.

Give it a `.sol` file and the classes to look for. For each class, code first finds the functions where the class could be, and a model then decides which of them are the real thing. A class with no candidate in the file costs nothing. Every finding comes back with the whole lines it cites, a confidence, and whether the class's own definition lets it stand, and the lines are always the ones the code chose, never the model's. Output is JSON, or SARIF 2.1.0 for anything that reads static-analysis results (GitHub code scanning among them).

```console
$ sc-sentry audit Vault.sol --class slippage --format sarif --out vault.sarif
auditing Vault.sol
  slippage                   1 candidate(s), 1 finding(s) standing of 1
wrote vault.sarif
```

## Install

```bash
git clone https://github.com/qazbnm456/sc-sentry
python -m venv .venv && . .venv/bin/activate
pip install -e ./sc-sentry
cp sc-sentry/.env.example .env && $EDITOR .env   # where the model lives
```

Both commands read `.env` from the directory you run them in, and a variable already exported wins over the file, so `RLM_MAIN_MODEL=x sc-sentry audit ...` overrides it for one run. `RLM_MAIN_MODEL`, `RLM_SUB_MODEL`, `RLM_BASE_URL`, `RLM_API_KEY` and `RLM_ADAPTER` say where the model is. `RLM_MAX_TOKENS` and `SC_SENTRY_TEMPERATURE` are optional (below). `--mode static` needs none of them.

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
| `--mode` | `triage` | `triage`, `explore` or `static`; see How it works |
| `--limit` | 9 | findings kept per class in `triage` and `static`, which is the benchmark's cap |
| `--candidates` | 20 | candidate functions sent to the model per class in `triage` |
| `--budget-seconds` | none | `triage` only: what a file may take from the command's start, see Under a budget |
| `--budget-calls` | none | `triage` only: the most model calls for a file |
| `--budget-tokens` | none | `triage` only: the most tokens for a file |
| `--max-tokens` | `RLM_MAX_TOKENS`, else 32768 | per-call generation cap |
| `--max-calls` | 4 | model calls per class |
| `--max-iterations` | 6 | planner turns per class, in `explore` |
| `--cache` | off | see below |

A finding the class definition rejects (say, a slippage citation in a function that makes no exchange call) is kept and marked: `rejected` in JSON, a suppressed result with the reason in SARIF. Whoever reads the report decides whether the screen was right, which they cannot do with what it silently took. JSON also says where each finding came from: `origin` is `model` when a model decided it and `static` when the harness cited it and no model reviewed it.

## How it works

The harness has two halves. The first is code: for each class, `candidates/<class>.py` finds the places the class could be and says which are likeliest, using tree-sitter, so any single file works whether or not its project builds. The candidates of one function are grouped, so a function is one finding however many sites fired in it, because a defect is located to a function and a cap counts findings. The second half is the model, in one of three modes.

- **`triage`** (the default) sends the candidate functions for one class in one file to the model, numbered, with each function's code and the class's definition. The model answers a verdict per number: instance or not, how sure, and why. The citation stays with the code. The report is never shorter than the candidates: functions the model picked come first, most confident first, then the ones it was not shown, then the ones it ruled out with its reason kept. The model can move a function up and cannot hide one.
- **`static`** asks no model. The candidates are the findings, likeliest first, each marked as not reviewed. It is the control group for everything the model adds, and it runs with no `.env`.
- **`explore`** gives a planner with nine tools (`outline`, `read_lines`, `state_writes`, `external_calls`, `guards`, `loops`, `arithmetic`, `member_reads`, `callers_of`) the file and the class and lets it investigate, and every candidate it considers must come from a tool. It was the first design and is kept for comparison, because it costs ten to forty times the tokens of `triage` (below).

**Under a budget**, `triage` shares one allowance between the classes of a file, for a host that meters a file from outside. `--budget-calls N` gives the calls to the N classes with the most candidate functions, because an order matters most where there is the most to order. `--budget-tokens T` pays for those classes in that order for as long as a useful call still fits: its fewest candidates and 4,000 tokens for the answer, since a reasoning model spends 2,600 to 5,000 tokens thinking before it answers and a call cut off there costs what a whole one does. What is left over is shared equally, and each call sends as many candidates as its share holds. `--budget-seconds S` counts from the start of the command, runs the calls side by side so a file costs the slowest of them and not their sum, and gives up on any class that has not answered by then. A class the budget did not reach, or that did not answer, keeps its static order and the report is still written, because a host that stops a late process or refuses an over-budget call discards the report and records the file as failed. A failed call is not retried, since a host that counts calls counts a retry. Give it the host's own limits less a margin: a process stopped before its own deadline loses every class of the file. Measured on ten public units with three classes, a call costs a prompt of 5,000 to 6,000 tokens and an answer of 3,400 to 5,800 and takes 8 to 14 seconds, so a limit of 20,000 tokens and 20 seconds pays for one call in full and a second only some of the time, and the rest of the file is static.

The rest of the package, by what it holds:

- **`skills/`**: what each class is, including the shapes that look like it and are not, and how to cite. Seven of the eight classes have one (`insecure_randomness` does not yet), plus `citing-source`. It is prose, editable by somebody who is not reading Python, and `triage` sends it to the model as the class definition.
- **`checks.py`**: wires the finders, groups them by function, and holds the rejections each class's definition settles. Two classes, `unchecked_external_call` and `insecure_randomness`, keep their finders here, and a single-line site is widened to enough whole lines for the benchmark to check the quote.
- **`audit.py`, `triage.py`, `static.py`, `report.py`**: the three modes and the JSON and SARIF writers.
- **`sites.py`** and **`solidity/`**: the tools of `explore` and the parser under everything.

These are eight of the benchmark's nine classes. `flashloan_manipulation` has no check here, so it scores nothing on its 7 records.

## What it scores

The public corpus judges whether a finding sits at a known defect, which is recall. It holds no judgment for a finding that matches nothing, so precision is not measured, and a number below is recall unless it says otherwise.

`static` over the whole corpus, with at most nine findings for each class in each unit, matched 375 of the 471 positive records at the function floor (the same lines, or the same function), which is 0.796. 443 matched at any strength. 165 of the 166 units could be scored.

| class | positive records | at the floor |
|---|---|---|
| denial_of_service | 200 | 159 |
| arithmetic_rounding | 66 | 57 |
| oracle_integrity | 66 | 50 |
| access_control | 62 | 51 |
| slippage | 38 | 32 |
| reentrancy | 20 | 18 |
| unchecked_external_call | 10 | 7 |
| flashloan_manipulation | 7 | 0 |
| insecure_randomness | 2 | 1 |

Three things limit what that figure says.

1. **It is a fit.** The finders were written against this corpus. Split by repository, 70 and 30 by a hash of the repository name, the finders recall 0.82 on the development part and 0.72 on the part held back, and the held-back part was looked at while tuning (up to three times for each class), so 0.72 is still an optimistic estimate of a corpus the finders have not seen.
2. **It does not count what it gets wrong.** `static` makes about 3,700 predictions that match no record and that the corpus has no judgment for. Its precision is unavailable, not zero, and a benchmark that ranks on precision will not rank it on this figure.
3. **The model added nothing measurable here.** On the development part, for slippage, oracle_integrity and denial_of_service, the model's ordering of the candidates and the static order matched the same number of records within nine findings: 25 of 28, 42 of 58 and 127 of 151. On the part held back, over all eight classes, the model's order matched 84 of 114 records and the static order 83, and in first place 32 against 31. The development runs cost 130,000, 207,000 and 760,000 tokens over 23, 43 and 116 files and the held-back runs 1.3 million over 193, so a call in `triage` averages about 6,000 to 7,000 tokens. What a model can add is ruling out look-alikes and putting the real defect first, which is precision, and that is the one thing this corpus cannot score. `--mode static` is there so that comparison can be made on any corpus that does judge precision.

`explore` is why the harness grew candidates. Its first run on a 12-unit slice of eight classes matched 2 of 45 reachable records at the floor, and 18 of its claims quoted lines that were not at the lines they gave, which the benchmark records as unverifiable. A planner on one class in one file took 56,000 to 97,000 tokens, 35 to 42 seconds and 5 to 7 model calls against `qwen36_35b_a3b` (two runs, 2026-10-06).

## Three defaults that are measurements, not taste

- **The model cache is off.** dspy caches on disk, and a cached answer comes back in two seconds having spent zero tokens, so a sweep that re-ran a pair would report a cost of nothing. `--cache` turns it on for iterating on everything downstream of the model, and prints that the cost column then means nothing.
- **Temperature is pinned to 0.0** (`SC_SENTRY_TEMPERATURE` overrides it). Unpinned means the server's default, often 1.0, and two runs of one harness over one unit are then two samples of an unrecorded distribution: comparing them measures the sampler.
- **`max_retries=3`.** Measured: 4 of 64 calls died with the adapter unable to parse the reply. That is reasoning-model truncation (the chain of thought and the structured answer share one `max_tokens`) and it presents as a model that cannot follow a schema, which is a different fix from the real one.

## Editing a class

A class has two places to change. The finder is `candidates/<class>.py`, and the skill is `skills/<class>/SKILL.md`. A change to a finder moves recall, because a defect the finder does not offer cannot be found, and a change to a skill moves what the model rules out. The sections of a skill that decide the score are **what is not an instance** (precision) and, in `explore`, **how to cite**.

Develop a finder against the public corpus and nothing else, and split it by repository as above, because a finder fitted to a record's own location measures how well it was fitted. Record which run file a figure came from, because a figure without its run is not reproducible.

## Scoring it (optional): the contract-assay adapter

`sc_sentry.contract_assay` is how the [contract-assay][ca] benchmark measures this harness. It is an adapter and not a second harness. `detectors.py` is the harness's checks as the benchmark's `Detector`s: `evidence()` is the candidate sites, `plan()` is the class's brief, or nothing when the unit has no candidates, which costs no model call, and `verdict()` is the class definition's rejections. `caller.py` is the one function the benchmark calls when a detector asks for a model, and it runs `triage` unless `SC_SENTRY_MODE=explore`. The harness never imports any of it, and nothing in it loops over a corpus, because the benchmark's own runner does that.

[ca]: https://github.com/qazbnm456/contract-assay

contract-assay is not on PyPI, and its repository is private for now: you need read access to it to install the extra. With that, follow the benchmark's README ("Where to start"), which is the path for any harness of your own. For this one it is:

```bash
git clone https://github.com/qazbnm456/contract-assay
pip install -e ./contract-assay && pip install -e "./sc-sentry[contract-assay]"
contract-assay fetch contract-assay/corpus/records --source-root checkout

args=(); for m in sc-sentry/src/sc_sentry/contract_assay/manifests/*.manifest.json; do args+=(--manifest "$m"); done
contract-assay run "${args[@]}" \
    --records contract-assay/corpus/records --source-root checkout \
    --model-caller sc_sentry.contract_assay.caller:call --limit 5 --out results/run.jsonl

contract-assay score results/run.jsonl --records contract-assay/corpus/records \
    --source-root checkout --submission-id sc-sentry --out results/score.json
```

There is one manifest for each of the eight classes, because a manifest names one detector. Leave a class out and the score marks it `nothing_ran` with a recall of 0.0, which is the benchmark saying nobody looked. The model and the endpoint come from `.env` in the directory you run it in, and the caller reads them when it is imported, so a missing `RLM_MAIN_MODEL` ends the command with one line. `SC_SENTRY_MODE` (`triage` or `explore`), `SC_SENTRY_CANDIDATES` (20), `SC_SENTRY_MAX_ITERATIONS` (6) and `SC_SENTRY_CACHE=1` set what a call does, and `--max-calls` reaches it through the benchmark.

The manifests under `manifests/static/` name the same eight classes as detectors that ask for no model, with ids that start `sentry-static-`. They need no `--model-caller` and no `.env`, and the benchmark records their runs as produced without a model. Score them under a different `--submission-id` from the model's, so the two are two rows to compare.

**A unit can cost more than a benchmark round allows.** Triage makes one call for each class a file has candidates in, so a file with five such classes makes five, and the benchmark's defaults for a whole unit are 4 calls, 20,000 tokens and 30 seconds. Nothing here enforces them, and the adapter prints a line when a call goes over. A host that does enforce them would refuse such units, so figures from this path measure the harness with its budget unbounded. `explore` is further over, by the figures above.

For iterating on the harness there is a convenience over the same runner:

```bash
sc-sentry-contract-assay run --units 12 --out results/run.jsonl \
    --corpus contract-assay/corpus/records --source-root checkout
sc-sentry-contract-assay score results/run.jsonl \
    --corpus contract-assay/corpus/records --source-root checkout
```

`run` takes a stratified slice, which covers every class once before any class twice, because the first 12 units of a corpus whose largest class holds 200 of its 478 records measure that one class. It also takes `--mode {triage,explore,static}`, `--units 0` for every readable unit, `--only CLASS`, `--predictions-per-unit` (the benchmark's default, 9), the same `--max-*` limits as `audit`, and `--cache`. `score` prints the per-class table. A figure over part of a corpus is not comparable with one over all of it.

## Licence

MIT. See [LICENSE](LICENSE).
