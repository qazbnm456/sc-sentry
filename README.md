# sc-sentry

Smart Contract Sentry: an RLM harness that hunts vulnerabilities in Solidity and
cites the exact lines it found them at.

Give it a `.sol` file and the classes to look for. For each class it first finds
where the class *could* be -- a class with no candidate sites costs nothing --
then a planner with purpose-built tools investigates, and every finding comes
back with the lines it cites, the model's confidence, and whether the class's
own definition lets it stand. Output is JSON, or SARIF 2.1.0 for anything that
reads static-analysis results (GitHub code scanning among them).

```console
$ sc-sentry audit Vault.sol --class slippage --format sarif --out vault.sarif
auditing Vault.sol
  slippage                   2 candidate(s), 1 finding(s) standing of 1
wrote vault.sarif
```

## Install

```bash
git clone https://github.com/qazbnm456/sc-sentry
python -m venv .venv && . .venv/bin/activate
pip install -e ./sc-sentry
cp sc-sentry/.env.example .env && $EDITOR .env   # where the model lives
```

Both commands read `.env` from the directory you run them in; a variable
already exported wins over the file, so `RLM_MAIN_MODEL=x sc-sentry audit ...`
overrides it for one run. `RLM_MAIN_MODEL`, `RLM_SUB_MODEL`, `RLM_BASE_URL`,
`RLM_API_KEY` and `RLM_ADAPTER` say where the model is; `RLM_MAX_TOKENS` and
`SC_SENTRY_TEMPERATURE` are optional (below).

## Use

```bash
sc-sentry classes                                  # the eight classes it hunts
sc-sentry audit contracts/*.sol                    # every class, JSON to stdout
sc-sentry audit Pool.sol --class reentrancy --class oracle_integrity \
    --format sarif --out pool.sarif
```

| option | default | |
|---|---|---|
| `--class` | every class | one class, or several comma-separated; repeatable |
| `--format` | `json` | or `sarif` |
| `--out` | stdout | |
| `--max-tokens` | `RLM_MAX_TOKENS`, else 32768 | per-call generation cap |
| `--max-calls` | 4 | model calls per class |
| `--max-iterations` | 6 | planner turns per class |
| `--cache` | off | see below |

A finding the class definition rejects -- say, a slippage citation in a
function that makes no exchange call -- is **kept, marked**: `rejected` in JSON,
a suppressed result with the reason in SARIF. Whoever reads the report decides
whether the screen was right, which they cannot do with what it silently took.

## How it works

- **`skills/`** — what each class *is*, including the shapes that look like it
  and are not, and how to cite. Seven of the eight classes (`insecure_randomness`
  has no skill yet, so its planner works from the class definition alone), plus
  `citing-source`. Prose,
  editable by somebody who is not reading Python, injected at startup so the
  planner never spends a turn finding out what it knows.
- **`solidity/`** — tree-sitter parsing. No compiler, so any single file works
  whether or not its project builds.
- **`checks.py`** — per class, where it could be and which citations its
  definition rules out. The deterministic half.
- **`sites.py`** — nine tools: `outline`, `read_lines`, `state_writes`,
  `external_calls`, `guards`, `loops`, `arithmetic`, `member_reads`,
  `callers_of`. Every candidate the planner considers must come from one of
  them. The first version gave the planner a prose instruction and a source
  string; it spun for 171 seconds and produced nothing.
- **`audit.py`** — the loop, and **`report.py`** — JSON and SARIF.

## Three defaults that are measurements, not taste

- **The model cache is off.** dspy caches on disk, and a cached answer comes back
  in two seconds having spent zero tokens — so a sweep that re-ran a pair would
  report a cost of nothing. `--cache` turns it on for iterating on everything
  downstream of the model, and prints that the cost column then means nothing.
- **Temperature is pinned to 0.0** (`SC_SENTRY_TEMPERATURE` overrides it). Unpinned means the server's default, often
  1.0, and two runs of one harness over one unit are then two samples of an
  unrecorded distribution: comparing them measures the sampler.
- **`max_retries=3`.** Measured: 4 of 64 calls died with the adapter unable to
  parse the reply. That is reasoning-model truncation — the chain of thought and
  the structured answer share one `max_tokens` — and it presents as a model that
  cannot follow a schema, which is a different fix from the real one.

## Editing a skill

A skill is one `SKILL.md` per class under `src/sc_sentry/skills/`. The two
sections that decide the score are **what is not an instance** (precision) and
**how to cite** (recall, because a quote that is not at the locator is discarded
before it is scored, and the run then reads as a detector that found nothing
rather than as one that was wrong).

Changing prose and re-measuring is the intended loop. Record which run file the
figure came from; a figure without its run is not reproducible.

## Scoring it (optional): the contract-assay adapter

`sc_sentry.contract_assay` is how the [contract-assay][ca] benchmark measures this harness. It is an adapter and not a second harness. `detectors.py` is the harness's checks as the benchmark's `Detector`s: `evidence()` is the candidate sites, `plan()` is the class's brief, or nothing when the unit has no candidates, which costs no model call, and `verdict()` is the class definition's rejections. `caller.py` is the one function the benchmark calls when a detector asks for a model, and it runs the same planner `sc-sentry audit` runs. The harness never imports any of it, and nothing in it loops over a corpus, because the benchmark's own runner does that.

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

There is one manifest for each of the eight classes, because a manifest names one detector. Leave a class out and the score marks it `nothing_ran` with a recall of 0.0, which is the benchmark saying nobody looked. The model and the endpoint come from `.env` in the directory you run it in, and the caller reads them when it is imported, so a missing `RLM_MAIN_MODEL` ends the command with one line. `SC_SENTRY_MAX_ITERATIONS` (6) and `SC_SENTRY_CACHE=1` set the planner's turn limit and the cache, and `--max-calls` reaches the planner through the benchmark.

**What a class costs here is more than a benchmark round allows.** Each class a unit has candidates for is one planner run, and on the public corpus a run has taken 56,000 to 97,000 tokens, 35 to 42 seconds and 5 to 7 model calls against `qwen36_35b_a3b` (two runs, 2026-10-06). The benchmark's defaults for a whole unit are 4 calls, 20,000 tokens and 30 seconds. Nothing here enforces them, and the adapter prints a line when a class goes over. A host that does enforce them would refuse these runs, so the figures from this path are a measure of the harness with its budget unbounded.

For iterating on the harness there is a convenience over the same runner:

```bash
sc-sentry-contract-assay run --units 12 --out results/run.jsonl \
    --corpus contract-assay/corpus/records --source-root checkout
sc-sentry-contract-assay score results/run.jsonl \
    --corpus contract-assay/corpus/records --source-root checkout
```

`run` takes a stratified slice, which covers every class once before any class twice, because the first 12 units of a corpus whose largest class holds 200 of 478 records measure that one class. It also takes `--units 0` for every readable unit, `--only CLASS`, `--predictions-per-unit` (the benchmark's default, 9), the same `--max-*` limits as `audit`, and `--cache`. `score` prints the per-class table that the figures below come from.

`lab-v2`, the best run before the adapter moved onto the benchmark's own runner: 12 units, 8 classes, 96 runs, 64 planner runs, 2,365,095 tokens, at a cap of 3 findings for each unit and class. It counted one model call for each planner run, which the harness's usage tracker now shows to be low, since one class on one unit has taken 5 to 7, so read its call count as a floor.

| | |
|---|---|
| matched at the floor (exact or function) | **2** |
| matched only loosely (call-adjacent or file) | 6 |
| claims whose quote was not where they said | 18 |
| reachable positive records in those 12 units | 45 |
| predictions nothing in the corpus judges (queue) | 6 |
| runs the harness itself marked invalid | 4 (1 transport, 3 citation unverified) |

Three things that table says, and each is a different fix:

1. **6 loose matches** are findings in the right file, of the right class, at
   the wrong lines. The model located the *file*, not the defect. That is a
   citing problem, not a knowledge problem, and it is the cheapest gap to close.
2. **18 unverifiable claims** are quotes that were not at the lines they were
   paired with. `citing-source` exists for exactly this and is still losing.
   The usual cause is a `quote` from one tool answer paired with `start_line`
   from another.
3. **2 at the floor out of 45** is what is left after those two. It is the real
   number, and nothing in this repository dresses it up.

A figure over part of a corpus is not comparable with one over all of it. These
12 units are a stratified slice (`slices.py`), chosen to cover every class once
before covering any class twice, because the first 12 units of a corpus whose
largest class holds 200 of 478 records measures that one class.

## Licence

MIT. See [LICENSE](LICENSE).
