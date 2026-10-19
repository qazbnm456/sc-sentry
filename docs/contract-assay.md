# Scoring it with the contract-assay adapter

`sc_sentry.contract_assay` is how the [contract-assay][ca] benchmark measures this harness. It is an adapter and not a second harness. `detectors.py` is the harness's checks as the benchmark's `Detector`s: `evidence()` is the candidate sites, `plan()` is the class's brief, or nothing when the unit has no candidates, which costs no model call, and `verdict()` is the class definition's rejections. `caller.py` is the one function the benchmark calls when a detector asks for a model, and it runs `triage` unless `SC_SENTRY_MODE=explore`. The harness never imports any of it, and nothing in it loops over a corpus, because the benchmark's own runner does that.

[ca]: https://github.com/qazbnm456/contract-assay

The extra installs contract-assay from PyPI. Its wheel is the engine only, and the corpus it scores against is in its repository, so a run needs a clone of that too. Then follow the benchmark's README ("Where to start"), which is the path for any harness of your own. For this one it is:

```bash
git clone --branch v0.1.3 https://github.com/qazbnm456/contract-assay
pip install -e "./sc-sentry[contract-assay]"
contract-assay fetch contract-assay/corpus/records --source-root checkout

args=(); for m in sc-sentry/src/sc_sentry/contract_assay/manifests/*.manifest.json; do args+=(--manifest "$m"); done
contract-assay run "${args[@]}" \
    --records contract-assay/corpus/records --source-root checkout \
    --model-caller sc_sentry.contract_assay.caller:call --limit 5 --out results/run.jsonl

contract-assay score results/run.jsonl --records contract-assay/corpus/records \
    --source-root checkout --submission-id sc-sentry --out results/score.json
```

There is one manifest for each of the eight classes, because a manifest names one detector. Leave a class out and the score marks it `nothing_ran` with a recall of 0.0, which is the benchmark saying nobody looked. The model and the endpoint come from `.env` in the directory you run it in, and the caller reads them when it is imported, so a missing `RLM_MAIN_MODEL` ends the command with one line. `SC_SENTRY_MODE` (`triage` or `explore`), `SC_SENTRY_CANDIDATES` (20), `SC_SENTRY_MAX_ITERATIONS` (6) and `SC_SENTRY_CACHE=1` set what a call does, and `--max-calls` reaches it through the benchmark.

The manifests under `manifests/static/` name the same eight classes as detectors that ask for no model, with ids that start `sentry-static-`. They need no `--model-caller` and no `.env`, and the benchmark records their runs as produced without a model. Score them under a different `--submission-id` from the model's, so that the two are two rows to compare.

**A unit can cost more than a benchmark round allows.** Triage makes one call for each class a file has candidates in, so a file with five such classes makes five, and the benchmark's defaults for a whole unit are 4 calls, 20,000 tokens and 30 seconds. Nothing here enforces them, and the adapter prints a line when a call goes over. A host that does enforce them would refuse such units, so figures from this path measure the harness with its budget unbounded. `explore` is further over, by the figures in [Why the code chooses the citations](benchmark.md#why-the-code-chooses-the-citations).

For iterating on the harness there is a convenience over the same runner:

```bash
sc-sentry-contract-assay run --units 12 --out results/run.jsonl \
    --corpus contract-assay/corpus/records --source-root checkout
sc-sentry-contract-assay score results/run.jsonl \
    --corpus contract-assay/corpus/records --source-root checkout
```

`run` takes a stratified slice, which covers every class once before any class twice, because the first 12 units of a corpus whose largest class holds 200 of its 478 records measure that one class. It also takes `--mode {triage,explore,static}`, `--units 0` for every readable unit, `--only CLASS`, `--predictions-per-unit` (the benchmark's default, 9), the same `--max-*` limits as `audit`, and `--cache`. `score` prints the per-class table. A figure over part of a corpus is not comparable with one over all of it.
