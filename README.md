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

## Use

```bash
sc-sentry classes                                  # the eight classes it hunts
sc-sentry audit contracts/*.sol                    # every class, JSON to stdout
sc-sentry audit Pool.sol --class reentrancy --class oracle_integrity \
    --format sarif --out pool.sarif
```

A finding the class definition rejects -- say, a slippage citation in a
function that makes no exchange call -- is **kept, marked**: `rejected` in JSON,
a suppressed result with the reason in SARIF. Whoever reads the report decides
whether the screen was right, which they cannot do with what it silently took.

## How it works

- **`skills/`** — what each class *is*, including the shapes that look like it
  and are not, and how to cite. Eight classes plus `citing-source`. Prose,
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
- **Temperature is pinned to 0.0.** Unpinned means the server's default, often
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

`sc_sentry.assay` adapts the harness to the [contract-assay][ca] benchmark:
the same checks exposed as its `Detector`s, a sweep over its corpus that writes
the runs file it scores, and a scoring front-end. The harness never imports it.

[ca]: https://github.com/qazbnm456/contract-assay

```bash
# contract-assay is not on PyPI yet: install it from a clone first.
git clone https://github.com/qazbnm456/contract-assay
pip install -e ./contract-assay && pip install -e "./sc-sentry[assay]"

contract-assay fetch contract-assay/corpus/records --source-root checkout
sc-sentry-assay --units 12 --out results/run.jsonl \
    --corpus contract-assay/corpus/records --source-root checkout
sc-sentry-score results/run.jsonl \
    --corpus contract-assay/corpus/records --source-root checkout
```

The adapter adds no judgement of its own -- `evidence()` is the harness's
candidates and `verdict()` its rejections -- so a benchmark figure measures
the same harness `sc-sentry audit` runs. What it measured:


`lab-v2`, the best run to date: 12 units, 8 classes, 96 runs, 64 model calls,
2,365,095 tokens.

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
largest class holds 190 of 435 records measures that one class.

## Licence

MIT. See [LICENSE](LICENSE).
