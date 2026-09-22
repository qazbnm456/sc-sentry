# sc-sentry

Smart Contract Sentry: an RLM agent that audits one Solidity unit for one
vulnerability class and cites the exact lines it found it at.

It is a **submission**, not a benchmark. [contract-assay][ca] defines what a
finding is, verifies the citation against a pinned commit, and scores the run.
A harness that scores itself has measured its own opinion, so scoring does not
live here.

[ca]: https://github.com/qazbnm456/contract-assay

> **Status: honest about a low number.** Over 12 units and 96 runs, the best
> configuration to date matched **2 of 45** reachable records at the strength
> floor. The figures are below, with the command that produced them. This
> repository exists to show the shape of a harness that can be scored at all —
> not to claim the class is solved.

## What it measured

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

## Install

`contract-assay` is not on PyPI yet, so install it from a clone first. `pip`
treats an already-installed requirement as satisfied and will not go looking.

```bash
git clone https://github.com/qazbnm456/contract-assay
git clone https://github.com/qazbnm456/sc-sentry
python -m venv .venv && . .venv/bin/activate
pip install -e ./contract-assay
pip install -e ./sc-sentry
```

## Use

```bash
# 1. Fetch the pinned sources the corpus names. Verified against a digest.
contract-assay fetch contract-assay/corpus/records --source-root checkout

# 2. Point it at a model.
cp .env.example .env && $EDITOR .env

# 3. Audit a slice. --units 0 is every readable unit, and costs real money.
sc-sentry --units 12 --out results/run.jsonl \
          --corpus contract-assay/corpus/records --source-root checkout

# 4. Score it. The corpus decides, not this package.
sc-sentry-score results/run.jsonl \
          --corpus contract-assay/corpus/records --source-root checkout
```

`--corpus` and `--source-root` are required rather than defaulted to a sibling
directory: a default would make the figures depend on where the clone happens to
sit, and a run scored against a different checkout than it audited is scored
against different text, so every quote fails to verify.

`checkout/` and `results/` are not committed. The first is reproducible from the
corpus; the second is 600KB of JSONL behind a number that belongs in prose.

## The four parts

- **`skills/`** — what each class *is*, including the shapes that look like it
  and are not, and how to cite. Eight classes plus `citing-source`. Prose,
  editable by somebody who is not reading Python, injected at startup so the
  planner never spends a turn finding out what it knows.
- **`sites.py`** — nine tree-sitter-backed tools: `outline`, `read_lines`,
  `state_writes`, `external_calls`, `guards`, `loops`, `arithmetic`,
  `member_reads`, `callers_of`. Every candidate the planner considers must come
  from one of them. The first version of this task gave the planner a prose
  instruction and a source string; it spun for 171 seconds and produced nothing.
- **`detectors.py`** — the deterministic half the benchmark scores through.
  `evidence()` records what is true of the source whatever the model concludes;
  `verdict()` rejects what the class definition does not cover, by *asking the
  evidence* rather than re-deriving the observation.
- **`run.py`** — the loop. A class with no candidate sites in a unit costs
  nothing, because `plan()` returns `None` and a planner asked to audit a file
  with no sites of what it seeks will invent one.

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

## Licence

MIT. See [LICENSE](LICENSE).
