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
| `--budget-parallel` | off | `triage` only: with a budget, send the classes' calls side by side |
| `--withdraw` | off | `triage` only: mark what the model ruled out as rejected, which a SARIF reader suppresses |
| `--max-tokens` | `RLM_MAX_TOKENS`, else 32768 | per-call generation cap |
| `--max-calls` | 4 | model calls per class |
| `--max-iterations` | 6 | planner turns per class, in `explore` |
| `--cache` | off | see below |

A finding the class definition rejects (say, a slippage citation in a function that makes no exchange call) is kept and marked: `rejected` in JSON, a suppressed result with the reason in SARIF. Whoever reads the report decides whether the screen was right, which they cannot do with what it silently took. JSON also says where each finding came from: `origin` is `model` when a model decided it and `static` when the harness cited it and no model reviewed it.

## How it works

The harness has two halves. The first is code: for each class, `candidates/<class>.py` finds the places the class could be and says which are likeliest, using tree-sitter, so any single file works whether or not its project builds. The candidates of one function are grouped, so a function is one finding however many sites fired in it, because a defect is located to a function and a cap counts findings. The second half is the model, in one of three modes.

- **`triage`** (the default) sends the candidate functions for one class in one file to the model, numbered, with each function's code and the class's definition. The model answers a verdict per number: instance or not, how sure, and why. The citation stays with the code. The report is never shorter than the candidates: functions the model picked come first, most confident first, then the ones it was not shown, then the ones it ruled out with its reason kept. The model can move a function up and cannot hide one, unless you ask it to with `--withdraw`, which marks what it ruled out as rejected so that a SARIF reader suppresses it. That is off, for the reason under What it scores.
- **`static`** asks no model. The candidates are the findings, likeliest first, each marked as not reviewed. It is the control group for everything the model adds, and it runs with no `.env`.
- **`explore`** gives a planner with nine tools (`outline`, `read_lines`, `state_writes`, `external_calls`, `guards`, `loops`, `arithmetic`, `member_reads`, `callers_of`) the file and the class and lets it investigate, and every candidate it considers must come from a tool. It was the first design and is kept for comparison, because it costs ten to forty times the tokens of `triage` (below).

**Under a budget**, `triage` shares one allowance between the classes of a file, for a host that meters a file from outside. `--budget-calls N` gives the calls to the N classes with the most candidate functions, because an order matters most where there is the most to order. `--budget-tokens T` pays for those classes in that order for as long as a useful call still fits: its fewest candidates and 4,000 tokens for the answer, since a reasoning model spends 2,600 to 5,000 tokens thinking before it answers and a call cut off there costs what a whole one does. What is left over is shared equally, and each call sends as many candidates as its share holds. `--budget-seconds S` counts from the start of the command, runs the calls one after another in that order, starts a call after the first only if 8 seconds are left, and gives up on any class that has not answered by then. `--budget-parallel` sends them side by side instead, so a file costs the slowest call and not the sum, which is right for an endpoint that answers several at once and wrong behind a relay that serves one request at a time: the later calls only queue, the ones that cannot finish before the deadline are paid for and thrown away, and they hold up the next file. On a metered relay of that kind, 12 of 24 side-by-side calls passed the deadline unanswered, so one after another is the default. One after another, the same ten units cost 12 calls and 66,429 tokens against 23 and 112,594, no call passed the deadline, and 12 of the 24 classes with candidates kept their static order because too little time was left to start another call. A class the budget did not reach, or that did not answer, keeps its static order and the report is still written, because a host that stops a late process or refuses an over-budget call discards the report and records the file as failed. A failed call is not retried, since a host that counts calls counts a retry. Give it the host's own limits less a margin: a process stopped before its own deadline loses every class of the file. Measured on ten public units with three classes, a call costs a prompt of 5,000 to 6,000 tokens, and what the answer adds depends on the model. `qwen36_35b_a3b` answered with 3,400 to 5,800 tokens in 8 to 14 seconds, so a limit of 20,000 tokens and 20 seconds paid for one call in full and a second only some of the time. `qwen38-flash-next` averaged about 10,700 tokens a call (median 9,300, 90th percentile 20,300, largest 28,300) and took a median of 78 seconds (mean 115, 90th percentile 229) with four runs at once, and 40 of 193 answers went past 16,384 tokens, so give it the 32,768 default and a budget counted in minutes. How many minutes was measured on ten development units chosen from the larger half (7 to 37 candidate functions in the three ranked classes), audited with the hosted sample's own command at four time budgets, two budgets at a time on the shared endpoint. Of the 25 per-class calls those units called for, 10 were answered at 180 seconds, 15 at 240, 16 at 300 and 21 at 540, and the mean time for a unit was 152, 167, 201 and 280 seconds, so a ten-unit sweep at the mean takes 25, 28, 34 and 47 minutes. A run never passed its budget by more than 0.7 seconds, and the longest took 540.6 seconds, 49 short of the 590 at which a 600-second sandbox stops the process. The calls that did not answer were mostly the first one of a larger file, the class with the most candidates, up to 20 functions in one call: such a call takes 250 to 300 seconds or fails at the endpoint (a timeout and two server errors in the 540-second runs), so seconds past 240 buy little, and at 180 seven units of ten ran out of time. The same file took 193, 128, 127 and over 177 seconds for its first call in four runs, so each figure is one sample and not a range. Whatever the budget does not reach is static. The command also ends by itself once it has written its report, without running the interpreter's exit handlers, from version 0.6.2: in a dry run a report was complete and the process then waited on a lock until the host killed it at its wall clock, and the host recorded the whole file as a timeout.

The rest of the package, by what it holds:

- **`skills/`**: what each class is, including the shapes that look like it and are not, and how to cite. Seven of the eight classes have one (`insecure_randomness` does not yet), plus `citing-source`. It is prose, editable by somebody who is not reading Python, and `triage` sends it to the model as the class definition.
- **`checks.py`**: wires the finders, groups them by function, and holds the rejections each class's definition settles. `insecure_randomness` keeps its finder here, and a single-line site is widened to enough whole lines for the benchmark to check the quote.
- **`audit.py`, `triage.py`, `static.py`, `report.py`**: the three modes and the JSON and SARIF writers.
- **`sites.py`** and **`solidity/`**: the tools of `explore` and the parser under everything.

These are eight of the benchmark's nine classes. `flashloan_manipulation` has no check here, so it scores nothing on its 7 records.

## What it scores

The public corpus judges whether a finding sits at a known defect, which is recall. It holds no judgment for a finding that matches nothing, so precision is not measured, and a number below is recall unless it says otherwise.

`static` over the whole corpus, with at most nine findings for each class in each unit, matched 376 of the 471 positive records at the function floor (the same lines, or the same function), which is 0.798. 443 matched at any strength. 165 of the 166 units could be scored.

| class | positive records | at the floor |
|---|---|---|
| denial_of_service | 200 | 159 |
| arithmetic_rounding | 66 | 57 |
| oracle_integrity | 66 | 50 |
| access_control | 62 | 51 |
| slippage | 38 | 32 |
| reentrancy | 20 | 18 |
| unchecked_external_call | 10 | 8 |
| flashloan_manipulation | 7 | 0 |
| insecure_randomness | 2 | 1 |

Three things limit what that figure says.

1. **It is a fit.** The finders were written against this corpus. Split by repository, 70 and 30 by a hash of the repository name, the finders recall 0.82 on the development part and 0.72 on the part held back, and the held-back part was looked at while tuning (up to three times for each class), so 0.72 is still an optimistic estimate of a corpus the finders have not seen. The split is by repository name, so a file pinned under two names lands on both sides: 5 of the 40 files held back are byte for byte a file in the development part, and without them the recall on the part held back is 0.720 and not 0.724.
2. **It does not count what it gets wrong.** `static` makes about 3,300 predictions that match no record and that the corpus has no judgment for. Its precision is unavailable, not zero, and a benchmark that ranks on precision will not rank it on this figure. Cutting predictions that cannot be an instance is the one way to raise it without touching recall, and version 0.6.1 does that for `unchecked_external_call`. That finder had listed every statement that calls something, `require` included, and in a candidate judged real it cited a `require` line and not the unchecked `transfer` a few lines below. It now lists a call only when it can return a status the caller drops, and orders the functions by how likely that is: a low-level call or `send` whose flag is never read, a token `transfer`, `transferFrom` or `approve` whose `bool` is dropped, a function the file declares with a `returns` clause, and last a call into a contract the file only imports. On the development part the class went from 708 predictions to 378 at the same 5 of 6 records, and on the part held back from 260 to 193 with the matches going from 2 to 3 of 4. Over all classes at a cap of 9, the F1 at the function floor is 0.191 on the development part (it was 0.172) and 0.152 on the part held back (0.141), at recalls of 0.823 and 0.724. The part held back was read while the finder was written, so its gain is not a held-out figure.
3. **At the default cap the model added nothing measurable to recall, and withdrawing what it rules out costs most of the matches.** Two models were measured. `qwen36_35b_a3b` was first, and the endpoint has since withdrawn it. On the development part, for slippage, oracle_integrity and denial_of_service, the model's ordering of the candidates and the static order matched the same number of records within nine findings: 25 of 28, 42 of 58 and 127 of 151. On the part held back, over all eight classes, the model's order matched 84 of 114 records and the static order 83, and in first place 32 against 31. The development runs cost 130,000, 207,000 and 760,000 tokens over 23, 43 and 116 files and the held-back runs 1.3 million over 193, so a call in `triage` averages about 6,000 to 7,000 tokens. Those figures are for the order. Withdrawing the candidates the model ruled out, which is what a report that suppresses them does, left 27 of the 114 matches at the function floor against 84, and the model's confidence is no help: withdrawing only what it was certain of, 5 on a scale of 5, still left 30. A judge then read 54 candidates on the part held back, none of which the corpus has a record of: all 14 the model kept and 40 drawn at random from the 241 it ruled out, shuffled so that the judge could not tell which was which. One of the 40 withdrawn was a real instance, about 3 percent with a 95 percent interval of 0 to 13, and one of the 14 kept was, where a second panel of reviewers found three. So that model was right about most of the unknown candidates it rules out and wrong about two thirds of what the corpus knows is real. The verdicts were prefilled by reviewer agents and checked by one person, who changed none, and a second, blind panel agreed with them on 50 of 54, so this is a small sample and the kept group of 14 is the weak part of it. `qwen38-flash-next`, the model the endpoint serves now, was then run over the whole part held back, with the finders as they were in 0.6.0 (version 0.6.1 changed only `unchecked_external_call`, and the model was not run again over its new candidates, so the prediction counts below include the old ones for that class): 193 files with at least two candidates and 2.7 million tokens, 31 answers cut off at 16,384 tokens and asked again at 32,768, and every pair answered in the end. A call averaged about 10,700 tokens and took a median of 78 seconds, with four runs at once. Counted as the benchmark counts, over every unit of the part and all 116 positive records (two of them in flashloan_manipulation, which the harness has no check for, so the 114 above are the most it can reach), with each prediction the corpus does not know counted as wrong: at a cap of 9 its order makes the same 1,058 predictions and 83 matches as the static list, a recall of 0.72, a precision of 0.08 and an F1 of 0.141. At a cap of 3 it matches 70 where the static list matches 64, an F1 of 0.213 against 0.195, and 0.337 against 0.318 over the three classes the classroom rounds rank. Withdrawing what it ruled out leaves 237 predictions and 36 matches at a cap of 9, a recall of 0.31, a precision of 0.15 and an F1 of 0.204. At a cap of 3 that is an F1 of 0.236, but over the three ranked classes it is 0.318, the static list's figure and below the model's order alone. So withdrawing raises precision by giving up more than half the matches, and it does not raise the figure the classroom ranks on. The development part, run the same way, gives the same picture and takes back the one gain: 583 files with at least two candidates over 134 units and 355 positive records, every pair answered, about 5 million tokens. At a cap of 9 the model's order and the static list both match 292 records from 3,033 predictions, an F1 of 0.172 and 0.353 over the ranked classes. At a cap of 3 the order matches 220 where the static list matches 222, an F1 of 0.217 against 0.219 and 0.355 against 0.369 over the ranked classes, so the six extra matches at that cap on the part held back did not repeat. Withdrawing leaves 95 matches from 593 predictions, a recall of 0.27 and a precision of 0.16: the F1 rises from 0.172 to 0.200, and over the ranked classes it falls from 0.353 to 0.288. A second judged sample was drawn for `qwen38-flash-next` from the same part: 54 candidates the corpus has no record of, stratified by class (the three classes the classroom ranks got 8 each), 26 the model kept and 28 it ruled out, shuffled so that the judges could not tell which was which, read by two panels of reviewer agents and checked by one person, who settled the one claim the panels split on. 4 of the 26 kept (15 percent) and 1 of the 28 ruled out (4 percent) were real instances, so the model's verdict separates the two groups about four to one, as the other model's did, and about nine in ten of the unknown predictions are not real either way. The ruled-out pool is five times the size of the kept one (763 against 156), so scaling each class's rate by its pool puts about as many real instances in the ruled-out pool as in the kept one, but those cells hold three to five claims each and one class, unchecked_external_call, carries most of the estimate. At the point estimates, withdrawing raises the F1 that counts judged instances from 0.25 to 0.31 over all classes and from 0.36 to 0.50 over the three ranked classes, at a precision of 0.28 against 0.15 and a recall of 0.35 against 0.83. With each cell's rate drawn from a Jeffreys posterior, withdrawing minus ordering is -0.04 over all classes (95 percent interval -0.24 to 0.13) and +0.05 over the ranked classes (-0.14 to 0.15), and the chance that withdrawing is ahead is 0.34 and 0.70, the second of which one changed verdict moves to 0.46. So the sample cannot rank the two lists on F1, and `--withdraw` stays off because the default ranking, bpref, is driven by recall.
4. **A lower cap trades recall for precision, and it pays on F1.** Counting predictions as the benchmark does, `static` at a cap of 3 findings for each class and unit has an F1 at the function floor of 0.234 on the development part and 0.199 on the part held back, against 0.191 and 0.152 at the cap of 9, at recalls of 0.63 and 0.55 against 0.82 and 0.72. Over the three classes the classroom rounds rank, weighted 2 for denial_of_service and 3 for oracle_integrity and slippage, the macro F1 goes from 0.353 to 0.369 on the development part and from 0.259 to 0.318 on the part held back. So `--limit 3` is the setting for a round ranked on F1, and `--limit 9`, the default, for one ranked on bpref or on recall.

The model figures were measured on rlm-harness 1.11 with dspy 3.3. The harness now needs rlm-harness 1.20 and dspy 3.4, and no model run has been repeated on them. dspy 3.4 adds a paragraph to every RLM prompt, which `explore` sends and `triage` does not, because a triage call is one `dspy.Predict`. Whether 3.4 changed what that call sends has not been checked, so the model figures are for the older stack. The static figures ask no model and do not depend on either.

`explore` is why the harness grew candidates. Its first run on a 12-unit slice of eight classes matched 2 of 45 reachable records at the floor, and 18 of its claims quoted lines that were not at the lines they gave, which the benchmark records as unverifiable. A planner on one class in one file took 56,000 to 97,000 tokens, 35 to 42 seconds and 5 to 7 model calls against `qwen36_35b_a3b` (two runs, 2026-10-06).

## Three defaults that are measurements, not taste

- **The model cache is off.** dspy caches on disk, and a cached answer comes back in two seconds having spent zero tokens, so a sweep that re-ran a pair would report a cost of nothing. `--cache` turns it on for iterating on everything downstream of the model, and prints that the cost column then means nothing.
- **Temperature is pinned to 0.0** for the main model and the sub model alike (`SC_SENTRY_TEMPERATURE` overrides it). Unpinned means the server's default, often 1.0, and two runs of one harness over one unit are then two samples of an unrecorded distribution: comparing them measures the sampler.
- **`max_retries=3`.** Measured: 4 of 64 calls died with the adapter unable to parse the reply. That is reasoning-model truncation (the chain of thought and the structured answer share one `max_tokens`) and it presents as a model that cannot follow a schema, which is a different fix from the real one.

## Editing a class

A class has two places to change. The finder is `candidates/<class>.py`, and the skill is `skills/<class>/SKILL.md`. A change to a finder moves recall, because a defect the finder does not offer cannot be found, and a change to a skill moves what the model rules out. The sections of a skill that decide the score are **what is not an instance** (precision) and, in `explore`, **how to cite**.

Develop a finder against the public corpus and nothing else, and split it by repository as above, because a finder fitted to a record's own location measures how well it was fitted. Record which run file a figure came from, because a figure without its run is not reproducible.

## Scoring it (optional): the contract-assay adapter

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
