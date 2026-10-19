# What it scores

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

## The figure is a fit

The finders were written against this corpus. Split by repository, 70 and 30 by a hash of the repository name, the finders recall 0.82 on the development part and 0.72 on the part held back. The held-back part was looked at while tuning, up to three times for each class, so 0.72 is still an optimistic estimate for a corpus the finders have not seen. Because the split is by repository name, a file pinned under two names lands on both sides: 5 of the 40 files held back are byte for byte a file in the development part, and without them the recall on the part held back is 0.720 rather than 0.724.

## Precision is not measured

`static` makes about 3,300 predictions that match no record and that the corpus has no judgment for. Its precision is unavailable, not zero, and a benchmark that ranks on precision will not rank it on this figure. The one way to raise precision without touching recall is to cut predictions that cannot be an instance, and the `unchecked_external_call` finder does that since version 0.6.1. It lists a call only when the call can return a status the caller drops, and orders the functions by how likely that is: a low-level call or `send` whose flag is never read, then a token `transfer`, `transferFrom` or `approve` whose `bool` is dropped, then a function the file declares with a `returns` clause, and last a call into a contract the file only imports. A finder that listed every statement that calls something, `require` included, cited a `require` line in a candidate judged real instead of the unchecked `transfer` a few lines below it.

The narrower finder makes 378 predictions on the development part instead of 708, at the same 5 of 6 records, and 193 on the part held back instead of 260, where its matches go from 2 to 3 of 4. Over all classes at a cap of 9, the F1 at the function floor is 0.191 on the development part (0.172 with the broader finder) and 0.152 on the part held back (0.141), at recalls of 0.823 and 0.724. The part held back was read while the finder was written, so its gain is not a held-out figure.

## What the model adds

At the default cap neither model measured added anything to recall, and withdrawing what a model rules out costs most of the matches. Two models were measured in `triage`: `qwen36_35b_a3b`, which the endpoint no longer serves, and `qwen38-flash-next`, the one it serves now.

**`qwen36_35b_a3b`.** On the development part, for slippage, oracle_integrity and denial_of_service, the model's order and the static order matched the same records within nine findings: 25 of 28, 42 of 58 and 127 of 151. On the part held back, over all eight classes, the model's order matched 84 of 114 records and the static order 83, and in first place 32 against 31. The development runs cost 130,000, 207,000 and 760,000 tokens over 23, 43 and 116 files, and the held-back runs 1.3 million over 193, so a call averages about 6,000 to 7,000 tokens. Withdrawing the candidates the model ruled out, which is what a report that suppresses them does, leaves 27 of the 114 matches at the function floor instead of 84, and the model's confidence does not help: withdrawing only what it was certain of, 5 on a scale of 5, still leaves 30.

**`qwen38-flash-next`.** It was run over both parts with the finders of version 0.6.0. Version 0.6.1 changed only `unchecked_external_call`, and the model was not run again over that finder's new candidates, so the prediction counts below include the old ones for that class. On the part held back it read 193 files with at least two candidates and used 2.7 million tokens. 31 answers were cut off at 16,384 tokens and asked again at 32,768, and every pair was answered in the end. On the development part it read 583 files with at least two candidates over 134 units and 355 positive records, answered every pair, and used about 5 million tokens.

The figures below are counted as the benchmark counts them: over every unit of the part, with each prediction the corpus does not know counted as wrong. The part held back has 116 positive records, two of them in flashloan_manipulation, which the harness has no check for, so 114 is the most it can reach there. The last column is the macro F1 over the three classes the classroom rounds rank.

| part | cap | list | predictions | matches | recall | precision | F1 | F1, ranked classes |
|---|---|---|---|---|---|---|---|---|
| held back | 9 | model's order | 1,058 | 83 | 0.72 | 0.08 | 0.141 | |
| held back | 9 | static | 1,058 | 83 | 0.72 | 0.08 | 0.141 | |
| held back | 9 | withdrawn | 237 | 36 | 0.31 | 0.15 | 0.204 | |
| held back | 3 | model's order | | 70 | | | 0.213 | 0.337 |
| held back | 3 | static | | 64 | | | 0.195 | 0.318 |
| held back | 3 | withdrawn | | | | | 0.236 | 0.318 |
| development | 9 | model's order | 3,033 | 292 | | | 0.172 | 0.353 |
| development | 9 | static | 3,033 | 292 | | | 0.172 | 0.353 |
| development | 9 | withdrawn | 593 | 95 | 0.27 | 0.16 | 0.200 | 0.288 |
| development | 3 | model's order | | 220 | | | 0.217 | 0.355 |
| development | 3 | static | | 222 | | | 0.219 | 0.369 |

At a cap of 9 the model's order and the static list are the same list on both parts. At a cap of 3 the model's order gained six matches on the part held back, and that gain did not repeat on the development part. Withdrawing raises precision by giving up more than half the matches, and it does not raise the figure the classroom ranks on: over the ranked classes it equals the static list on the part held back and falls from 0.353 to 0.288 on the development part.

**Judged samples.** The corpus says nothing about a prediction it has no record of, so two samples of such predictions on the part held back were judged by hand, one for each model. In both, the judges read the candidates shuffled, without knowing which ones the model had kept.

| | `qwen36_35b_a3b` | `qwen38-flash-next` |
|---|---|---|
| candidates judged | 54 | 54, stratified by class, 8 each in the three ranked classes |
| of them kept by the model | 14, all it kept | 26 |
| of them ruled out | 40, at random from the 241 it ruled out | 28 |
| real among the kept | 1, where a second panel found 3 | 4 (15 percent) |
| real among the ruled out | 1 (about 3 percent, 95 percent interval 0 to 13) | 1 (4 percent) |
| how it was judged | prefilled by reviewer agents and checked by one person, who changed none; a second, blind panel agreed on 50 of 54 | read by two panels of reviewer agents and checked by one person, who settled the one claim the panels split on |

`qwen36_35b_a3b` was right about most of the unknown candidates it ruled out, and wrong about two thirds of what the corpus knows is real. Its sample is small, and the kept group of 14 is its weak part.

For `qwen38-flash-next` the verdict separates the two groups about four to one, as the other model's did, and about nine in ten of the unknown predictions are not real either way. The ruled-out pool is five times the size of the kept one (763 against 156), so scaling each class's rate by its pool puts about as many real instances in the ruled-out pool as in the kept one. Those cells hold three to five claims each, though, and one class, unchecked_external_call, carries most of the estimate. At the point estimates, withdrawing raises the F1 that counts judged instances from 0.25 to 0.31 over all classes and from 0.36 to 0.50 over the three ranked classes, at a precision of 0.28 against 0.15 and a recall of 0.35 against 0.83. With each cell's rate drawn from a Jeffreys posterior, withdrawing minus ordering is -0.04 over all classes (95 percent interval -0.24 to 0.13) and +0.05 over the ranked classes (-0.14 to 0.15). The chance that withdrawing is ahead is 0.34 and 0.70, and one changed verdict moves the second to 0.46. The sample cannot rank the two lists on F1, so `--withdraw` stays off, because the default ranking, bpref, is driven by recall.

## Choosing a cap

A lower cap trades recall for precision, and it pays on F1. Counting predictions as the benchmark does, `static` at a cap of 3 findings for each class and unit has an F1 at the function floor of 0.234 on the development part and 0.199 on the part held back, against 0.191 and 0.152 at the cap of 9, at recalls of 0.63 and 0.55 against 0.82 and 0.72. Over the three classes the classroom rounds rank, weighted 2 for denial_of_service and 3 for oracle_integrity and slippage, the macro F1 goes from 0.353 to 0.369 on the development part and from 0.259 to 0.318 on the part held back. So `--limit 3` is the setting for a round ranked on F1, and `--limit 9`, the default, for one ranked on bpref or on recall.

## Which versions the model figures hold for

The model figures were measured on rlm-harness 1.11 with dspy 3.3, and the harness now needs rlm-harness 1.20 and dspy 3.4. No model run has been repeated on them, and for `triage` the change should not move the figures. A triage call is one `dspy.Predict` through rlm-harness's JSON adapter, and for its signature dspy 3.3.1 and 3.4.1 build byte-identical messages and an identical response schema, compared without a model. They differ in one place, the parse: a reply that drops its outer braces fails on 3.3.1 and is recovered on 3.4.1. That can only turn a failed call into an answered one, and every pair in the measured runs was answered. The cache was off for those runs and is off now. What lies below the adapter, `dspy.LM` and litellm, was not compared. `explore` did change, since dspy 3.4 adds a paragraph to every RLM prompt and rlm-harness 1.18 added three sentences to its validator tool, so its figures are for the older stack. The static figures ask no model and depend on neither.

## Why the code chooses the citations

In `explore` the model picks the lines it cites, and that is why `triage` leaves the citing to code. On a 12-unit slice of eight classes, `explore` matched 2 of 45 reachable records at the floor, and 18 of its claims quoted lines that were not at the lines they gave, which the benchmark records as unverifiable. A planner on one class in one file took 56,000 to 97,000 tokens, 35 to 42 seconds and 5 to 7 model calls against `qwen36_35b_a3b` (two runs, 2026-10-06).
