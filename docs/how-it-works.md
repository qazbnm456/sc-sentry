# How it works

The harness has two halves. The first is code: for each class, `candidates/<class>.py` finds the places the class could be and ranks them by likelihood. It uses tree-sitter, so any single file works whether or not its project builds. The candidates of one function are grouped into one finding however many sites fired in it, because a defect is located to a function and a cap counts findings. The second half is the model, in one of three modes.

- **`triage`** (the default) sends the candidate functions for one class in one file to the model, numbered, with each function's code and the class's definition. The model answers a verdict per number: instance or not, how sure, and why. The citation stays with the code. The report is never shorter than the candidates: functions the model picked come first, most confident first, then the ones it was not shown, then the ones it ruled out, with its reason kept. The model can move a function up but cannot hide one. `--withdraw` changes that by marking what the model ruled out as rejected, so that a SARIF reader suppresses it; it is off for the reasons under [What the model adds](benchmark.md#what-the-model-adds).
- **`static`** asks no model. The candidates are the findings, likeliest first, each marked as not reviewed. It is the control group for everything the model adds, and it runs without a `.env`.
- **`explore`** gives a planner the file, the class and nine tools (`outline`, `read_lines`, `state_writes`, `external_calls`, `guards`, `loops`, `arithmetic`, `member_reads`, `callers_of`) and lets it investigate. Every candidate it considers must come from a tool. It is kept as a comparison with `triage`, which spends a tenth to a fortieth of its tokens (see [What it scores](benchmark.md)).

## Running under a budget

`triage` can share one allowance between the classes of a file, for a host that meters each file from outside.

- `--budget-calls N` gives the calls to the N classes with the most candidate functions, because an order matters most where there is the most to order.
- `--budget-tokens T` pays for those classes in the same order for as long as a useful call still fits, which means the call's fewest candidates plus 4,000 tokens for the answer. A reasoning model spends 2,600 to 5,000 tokens thinking before it answers, and a call cut off there costs as much as a whole one. What is left over is shared equally, and each call sends as many candidates as its share holds.
- `--budget-seconds S` counts from the start of the command and runs the calls one after another in that order. It starts a call after the first only if 8 seconds are left, and gives up on any class that has not answered by the deadline.
- `--budget-parallel` sends the calls side by side, so a file costs its slowest call rather than the sum. That suits an endpoint that answers several requests at once. Behind a relay that serves one request at a time, the later calls only queue, the ones that cannot finish before the deadline are paid for and thrown away, and they hold up the next file.

One after another is the default because of that relay. On a metered relay of that kind, side by side, 12 of 24 calls passed the deadline unanswered. One after another, the same ten units cost 12 calls and 66,429 tokens against 23 calls and 112,594 tokens, no call passed the deadline, and 12 of the 24 classes with candidates kept their static order because too little time was left to start another call.

A class the budget did not reach, or that did not answer, keeps its static order, and the report is still written: a host that stops a late process or refuses an over-budget call discards the report and records the file as failed. A failed call is not retried, since a host that counts calls counts a retry. The command exits as soon as its report is written, without running the interpreter's exit handlers, because a process that wrote a complete report and then waited on a lock was killed at the host's wall clock and the whole file recorded as a timeout. Give the budget the host's own limits less a margin, since a process stopped before its own deadline loses every class of the file.

**What a call costs.** Measured on ten public units with three classes, a call sends a prompt of 5,000 to 6,000 tokens. What the answer adds depends on the model:

| model | tokens | time per call |
|---|---|---|
| `qwen36_35b_a3b` | answers of 3,400 to 5,800 | 8 to 14 seconds |
| `qwen38-flash-next` | about 10,700 a call on average (median 9,300, 90th percentile 20,300, largest 28,300) | median 78 seconds (mean 115, 90th percentile 229), with four runs at once |

With `qwen36_35b_a3b`, a limit of 20,000 tokens and 20 seconds paid for one call in full and a second only some of the time. With `qwen38-flash-next`, 40 of 193 answers went past 16,384 tokens, so give it the 32,768 default and a budget counted in minutes.

**How many seconds a file needs.** This was measured on ten development units from the larger half of the corpus (7 to 37 candidate functions in the three ranked classes), audited with the hosted sample's own command at four time budgets, two budgets at a time on the shared endpoint. The ten units called for 25 per-class calls.

| budget | calls answered, of 25 | mean time per unit | a ten-unit sweep at the mean |
|---|---|---|---|
| 180 s | 10 | 152 s | 25 min |
| 240 s | 15 | 167 s | 28 min |
| 300 s | 16 | 201 s | 34 min |
| 540 s | 21 | 280 s | 47 min |

No run passed its budget by more than 0.7 seconds. The longest took 540.6 seconds, 49 short of the 590 at which a 600-second sandbox stops the process. Most of the calls that did not answer were the first call of a larger file, which goes to the class with the most candidates and carries up to 20 functions. Such a call takes 250 to 300 seconds or fails at the endpoint (a timeout and two server errors in the 540-second runs), so seconds past 240 buy little, and at 180 seconds seven of the ten units ran out of time. One file's first call took 193, 128, 127 and over 177 seconds in four runs, so each figure in the table is a single sample and not a range.

## What the package holds

- **`skills/`**: what each class is, including the shapes that look like it and are not, and how to cite. Seven of the eight classes have one (`insecure_randomness` does not yet), plus `citing-source`. It is prose, editable by somebody who does not read Python, and `triage` sends it to the model as the class definition.
- **`checks.py`**: wires the finders, groups them by function, and holds the rejections each class's definition settles. `insecure_randomness` keeps its finder here, and a single-line site is widened to enough whole lines for the benchmark to check the quote.
- **`audit.py`, `triage.py`, `static.py`, `report.py`**: the three modes and the JSON and SARIF writers.
- **`sites.py`** and **`solidity/`**: the tools of `explore` and the parser under everything.

These are eight of the benchmark's nine classes. `flashloan_manipulation` has no check here, so it scores nothing on its 7 records.
