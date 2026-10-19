# Development

## Three defaults that are measurements, not taste

- **The model cache is off.** dspy caches on disk, and a cached answer comes back in two seconds having spent zero tokens, so a sweep that re-ran a pair would report a cost of nothing. `--cache` turns it on for iterating on everything downstream of the model, and prints that the cost column then means nothing.
- **Temperature is pinned to 0.0** for the main model and the sub model alike (`SC_SENTRY_TEMPERATURE` overrides it). Unpinned means the server's default, often 1.0, and two runs of one harness over one unit are then two samples of an unrecorded distribution, so comparing them measures the sampler.
- **`max_retries=3`.** In 4 of 64 calls the adapter could not parse the reply. That is reasoning-model truncation, where the chain of thought and the structured answer share one `max_tokens`, and it looks like a model that cannot follow a schema, which calls for a different fix.

## Editing a class

A class has two places to change. The finder is `candidates/<class>.py`, and the skill is `skills/<class>/SKILL.md`. A change to a finder moves recall, because a defect the finder does not offer cannot be found, and a change to a skill moves what the model rules out. The sections of a skill that decide the score are **what is not an instance** (precision) and, in `explore`, **how to cite**.

Develop a finder against the public corpus and nothing else, and split it by repository as in [The figure is a fit](benchmark.md#the-figure-is-a-fit), because a finder fitted to a record's own location measures how well it was fitted. Record which run file a figure came from, because a figure without its run cannot be reproduced.
