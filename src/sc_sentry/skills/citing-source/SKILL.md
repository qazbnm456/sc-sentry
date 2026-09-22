---
name: citing-source
description: How a finding is checked before it is scored, and the two ways a true finding is thrown away. Read this first.
---

# Citing source

A finding is scored only if the harness can re-read the source at the locator
you gave and find the quote you gave. That check is not the detector's; it runs
unconditionally, before any verdict. **Two true findings out of three are lost
here, not to being wrong.**

## The quote must be the source, not a summary of it

The comparison normalises leading and trailing whitespace per line and ignores
blank lines. It does not tolerate:

- a reworded line (`owner = msg.sender` where the source says `owner = _owner`)
- an added or removed semicolon, brace, or `;`
- reconstructed code that reads correctly and is not in the file
- an ellipsis, a comment you inserted, or `// ...`

If you are pulling from a tool that hands you the exact text of a span, quote
**that string**, unmodified. If you are typing it from memory, you are wrong
roughly half the time and every one of those findings measures nothing.

## The lines must contain the quote

`start_line` and `end_line` are 1-indexed and inclusive, and the quote must be
what those lines hold — all of them, in order. A quote of one statement with a
span covering the whole function fails. A span off by one, because you counted a
blank line or a `pragma`, fails.

Prefer the smallest span that contains the defect and is a complete statement.

## What a failed citation costs

The run becomes `invalid` with `citation_unverified` — which means it **measured
nothing**, not that it was wrong. A class whose runs are all invalid reports no
recall and no precision, and reads exactly like a detector that found nothing.
The number of unverifiable claims is published separately, so proposing many
cheap guesses is visible rather than free.

## The order you report in is the order that counts

A cap applies per source unit per class, and it keeps the **first** few in the
order you returned them. Put your best finding first. Nothing re-ranks for you,
and nothing warns you that the cap bit.
