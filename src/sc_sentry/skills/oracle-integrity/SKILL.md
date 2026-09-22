---
name: oracle-integrity
description: A price or rate consumed without establishing that it is fresh, sane, and not manipulable. What must be checked and what a check must cover.
---

# Oracle integrity

An instance is **a value read from outside and used in a decision without
establishing that it can be trusted.** The decision is usually a mint, a
liquidation, a collateral ratio, or a swap bound.

## The three properties, and what establishes each

- **Freshness.** `latestRoundData` returns `updatedAt`; using the answer
  without comparing it to `block.timestamp` against a heartbeat is an instance.
  `latestAnswer`/`latestRound` are deprecated *because* they cannot carry it.
- **Sanity.** A negative or zero `answer`, or one outside `minAnswer`/
  `maxAnswer`, is a feed at its circuit-breaker bound reporting a price that is
  not the market price. Casting `int256` to `uint256` without checking the sign
  is an instance in its own right.
- **Manipulability.** A spot read from an AMM — `getReserves`, `slot0`,
  `balanceOf` of a pool, `getAmountsOut` — is the price *at this instant*, and
  an instant is purchasable with a flash loan. A TWAP, or a second independent
  feed, is what establishes it.

## The idioms that are instances

- `(, int256 price, , , ) = feed.latestRoundData();` then `price` used directly
- `updatedAt` destructured and never read
- a Pyth/Redstone read with no `publishTime` / staleness argument
- `getReserves()` divided to produce a price used for collateral
- a rebasing or fee-on-transfer token's `balanceOf` treated as a share price
- a hard-coded decimals assumption (`price * 1e10`) where the feed's `decimals()`
  says otherwise — a correct price scaled wrong is a wrong price
- one heartbeat constant reused for every feed, where the feeds' own heartbeats
  differ

## Not an instance

- the staleness check exists and is simply further up the function, or in a
  library the function calls
- the value is not used in a decision — logged, or returned to a caller that
  checks it
- it is a TWAP over a window long enough to make manipulation cost more than
  the position

## What to cite

The line that **uses** the value in the decision, not the line that read it,
when they differ — that is where the missing check has to go.
