---
name: slippage
description: A swap or liquidity action with no enforced bound on what comes back. What counts as a bound, and the two that only look like one.
---

# Slippage

An instance is **an exchange whose output is not bounded by anything the caller
chose.** The defect is not the swap; it is the absence of a floor under it, so a
sandwich takes the difference.

## What a bound is

A swap's `amountOutMin` (or `amountInMax`, or `sqrtPriceLimitX96`) that is:

- **non-zero**, and
- **derived from something the caller supplied**, not from the pool's own state
  at that instant

The second half is the one that is usually missed. `amountOutMin` computed as
`getAmountsOut(...) * 99 / 100` is a bound against the price the pool has *right
now*, which is the price the attacker has already moved. It bounds nothing.

## The idioms that are instances

- `swapExactTokensForTokens(amountIn, 0, path, to, deadline)` — a literal zero
- `amountOutMin` derived from `getReserves()`, `getAmountsOut()`, `slot0()`,
  `quote()`, or any read of the pool being swapped against
- `sqrtPriceLimitX96: 0` on a Uniswap V3 `exactInputSingle`
- `deadline: block.timestamp` — satisfied by definition, so the transaction can
  sit in the mempool and execute at any later price
- `addLiquidity` with `amountAMin`/`amountBMin` of zero
- a bound the *contract* chooses (a stored `maxSlippageBps`) where the caller
  bears the loss — arguable, and worth reporting only if the caller cannot
  override it
- a multi-hop path bounded only on the final output, with an unbounded
  intermediate hop

## Two that look like an instance and are not

- **A zero minimum on a function only the protocol can call**, where the
  protocol's own keeper sets the parameters atomically. Check reachability
  first.
- **A swap inside a larger operation that checks the net result afterwards** —
  `require(finalBalance >= expected)` after the fact is a bound, even if the
  swap call itself passes zero.

## What to cite

The call with the unbounded argument. When the argument is computed above, cite
the computation — that is the line a fix changes.
