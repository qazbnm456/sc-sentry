---
name: arithmetic-rounding
description: Precision lost or a rounding direction that favours the wrong party. The one shape that dominates, and why most of these need a specification to call.
---

# Arithmetic and rounding

An instance is **arithmetic whose result is wrong in a direction that matters**,
at a location a fix would change. Two families, and they are found differently.

## Family one: precision destroyed by order of operations

The dominant shape, and the one you can establish from the source alone:

    amount / total * scale        // divides first: the quotient truncates
    amount * scale / total        // correct: scales first

Integer division truncates toward zero, so dividing before multiplying throws
away every digit below the divisor. Look for a division whose result is then
multiplied, or fed into another division. `divides_then_scales` finds it.

Related, same family:

- `(a / b) * b` reconstructed and compared to `a`
- a share price computed as `totalAssets / totalSupply` and then multiplied by
  a user's shares, rather than `shares * totalAssets / totalSupply`
- a fee taken as `amount * feeBps / 10000` where `amount * feeBps` can round to
  zero for small amounts — a fee-free path for dust
- mixing token decimals without normalising: 6-decimal USDC against 18-decimal
  WETH, scaled by a constant that is right for one of them

## Family two: the rounding direction favours the wrong party

`x / y` rounds down. Whether that is a defect depends on **who benefits**:

- rounding **down** when computing what a user *owes* the protocol → the user
  underpays
- rounding **up** when computing what the protocol *owes* a user → the protocol
  overpays
- a deposit that mints `assets * supply / totalAssets` shares rounding down, and
  a withdrawal that burns the same formula rounding down — the difference is a
  slow drain

This family usually needs the protocol's own intent to call. "Rounds down" is
not a defect; "rounds down where the accounting identity requires up" is. If the
source does not state which way it must go, say so rather than guessing — an
unverifiable claim costs precision and measures nothing.

## Not an instance

- a division by a literal power of ten used only for display or an event
- `unchecked` arithmetic where the bound is established immediately above
- Solidity ≥ 0.8 overflow: the compiler reverts, so an unchecked *overflow* is
  not this class unless the block is explicitly `unchecked`
- a truncation of one wei where nothing accumulates it

## What to cite

The expression, not the whole statement, when the statement holds several. The
smallest complete expression whose rewrite fixes it.
