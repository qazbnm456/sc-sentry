---
name: denial-of-service
description: A path that can be made to always revert or never fit in a block. The three mechanisms, and why "gas is expensive" is not one of them.
---

# Denial of service

An instance is **a path an attacker can make permanently unusable, for somebody
other than themselves.** Three mechanisms, ordered by how often they actually
occur -- an unbounded loop is the one everybody looks for and the rarest of the
three.

## 1. A revert an outsider controls on a path somebody else needs

- pushing ether or tokens to an address that reverts, inside a loop that pays
  everybody — one reverting recipient freezes the whole distribution
- `transfer` to a contract with no receive function, in a queue
- a `require` on a state an attacker can set (registering the last slot, taking
  a unique name someone else needs)
- an auction whose refund to the previous bidder must succeed for a new bid to
  land — the classic King-of-the-Hill freeze
- reliance on a single external call that can be made to revert (an oracle a
  griefer can pause)

## 2. A state the protocol cannot leave

- a first-depositor share-inflation that makes later deposits round to zero
  shares
- a fee or reserve that can be driven to a value where every subsequent
  operation underflows or divides by zero
- an initialisation that can be front-run into a state with no exit
- a `selfdestruct`-forced balance breaking a strict `balanceOf` equality

## 3. Unbounded iteration — the rarest, and the one most looked for

A loop over an array whose length an outsider can grow, in a function that must
succeed:

- `for (uint i; i < holders.length; i++)` where anyone can become a holder
- iterating all positions to compute a total, on the liquidation path
- a `delete` or a clear over an array with no cap on pushes

The test is not "the loop is long" — it is **who can lengthen it, and what
breaks when it no longer fits.** A loop over a fixed-size or owner-only array is
not an instance.

## What is not an instance

- "this loop costs a lot of gas" with no outsider able to grow it and nothing
  that must succeed
- a path whose only victim is the caller who chose it
- an owner able to pause their own protocol — that is the design unless the
  pause is unrecoverable
- a revert on invalid input

## What to cite

The loop header, the external call inside the loop, or the `require` an outsider
controls. The line whose behaviour a fix changes — not the function signature.
