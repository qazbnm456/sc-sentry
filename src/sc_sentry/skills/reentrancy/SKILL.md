---
name: reentrancy
description: State read or written across an external call that can call back. The ordering that matters, and why a guard elsewhere does not help.
---

# Reentrancy

An instance is **an external call that can return control to an untrusted
party, with state that the contract still depends on left inconsistent across
it.** The shape:

1. a call out whose destination is attacker-influenced — `.call`, `.send`,
   `.transfer` to an arbitrary address, an ERC-20 whose token address is
   user-supplied, an ERC-721 `safeTransferFrom` (the `onERC721Received` hook), a
   callback interface the caller implements
2. a **state write after it**, or a state read before it whose value the
   callback can change

Checks-effects-interactions is the rule: the write that protects an invariant
must land before the call, not after.

## The idioms that are instances

- `withdraw`: `balances[msg.sender]` read, ether sent, balance zeroed **after**
- an ERC-721 mint that increments a counter after `_safeMint`
- an ERC-777 / fee-on-transfer token where `transfer` itself calls back
- a loop that pays several recipients and updates a total after the loop
- cross-function: `f()` sends out, `g()` reads the state `f()` has not yet
  updated. Both are externally reachable and the callback calls `g()`.
- read-only reentrancy: a view an integrator trusts (`getPrice`,
  `totalAssets`) returns a stale value **during** a callback

## What does not make it safe

- a `nonReentrant` modifier on **another** function. It has to be on this path.
- a comment saying the token is trusted. If the token address is settable or
  user-supplied, it is not.
- the call being last in the *source* order but not last in *execution* order
  (a modifier body running after, an implicit transfer in a helper).

## Not an instance

- the destination is a fixed, known-good address set at construction and not
  changeable
- nothing is read or written across the call — the call is genuinely the last
  effect
- the "call" is a `staticcall` or a pure view on a contract that cannot call back
- a `transfer`/`send` with a 2300-gas stipend **and** no state depending on it
  afterwards

## What to cite

The external call and the state write together when they are adjacent; the
state write alone when they are far apart, because that is the line that has to
move.
