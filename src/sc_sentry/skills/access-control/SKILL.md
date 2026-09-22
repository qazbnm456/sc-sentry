---
name: access-control
description: Missing or wrong authorisation on a state-changing path. What must be true, the idioms, and the four things that look like it and are not.
---

# Access control

An instance is a **state-changing path reachable by an account that should not
be able to take it**. Two halves, and both must hold at the cited location:

1. the function is externally reachable (`external`/`public`, or reachable
   through one that is), and
2. nothing on the path establishes the caller's right to take it.

## Where the guard can be, and still count

A guard does not have to be an inline `require`. Any of these establishes the
caller and means **no instance**:

- a modifier: `onlyOwner`, `onlyRole(...)`, `onlyGovernance`, `auth`, `restricted`
- an inline check: `require(msg.sender == owner)`, `if (msg.sender != x) revert`
- a delegated check: `_checkOwner()`, `_authorizeUpgrade()`, `AccessControl`'s
  `_checkRole`
- a state machine that only the owner can advance into

Read the **whole** function body and its modifier list before concluding
nothing guards it.

## The idioms that are instances

- an initialiser with no `initializer`/`initialized` guard — callable twice, and
  the second caller takes ownership
- a setter for a privileged address (`setOwner`, `setOracle`, `setFeeTo`,
  `setImplementation`) with no caller check
- a `_mint`/`_burn` wrapper made `public` with no check
- an emergency path (`pause`, `sweep`, `rescueTokens`) with no check
- a check on the **wrong** principal: `require(msg.sender == someUser)` where
  the authority is `owner`, or a check against a value the caller supplies
- `tx.origin` used as the principal — phishable, and a check that does not
  establish who called

## Four things that look like it and are not

- **`internal` or `private` with no external caller.** Not reachable, so no
  path. Check `callers_of` before claiming one.
- **A constructor.** It runs once, at deployment, from the deployer.
- **A permissionless-by-design function.** `deposit`, `swap`, `claim` for the
  caller's own position. The absence of a check is the design; the question is
  whether it writes state belonging to *somebody else*.
- **A view function.** No state change, so nothing to authorise. `is_read_only`
  settles it.

## What to cite

The line that writes the state, or the function's signature line if the whole
function is the defect. Not the modifier list, and not the contract declaration.
