---
name: unchecked-external-call
description: A call whose failure is discarded. The two shapes, and the one that has no observable symptom at the call site.
---

# Unchecked external call

An instance is **a call whose failure the caller does not observe, continuing as
though it succeeded.** Two shapes, and the second is easy to miss because the
code looks like it is checking.

## 1. A low-level call whose boolean is dropped

`address.call`, `.delegatecall`, `.staticcall`, and `.send` return a `bool` and
do **not** revert on failure:

    (bool ok, ) = target.call(data);       // `ok` never read
    target.call(data);                     // return value discarded entirely
    payable(to).send(amount);              // returns false, execution continues

The fix is `require(ok)` or a handled branch. `transfer` reverts by itself, so
it is not this class.

## 2. An interface call whose return value is a discardable bool

The one with no symptom at the call site:

    IERC20(token).transfer(to, amount);    // returns bool; some tokens return
                                           // false instead of reverting

`IERC20.transfer` and `transferFrom` are declared `returns (bool)`. A token that
returns `false` on failure — USDT's historical behaviour, and any token with a
blocklist — leaves the caller's accounting believing a transfer happened. The
call did not revert, no predicate at the call site can see it, and the loss
shows up later somewhere else. `SafeERC20`'s `safeTransfer` exists for exactly
this.

Related: `approve` returning false; a `swap` returning an amount that is
ignored; an `ecrecover` returning `address(0)` for a malformed signature and the
result compared against something without checking.

## Not an instance

- `transfer`/`transferFrom` on a **known** token that reverts (a specific,
  fixed, non-blocklisting token address set at construction)
- a `call` whose boolean **is** read, including in a `require` on the next line
  or a branch further down
- a deliberate best-effort call whose failure is handled — an event emitted, a
  fallback path taken. The comment saying so is not enough; the code has to do
  something.
- `delegatecall` in a proxy that bubbles the revert in assembly

## What to cite

The call statement. When the boolean is bound and then never used, cite the
binding — that is the line that shows the value was available and discarded.
