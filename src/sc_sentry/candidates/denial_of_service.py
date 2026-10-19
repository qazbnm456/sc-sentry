"""Denial of service: a path an outsider can make permanently unusable for somebody else.

`candidates(parsed)` finds the sites and `priority(ref)` orders the functions that hold them. A
function is a candidate only if it holds a way to fail that somebody else can bring about: a loop
with no constant bound, a call into another contract, or a revert over a balance. A revert condition
on parameters or on this contract's own flags is not enough by itself.
"""

from __future__ import annotations

import math
import re
from collections import defaultdict
from typing import Any

from sc_sentry.candidate import Candidate
from sc_sentry.solidity import Site, Syntax
from sc_sentry.solidity.syntax import CallSite, GuardSite, LoopSite

# --- language and standard-library vocabulary; nothing here is taken from a codebase ----------

_NOT_A_CONTRACT = frozenset({"abi", "msg", "block", "tx", "type", "super", "string", "bytes"})
"""Receivers that are the language itself, so a call on them reaches no other contract."""

_NOT_A_CALL = frozenset(
    {
        "require", "assert", "revert", "keccak256", "sha256", "ripemd160", "ecrecover",
        "addmod", "mulmod", "selfdestruct", "push", "pop", "encode", "encodePacked",
        "encodeWithSelector", "encodeWithSignature", "encodeCall", "decode", "concat",
        "length", "payable", "address", "uint256", "uint", "bytes32",
    }
)  # fmt: skip
"""Built-in members and conversions: not an interaction with another contract."""

_ARITHMETIC_HELPERS = frozenset(
    {
        "add", "sub", "mul", "div", "mod", "min", "max", "abs", "sqrt", "mulDiv",
        "mulDivDown", "mulDivUp", "toUint256", "toUint128", "toUint64", "toUint32",
        "toUint8", "toInt256", "wmul", "wdiv", "rpow",
    }
)  # fmt: skip
"""Library members that compute on values and call out to nobody."""

_VALUE_MOVERS = frozenset(
    {
        "transfer", "send", "transferFrom", "safeTransfer", "safeTransferFrom",
        "sendValue", "safeTransferETH", "transferETH", "forceSafeTransferETH",
    }
)  # fmt: skip
"""Members that move value to a recipient, and fail the whole call when the recipient refuses."""

_TRANSFER_HELPERS = frozenset(
    {"safeTransfer", "safeTransferFrom", "safeTransferETH", "sendValue", "transferETH"}
)
"""What a contract calls its own wrapper around a transfer, with or without a leading underscore."""

_BALANCE = re.compile(r"\.balance\b|balanceOf\s*\(|totalSupply|totalAssets")
"""A quantity anyone can change by sending funds or minting, without calling this contract."""

_REVERTS = re.compile(r"\brevert\b|\bthrow\b")
_COUNTER = re.compile(r"for\s*\(\s*(?:[\w.\[\]]+\s+)?(?:memory\s+|storage\s+)?(\w+)\s*[=;]")
_CONSTANT = re.compile(r"[A-Z][A-Z0-9_]*")

# --- the ordering: one weight per structural feature, each with the sentence that defends it ---

FEATURES: dict[str, tuple[float, str]] = {
    "moves_value": (2.0, "A payment: a recipient that refuses it fails the whole call."),
    "loop_hazard": (2.0, "An external call in a loop, or a dynamic loop around external calls."),
    "balance_revert": (2.0, "A revert over a balance or supply that a donation can change."),
    "reachable": (1.0, "An outsider can invoke it and it changes state."),
    "storage_loop": (1.0, "A loop bounded by contract storage, which others' actions grow."),
    "unbounded_loop": (0.5, "A loop whose length is not a constant."),
    "external_calls": (0.25, "Per call into another contract, up to four: each can revert."),
    "size": (0.5, "log2 of the line count: more steps, more ways to fail."),
    "inert_read": (-2.0, "A view with no loop leaves nothing half done to be blocked."),
}


class _Facts:
    """What one function says about the ways it can be made to fail."""

    __slots__ = (
        "any_loop",
        "balance_revert",
        "call_in_loop",
        "external_calls",
        "kind",
        "lines",
        "moves_value",
        "reachable",
        "read_only",
        "storage_loop",
        "unbounded_loop",
    )

    def __init__(self) -> None:
        self.kind = "function"
        self.lines = 1
        self.read_only = False
        self.reachable = False
        self.external_calls = 0
        self.moves_value = False
        self.call_in_loop = False
        self.unbounded_loop = False
        self.storage_loop = False
        self.any_loop = False
        self.balance_revert = False

    @property
    def loop_hazard(self) -> bool:
        return self.call_in_loop or (self.unbounded_loop and self.external_calls > 0)

    def score(self) -> float:
        """The sum of the weights of the features this function has."""
        w = {name: weight for name, (weight, _) in FEATURES.items()}
        return (
            w["moves_value"] * self.moves_value
            + w["loop_hazard"] * self.loop_hazard
            + w["balance_revert"] * self.balance_revert
            + w["reachable"] * self.reachable
            + w["storage_loop"] * self.storage_loop
            + w["unbounded_loop"] * self.unbounded_loop
            + w["external_calls"] * min(self.external_calls, 4)
            + w["size"] * math.log2(max(self.lines, 1))
            + w["inert_read"] * (self.read_only and not self.any_loop)
        )


Key = tuple[str | None, str | None]


def _key(site: Site) -> Key:
    return (site.host.contract, site.host.function)


def _is_external_call(call: CallSite) -> bool:
    """A call into another contract or library, or into this contract's own transfer wrapper."""
    if call.callee in _NOT_A_CALL or call.callee in _ARITHMETIC_HELPERS:
        return False
    if call.receiver is None:
        return call.callee.lstrip("_") in _TRANSFER_HELPERS
    return re.split(r"[.\[(]", call.receiver.strip(), maxsplit=1)[0] not in _NOT_A_CONTRACT


def _moves_value(call: CallSite) -> bool:
    """A transfer, a payment or a low-level call: value leaves to a recipient that can refuse it."""
    return call.callee.lstrip("_") in _VALUE_MOVERS or call.callee == "call"


def _reverts(guard: GuardSite) -> bool:
    """A condition whose failing branch stops the call: a require, an assert or a reverting if."""
    text = guard.site.text
    return text.lstrip().startswith(("require", "assert")) or bool(_REVERTS.search(text))


def _dynamic(loop: LoopSite) -> bool:
    """A loop bounded by something other than a literal or an upper-case constant."""
    match = _COUNTER.match(loop.site.text.lstrip())
    counter = match.group(1) if match else None
    return any(i != counter and not _CONSTANT.fullmatch(i) for i in loop.bound_identifiers)


def _facts(parsed: Syntax) -> dict[Key, _Facts]:
    facts: dict[Key, _Facts] = defaultdict(_Facts)
    for fn in parsed.functions:
        f = facts[_key(fn.site)]
        f.kind = fn.declaration.kind.value
        f.lines = max(f.lines, fn.site.end_line - fn.site.start_line + 1)
        f.read_only = f.read_only or fn.is_read_only
        f.reachable = f.reachable or (fn.is_externally_reachable and not fn.is_read_only)
    spans = [(ls.site.start_line, ls.site.end_line) for ls in parsed.loops]
    for ls in parsed.loops:
        f = facts[_key(ls.site)]
        f.any_loop = True
        f.unbounded_loop = f.unbounded_loop or _dynamic(ls)
        f.storage_loop = f.storage_loop or bool(set(ls.bound_identifiers) & parsed.state_variables)
    for call in parsed.calls:
        if not _is_external_call(call):
            continue
        f = facts[_key(call.site)]
        f.external_calls += 1
        f.moves_value = f.moves_value or _moves_value(call)
        f.call_in_loop = f.call_in_loop or any(a <= call.site.start_line <= b for a, b in spans)
    for guard in parsed.guards:
        if _reverts(guard) and _BALANCE.search(guard.site.text.split("{")[0]):
            facts[_key(guard.site)].balance_revert = True
    return facts


def _eligible(f: _Facts) -> bool:
    """A function (not a constructor or modifier) with a way to fail that others can bring about."""
    if f.kind in ("constructor", "modifier"):
        return False
    return f.unbounded_loop or f.external_calls > 0 or f.balance_revert


PREDICATES = {
    "unbounded_loop": "A loop whose length is not a constant, so it can outgrow what a call pays.",
    "external_call_inside_a_loop": "A call into another contract in a loop: one refusal fails all.",
    "value_moving_call": "A transfer or payment whose recipient can refuse it and fail the call.",
    "external_call": "A call into another contract, whose revert fails this function.",
    "revert_condition": "A condition that reverts the call, in a function with a way to fail.",
}
_CITATION_RANK = {
    "external_call_inside_a_loop": 5,
    "unbounded_loop": 4,
    "value_moving_call": 3,
    "external_call": 2,
    "revert_condition": 1,
}
"""Which site stands for a function when it is cited: a call in a loop first, a bare revert last."""


def candidates(parsed: Syntax) -> list[Candidate]:
    facts = _facts(parsed)
    spans = [(ls.site.start_line, ls.site.end_line) for ls in parsed.loops]
    out: list[Candidate] = []

    def add(predicate: str, site: Site, **detail: str | int | float | bool) -> None:
        f = facts.get(_key(site))
        if f is None or not _eligible(f):
            return
        detail.update(score=round(f.score(), 4), rank=_CITATION_RANK[predicate])
        out.append(Candidate(predicate, site, detail))

    for ls in parsed.loops:
        if _dynamic(ls):
            add("unbounded_loop", ls.site, bound_on=",".join(ls.bound_identifiers or ()))
    for call in parsed.calls:
        if not _is_external_call(call):
            continue
        if any(a <= call.site.start_line <= b for a, b in spans):
            add("external_call_inside_a_loop", call.site, callee=call.callee)
        elif _moves_value(call):
            add("value_moving_call", call.site, callee=call.callee)
        else:
            add("external_call", call.site, callee=call.callee)
    for guard in parsed.guards:
        if _reverts(guard):
            add("revert_condition", guard.site)
    out.sort(key=lambda c: (c.site.start_line, c.site.start_byte))
    return out


def priority(ref: Any) -> float:
    """The function's score, so the likeliest to be blocked comes first; the rank picks its site."""
    return float(ref.detail.get("score", 0.0)) * 100 + float(ref.detail.get("rank", 0))
