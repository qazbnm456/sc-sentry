"""Unchecked external call: a call whose failure the caller does not observe.

`candidates(parsed)` finds the sites and `priority(ref)` orders the functions that hold them. A
statement that calls something is not yet a candidate, because most statement calls return nothing
(`require`, `push`, a setter on a registry): a call is listed when it can return a status the
caller then drops. The strongest are the ones the language says return a flag, a low-level call
or a `send` whose boolean is never read, then a token `transfer`, `transferFrom` or `approve`
whose `bool` is dropped, then a function this unit declares with a `returns` clause. A call into
a contract this unit only imports is listed last, since nothing here says what it returns.
"""

from __future__ import annotations

import re

from sc_sentry.candidate import Candidate
from sc_sentry.candidates.citable import citable_site
from sc_sentry.solidity import Syntax
from sc_sentry.solidity.syntax import CallSite

# --- language and standard-library vocabulary; nothing here is taken from a codebase ----------

_RETURNS_NOTHING = frozenset(
    {"require", "assert", "revert", "selfdestruct", "suicide", "push", "pop"}
)
"""Built-ins and array members: a statement that calls one has no result to drop."""

_CHECKS_ITSELF = frozenset(
    {
        "sendValue", "functionCall", "functionCallWithValue", "functionStaticCall",
        "functionDelegateCall", "forceApprove", "safeTransferETH", "forceSafeTransferETH",
    }
)  # fmt: skip
"""Wrappers that revert on failure themselves, as every `safe*` member does."""

_TOKEN_FLAG = {"transfer": 2, "transferFrom": 3, "approve": 2}
"""ERC-20 members declared `returns (bool)` and the number of arguments each takes.

`transfer` with one argument is `address.transfer`, which reverts instead of returning a flag.
"""

_NOT_ERC20 = re.compile(r"721|1155", re.IGNORECASE)
"""A receiver naming an NFT standard: those `transferFrom` members return nothing."""

_CONVERSION = re.compile(r"\s*([A-Za-z_]\w*)\s*\(")
"""A receiver written as a type conversion, `IPool(addr)`: the type is named in the call."""

RANK_FLAG = 5.0
RANK_TOKEN = 4.0
RANK_DECLARED = 2.0
RANK_IMPORTED = 1.0
RANK_UNQUALIFIED = 0.5


def _flag_unread(parsed: Syntax, call: CallSite) -> bool:
    """Whether the flag a low-level call or `send` returns is dropped or bound and never read."""
    if not call.bound_names:
        return True
    line = parsed.lines[call.site.start_line - 1]
    if re.match(r"\s*\(\s*,", line.split("=")[0]):
        return True  # `(, bytes memory data) = x.call(...)` leaves out the flag
    declaration = parsed.callable_at(call.site.start_line)
    return declaration is not None and parsed.identifier_uses(declaration, call.bound_names[0]) <= 1


def _declared_returns(parsed: Syntax, call: CallSite) -> bool | None:
    """Whether the function this call reaches returns a value, when this unit declares it.

    A name alone is not enough for a call on a receiver: `pool.create()` reaches another contract's
    `create`, not a function of this unit that happens to share the name. So a receiver counts only
    when it names a type this unit declares, as `IPool(addr)` or `Library` do.
    """
    receiver = call.receiver
    if receiver is None or receiver in ("this", "super"):
        return parsed.returns_of(call.callee)
    named = _CONVERSION.match(receiver)
    inside = named.group(1) if named else receiver
    if parsed.index.declares_type(inside):
        return parsed.returns_of(call.callee, inside_type=inside)
    return None


def _shape(parsed: Syntax, call: CallSite) -> tuple[str, float] | None:
    """The predicate that lists this call and its rank, or None when the call drops nothing."""
    callee = call.callee
    flagging = call.is_low_level or (callee == "send" and len(call.arguments) == 1)
    if flagging:
        return ("flag_of_a_call_never_read", RANK_FLAG) if _flag_unread(parsed, call) else None
    if not call.is_bare_statement or call.bound_names:
        return None
    if callee in _RETURNS_NOTHING or callee in _CHECKS_ITSELF or callee.startswith("safe"):
        return None
    returns = _declared_returns(parsed, call)
    if returns is False:
        return None
    arity = _TOKEN_FLAG.get(callee)
    if (
        arity == len(call.arguments)
        and call.receiver is not None
        and not _NOT_ERC20.search(call.receiver)
    ):
        return ("token_bool_discarded", RANK_TOKEN)
    if callee in _TOKEN_FLAG and len(call.arguments) != arity:
        return None  # `address.transfer(amount)` reverts by itself
    if returns:
        return ("returned_value_discarded", RANK_DECLARED)
    if call.receiver is not None:
        return ("call_into_an_imported_contract_as_a_statement", RANK_IMPORTED)
    return ("call_as_a_statement", RANK_UNQUALIFIED)


def candidates(parsed: Syntax) -> list[Candidate]:
    out: list[Candidate] = []
    for call in parsed.calls:
        shape = _shape(parsed, call)
        if shape is None:
            continue
        predicate, rank = shape
        out.append(
            Candidate(
                predicate,
                citable_site(parsed, call.site),
                {"callee": call.callee or "", "rank": rank},
            )
        )
    return out


def priority(ref: Candidate) -> float:
    """How likely the call is to drop a failure, so the likeliest function comes first."""
    return float(ref.detail.get("rank", 0.0))
