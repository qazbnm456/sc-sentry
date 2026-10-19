"""Reentrancy: control leaves the contract while the state it depends on is not yet settled.

A function is a candidate when it hands control to code it does not control (a low-level call, a
payment, a token transfer or mint whose receiver has a hook, a call on an address or interface the
caller chose, or a call to an internal function of the file that does one of those) and, for the
weaker kinds of hand-off, leaves the contract unsettled while it does: state is written after the
hand-off, or a balance is read before it and again after it. A view or pure function holds none,
because its external calls are static. Calls are read as the language and the standard token
interfaces spell them (call, send, safeTransferFrom, _safeMint), never by a project's own names. A
candidate is cited at whole lines that could be quoted (six tokens, one naming something of the
file's own), widened inside its function if it must be.

Predicates (the two that the class's `rejects` knows; the kind of hand-off is in `detail["kind"]`)
  external_call                       control leaves the function: to an external address or
                                      receiver, or through an internal call that does
  state_write_after_an_external_call  a write to contract state, or through a storage pointer, that
                                      follows such a hand-off in the function

Ordering features of `priority` (the strength of the hand-off plus the bonuses, then times the
factors)
  strength          how directly outside code runs: 5 value call or ether helper; 4 hook transfer,
                    low-level call, caller-chosen callee; 3 token or ether transfer; 2 other; 1
                    allowance
  write_after       state is written after the hand-off, so checks-effects-interactions is broken
  consulted_written the state written after is state the function read in a condition or an argument
                    before the hand-off
  balance_span      a balance or supply is read before the hand-off and again after it
  extra_handoffs    further hand-offs of strength 3 or more in the same function
  internal_only     the function cannot be entered from outside (internal or private)
  guarded           a reentrancy lock on the function, on one of its modifiers, or on every caller
                    of an internal function
  guard_elsewhere   the file locks other functions but leaves this one unlocked
  indirect          the hand-off is in an internal function this one calls, not in its own body
"""

from __future__ import annotations

import re
from dataclasses import replace
from typing import NamedTuple, TypedDict

from sc_sentry.candidate import Candidate
from sc_sentry.solidity.syntax import CallSite, Site, Syntax

# ---------------------------------------------------------------------------------------------
# Vocabulary of the language and of its standard token interfaces, not of any one codebase.

_NOT_A_CONTRACT = frozenset(
    {"abi", "block", "type", "super", "string", "bytes", "console", "console2"}
)
"""Receivers that are the language itself, so a call on them reaches no other contract."""

_NOT_A_CALL = frozenset(
    {
        "require",
        "assert",
        "revert",
        "keccak256",
        "sha256",
        "ripemd160",
        "ecrecover",
        "addmod",
        "mulmod",
        "selfdestruct",
        "push",
        "pop",
        "encode",
        "encodePacked",
        "encodeWithSelector",
        "encodeWithSignature",
        "encodeCall",
        "decode",
        "concat",
        "length",
        "payable",
        "address",
        "uint256",
        "uint",
        "bytes32",
        "bytes4",
        "bytes",
        "string",
        "int256",
        "uint8",
        "uint16",
        "uint32",
        "uint64",
        "uint96",
        "uint128",
        "uint160",
        "blockhash",
        "gasleft",
        "this",
        "new",
    }
)
"""Built-in members and conversions: they hand control to no one."""

_ARITHMETIC = frozenset(
    {
        "add",
        "sub",
        "mul",
        "div",
        "mod",
        "min",
        "max",
        "abs",
        "sqrt",
        "mulDiv",
        "mulDivDown",
        "mulDivUp",
        "toUint256",
        "toUint128",
        "toUint64",
        "toUint32",
        "toUint8",
        "toInt256",
        "wmul",
        "wdiv",
        "rpow",
        "pow",
        "ceilDiv",
        "wadMul",
        "wadDiv",
        "rayMul",
        "rayDiv",
        "fullMulDiv",
        "tryAdd",
        "trySub",
        "tryMul",
        "tryDiv",
        "average",
        "log2",
        "log10",
        "log256",
        # the standard collection and counter helpers, which only touch the caller's own storage
        "remove",
        "contains",
        "at",
        "values",
        "increment",
        "decrement",
        "tryGet",
        "unsafeAccess",
    }
)
"""Library members that compute on values or keep a collection: they hand control to no one."""

_ETHER_HELPERS = frozenset(
    {
        "sendValue",
        "safeTransferETH",
        "transferETH",
        "forceSafeTransferETH",
        "safeTransferNative",
        "transferNative",
        "sendETH",
        "sendEth",
        "forwardETH",
        "functionCallWithValue",
    }
)
"""Helpers that send ether with the gas to run the receiver's code."""

_CALL_HELPERS = frozenset({"functionCall", "functionDelegateCall", "functionStaticCall"})
"""Helpers that wrap a low-level call to an address."""

_HOOK_TRANSFERS = frozenset(
    {
        "safeTransferFrom",
        "safeBatchTransferFrom",
        "safeMint",
        "operatorSend",
        "transferAndCall",
        "transferFromAndCall",
        "approveAndCall",
        "send",
    }
)
"""Token operations, called on a token, that run a hook on the receiving contract (ERC721, ERC1155,
ERC777, ERC1363)."""

_INHERITED_HOOKS = frozenset(
    {
        "_safeMint",
        "_safeTransfer",
        "_safeTransferFrom",
        "_safeBatchTransferFrom",
        "_mintBatch",
        "_doSafeTransferAcceptanceCheck",
        "_checkOnERC721Received",
        "_checkOnERC1155Received",
    }
)
"""The same operations as the token bases spell them, called unqualified from a contract that
inherits them."""

_TOKEN_TRANSFERS = frozenset({"transfer", "transferFrom", "safeTransfer"})
"""Fungible-token movements: the token or the receiver may run a hook (ERC777 and callback
tokens)."""

_CALLBACK_WORDS = frozenset({"flash", "callback", "hook", "multicall", "onerc"})
"""Words of a callee that names an interaction in which the callee calls back into its caller."""

_ALLOWANCES = frozenset(
    {
        "approve",
        "safeApprove",
        "forceApprove",
        "increaseAllowance",
        "decreaseAllowance",
        "safeIncreaseAllowance",
        "safeDecreaseAllowance",
        "permit",
    }
)
"""Calls that change what a spender may take but hand nothing over."""

_EFFECT_WORDS = frozenset(
    {
        "transfer",
        "send",
        "mint",
        "burn",
        "deposit",
        "withdraw",
        "redeem",
        "claim",
        "swap",
        "stake",
        "unstake",
        "supply",
        "borrow",
        "repay",
        "liquidate",
        "harvest",
        "execute",
        "call",
        "create",
        "add",
        "remove",
        "set",
        "update",
        "initialize",
        "init",
        "register",
        "settle",
        "close",
        "open",
        "cancel",
        "fill",
        "bid",
        "buy",
        "sell",
        "lock",
        "unlock",
        "release",
        "sync",
        "skim",
        "collect",
        "increase",
        "decrease",
        "pay",
        "fund",
        "wrap",
        "unwrap",
        "exit",
        "join",
        "enter",
        "leave",
        "accrue",
        "rebalance",
        "notify",
        "distribute",
        "flash",
        "delegate",
        "vote",
        "propose",
        "queue",
        "process",
        "handle",
        "receive",
        "on",
        "bridge",
        "relay",
        "submit",
        "finalize",
        "complete",
        "reset",
        "rescue",
        "sweep",
        "push",
        "pull",
        "take",
        "invest",
        "reinvest",
        "compound",
        "restake",
        "slash",
        "trigger",
        "run",
        "perform",
        "apply",
        "start",
        "stop",
        "pause",
        "unpause",
        "kill",
        "migrate",
        "upgrade",
        "mark",
        "record",
        "report",
        "checkpoint",
        "poke",
        "refresh",
        "reconcile",
        "trade",
        "place",
        "approve",
    }
)
"""First words of a callee that changes state. A call whose result is used and that does not start
with one is a read."""

_STATE_MUTATORS = frozenset(
    {
        "_burn",
        "_mint",
        "_transfer",
        "_approve",
        "_spendAllowance",
        "_update",
        "_setApprovalForAll",
        "_safeMint",
        "_mintBatch",
        "_burnBatch",
        "_transferOwnership",
        "_grantRole",
        "_revokeRole",
        "_setOwner",
    }
)
"""Unqualified calls to the standard token and ownership bases that write the contract's own
storage."""

_BALANCE_CALLS = frozenset({"balanceOf", "totalSupply", "totalAssets", "getBalance"})
"""Reads of a quantity that a callback can change by moving funds."""

_YUL_CALL = re.compile(
    r"\b(call|delegatecall|callcode)\s*\(\s*([^,()]*(?:\([^()]*\))?[^,()]*),\s*[^,()]+,\s*([^,()]+),"
)
"""A call opcode inside an inline assembly block: the target, then (for `call`) the value, as the
opcode takes them."""

_STORAGE_POINTER = re.compile(r"\bstorage\s+([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)")
_DELETE = re.compile(r"\bdelete\s+([A-Za-z_]\w*)")
_STEP = re.compile(
    r"(?:\+\+|--)\s*([A-Za-z_]\w*)|\b([A-Za-z_]\w*)(?:\s*\[[^\]\n]*\]|\s*\.\s*\w+)*\s*(?:\+\+|--)"
)
_PUSH_POP = re.compile(r"\b([A-Za-z_]\w*)(?:\s*\[[^\]\n]*\]|\s*\.\s*\w+)*\s*\.\s*(?:push|pop)\s*\(")
_IDENT = re.compile(r"[A-Za-z_]\w*")
_TOKEN = re.compile(r"[A-Za-z_][A-Za-z_0-9]*|\d+|[^\sA-Za-z_0-9]")
_LANGUAGE = frozenset(
    {
        "function", "returns", "return", "if", "else", "for", "while", "do", "break", "continue",
        "require", "assert", "revert", "emit", "new", "delete", "public", "external", "internal",
        "private", "view", "pure", "payable", "virtual", "override", "constant", "immutable",
        "memory", "storage", "calldata", "unchecked", "try", "catch", "is", "using", "mapping",
        "struct", "enum", "event", "error", "modifier", "constructor", "contract", "interface",
        "library", "import", "pragma", "true", "false", "this", "super", "msg", "block", "tx",
        "abi", "sender", "value", "timestamp", "number", "address", "bool", "string", "bytes",
        "uint", "int", "uint8", "uint16", "uint32", "uint64", "uint128", "uint256", "int8", "int16",
        "int32", "int64", "int128", "int256", "bytes4", "bytes32", "length", "push", "pop",
        "encode", "encodePacked", "decode", "i", "j", "k",
    }
)  # fmt: skip

# The ordering of the functions that hold candidates. The score is the strength of the hand-off (how
# directly code the contract does not control gets to run, 1 to 5, assigned in `_handoff_of`) plus
# what shows the state is unsettled when it does, then scaled by how reachable the function is and
# whether a lock stands in the way. A rung of strength is one unit, so unsettled state can outweigh
# one or two rungs and not more. All set by hand.
WEIGHTS = {
    # state is written after the hand-off: checks-effects-interactions is broken
    "write_after": 1.5,
    "consulted_written": 1.0,  # ... and it is state the function consulted before the hand-off
    "balance_span": 1.0,  # a balance is read before a hand-off and again after it
    "extra_handoffs": 0.25,  # per further hand-off of strength 3 or more, up to three
    "internal_only": 0.8,  # factor: the language keeps an outside caller out of the function
    "guarded": 0.1,  # factor: a reentrancy lock on the function or one of its modifiers
    "guard_elsewhere": 1.15,  # factor: the file locks other functions but not this one
    "indirect": 0.85,  # factor: the hand-off is in an internal function this one calls
}

# ---------------------------------------------------------------------------------------------


class _Handoff(NamedTuple):
    """A place where control leaves the function."""

    start: int
    end: int
    strength: int  # 1 allowance change ... 5 value call
    kind: str
    site: Site


class _Fn:
    """One function-like declaration and what its body says about hand-offs and state."""

    def __init__(
        self,
        site: Site,
        kind: str,
        name: str,
        reachable: bool,
        read_only: bool,
        params: frozenset[str],
    ) -> None:
        self.site = site
        self.kind = kind
        self.name = name
        self.reachable = reachable
        self.read_only = read_only
        self.params = params
        self.locked = False
        self.handoffs: list[_Handoff] = []
        self.internal_calls: list[tuple[Site, str]] = []  # (site, callee)
        self.writes: list[tuple[int, int, str, Site]] = []  # (start, end, root, site)
        self.balances: list[int] = []  # start byte of each balance read
        self.guards: list[tuple[int, set[str]]] = []  # (start, identifiers)
        self.aliases: dict[str, str] = {}  # storage pointer -> the state variable it points into


def _words(name: str) -> list[str]:
    spaced = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name))
    return [w.lower() for w in re.split(r"[^A-Za-z0-9]+", spaced) if w]


def _citable(text: str) -> bool:
    """Whether whole lines of this text could be cited: six tokens, one naming something of the
    file's own."""
    tokens = _TOKEN.findall(text)
    return len(tokens) >= 6 and any(
        (t[0].isalpha() or t[0] == "_") and t not in _LANGUAGE for t in tokens
    )


def _header(f: _Fn) -> Site:
    """The declaration line(s) of a function, up to its opening brace: a citation, not a whole
    body."""
    site = f.site
    head = site.text.split("{", 1)[0]
    return replace(
        site, end_line=site.start_line + head.count("\n"), text=head, start_byte=-1, end_byte=-1
    )


def _span(f: _Fn, site: Site) -> Site:
    """`site`, widened by whole lines inside its function until it is citable; the declaration if
    nothing else is."""
    rows = f.site.text.split("\n")
    base = f.site.start_line
    lo, hi = site.start_line, site.end_line
    for _ in range(3):
        text = "\n".join(rows[lo - base : hi - base + 1])
        if _citable(text):
            if (lo, hi) == (site.start_line, site.end_line):
                return site
            return replace(site, start_line=lo, end_line=hi, text=text, start_byte=-1, end_byte=-1)
        if lo > base + 1:
            lo -= 1
        elif hi < f.site.end_line:
            hi += 1
    return _header(f)


def _address_params(site: Site) -> frozenset[str]:
    """Parameters that name a callee the caller chose: an address or a contract type, not a struct
    or array in memory."""
    head = site.text.split("{", 1)[0]
    start = head.find("(")
    if start < 0:
        return frozenset()
    depth, end = 0, len(head)
    for i in range(start, len(head)):
        depth += head[i] == "("
        depth -= head[i] == ")"
        if depth == 0:
            end = i
            break
    found: set[str] = set()
    for part in head[start + 1 : end].split(","):
        words = part.split()
        if len(words) >= 2 and not {"memory", "calldata", "storage"} & set(words):
            kind = " ".join(words[:-1])
            if kind in ("address", "address payable") or kind[:1].isupper():
                found.add(words[-1])
    return frozenset(found)


def _root(text: str | None) -> str:
    """The identifier an expression starts from: `a.b[c].d` starts at `a`, `IFoo(a).b` at `IFoo`."""
    m = _IDENT.search(text or "")
    return m.group(0) if m else ""


def _handoff_of(call: CallSite, fn: _Fn, declared: frozenset[str]) -> tuple[int, str] | None:
    """The strength (1 to 5) and kind of the hand-off a call makes, or None when it hands control to
    no one."""
    callee, receiver = call.callee, call.receiver
    if callee in _NOT_A_CALL or callee in _ARITHMETIC or call.site.text.lstrip().startswith("new "):
        return None
    if receiver is None:
        if callee in declared:
            return None
        if callee in _INHERITED_HOOKS or (callee == "_mint" and len(call.arguments) >= 4):
            # `_mint(to, id, amount, data)` is the ERC1155 and ERC777 mint, which asks the receiver
            return 4, "token_hook_transfer"
        if callee in _ETHER_HELPERS:
            return 5, "ether_helper"
        return None
    if _root(receiver) in _NOT_A_CONTRACT or receiver.strip() in ("this", "super"):
        return None
    if callee == "value" and receiver.rstrip().endswith(
        ".call"
    ):  # the old spelling, `.call.value(x)(data)`
        return 5, "value_call"
    if callee == "call":
        carries_value = (
            call.has_call_options and re.search(r"\bvalue\s*:", call.site.text) is not None
        )
        return (5, "value_call") if carries_value else (4, "low_level_call")
    if callee == "delegatecall" or callee in _CALL_HELPERS:
        return 4, "low_level_call"
    if callee in ("staticcall", "gas"):
        return None
    if callee in _ETHER_HELPERS:
        return 5, "ether_helper"
    if callee in ("transfer", "send") and len(call.arguments) == 1:
        return 3, "ether_transfer"
    if callee in _HOOK_TRANSFERS:
        return 4, "token_hook_transfer"
    if callee in ("_mint", "mint") and len(call.arguments) >= 4:
        return 4, "token_hook_transfer"
    if callee in _TOKEN_TRANSFERS:
        return 3, "token_transfer"
    if callee in _ALLOWANCES:
        return 1, "allowance_change"
    words = _words(callee)
    if not call.is_bare_statement and (
        not call.arguments or not (words and words[0] in _EFFECT_WORDS)
    ):
        # its result is used and its name is no verb of change: a read, which code can re-enter
        # through but never into
        return None
    if re.fullmatch(r"[A-Z]\w*", receiver.strip()):
        # a static call on a library or a contract's own name: code that runs inside this contract
        return None
    if (
        set(_IDENT.findall(receiver)) & fn.params
        or "msg.sender" in receiver
        or "tx.origin" in receiver
    ):
        return 4, "call_on_supplied_address"
    if any(w in _CALLBACK_WORDS for w in words):
        return 4, "callback_call"
    return 2, "external_call"


def _assigned(text: str) -> set[str]:
    """Names assigned with `=` in a stretch of code."""
    return {m.group(1) for m in re.finditer(r"\b([A-Za-z_]\w*)\s*=[^=]", text)}


def _locking_modifiers(parsed: Syntax) -> set[str]:
    """Modifiers of the file that write a state flag before the body and write it again after: a
    reentrancy lock."""
    state = parsed.state_variables
    found: set[str] = set()
    for f in parsed.functions:
        if f.declaration.kind.value != "modifier":
            continue
        head, sep, tail = f.site.text.partition("_;")
        if sep and _assigned(head.split("{", 1)[-1]) & _assigned(tail) & state:
            found.add(f.declaration.names[0])
    return found


def _locks_inline(text: str, state: frozenset[str]) -> bool:
    """A body that raises a state flag and lowers it again, or calls a lock's own entry and exit."""
    if re.search(r"\b_?nonReentrant(Before|After)\s*\(", text):
        return True
    flags = [
        m.group(1)
        for m in re.finditer(r"\b([A-Za-z_]\w*)\s*=\s*(?:true|false|[0-2])\b", text)
        if m.group(1) in state
    ]
    return len(flags) != len(set(flags))


def _statement(fn: _Fn, text: str, start_char: int, end_char: int) -> Site:
    """A site for a stretch of a function's text, found by regular expression where the parser has
    no node for it."""
    body, base = fn.site.text, fn.site.start_byte
    return replace(
        fn.site,
        node_type="statement",
        text=text,
        start_line=fn.site.start_line + body[:start_char].count("\n"),
        end_line=fn.site.start_line + body[:end_char].count("\n"),
        start_byte=base + len(body[:start_char].encode("utf-8")),
        end_byte=base + len(body[:end_char].encode("utf-8")),
    )


def _assembly_handoffs(fn: _Fn) -> None:
    """Call opcodes in the function's inline assembly blocks, which the parser does not read as
    calls."""
    text = fn.site.text
    for block in re.finditer(r"\bassembly\b[^{]*\{", text):
        depth, i = 1, block.end()
        while i < len(text) and depth:
            depth += (text[i] == "{") - (text[i] == "}")
            i += 1
        for m in _YUL_CALL.finditer(text[block.end() : i]):
            moves_value = m.group(1) == "call" and m.group(3).strip() not in ("0", "0x0")
            site = _statement(fn, m.group(0), block.end() + m.start(), block.end() + m.end())
            fn.handoffs.append(
                _Handoff(
                    site.start_byte,
                    site.end_byte,
                    5 if moves_value else 4,
                    "value_call" if moves_value else "low_level_call",
                    site,
                )
            )


def _statement_writes(fn: _Fn, state: frozenset[str]) -> None:
    """Writes the parser has no assignment for: delete, increment and decrement, push and pop on
    state."""
    roots = set(state) | set(fn.aliases)
    for pattern in (_DELETE, _PUSH_POP, _STEP):
        for m in pattern.finditer(fn.site.text):
            name = next(g for g in m.groups() if g)
            if name in roots:
                site = _statement(fn, m.group(0), m.start(), m.end())
                fn.writes.append((site.start_byte, site.end_byte, fn.aliases.get(name, name), site))


def _functions(parsed: Syntax) -> list[_Fn]:
    """Every function-like declaration of the unit with its hand-offs, writes, balance reads, guards
    and locks."""
    state = parsed.state_variables
    locks = _locking_modifiers(parsed)
    declared = frozenset(
        f.declaration.names[0] for f in parsed.functions if f.declaration.kind.value == "function"
    )
    libraries = {d.names[0] for d in parsed.index.declarations if d.kind.value == "library"}
    fns: list[_Fn] = []
    fn: _Fn | None
    for f in parsed.functions:
        fn = _Fn(
            site=f.site,
            kind=f.declaration.kind.value,
            name=f.declaration.names[0],
            reachable=f.is_externally_reachable,
            read_only=f.is_read_only,
            params=_address_params(f.site),
        )
        mods = {_root(m) for m in f.modifiers}
        fn.locked = (
            bool(mods & locks)
            or any("reentr" in m.lower() for m in mods)
            or _locks_inline(f.site.text, state)
        )
        fn.aliases = {a: r if r in state else a for a, r in _STORAGE_POINTER.findall(f.site.text)}
        fns.append(fn)
    by_start = sorted(fns, key=lambda fn: (fn.site.start_byte, -fn.site.end_byte))

    def owner(site: Site) -> _Fn | None:
        """The innermost function whose text holds the site, or None."""
        best: _Fn | None = None
        for fn in by_start:
            if fn.site.start_byte > site.start_byte:
                break
            if site.start_byte < fn.site.end_byte and (
                best is None or fn.site.end_byte <= best.site.end_byte
            ):
                best = fn
        return best

    for c in parsed.calls:
        fn = owner(c.site)
        if fn is None or fn.kind in ("modifier", "constructor") or fn.read_only:
            continue
        own = (
            c.receiver is None or c.receiver.strip() in libraries
        )  # the file's own code, by name or by its library
        if own and (c.callee in declared or (c.receiver is None and c.callee in _STATE_MUTATORS)):
            fn.internal_calls.append((c.site, c.callee))
            if c.callee in declared:
                continue
        hit = _handoff_of(c, fn, declared)
        if hit is not None:
            fn.handoffs.append(_Handoff(c.site.start_byte, c.site.end_byte, hit[0], hit[1], c.site))
        if c.callee in _BALANCE_CALLS and c.receiver is not None:
            fn.balances.append(c.site.start_byte)
    for site, _object, member in parsed.member_reads:
        fn = owner(site)
        if member == "balance" and fn is not None:
            fn.balances.append(site.start_byte)
    for g in parsed.guards:
        fn = owner(g.site)
        if fn is not None:
            fn.guards.append((g.site.start_byte, set(g.identifiers)))
    for w in parsed.writes:
        fn = owner(w.site)
        if fn is not None and (w.writes_state or w.target_root in fn.aliases):
            fn.writes.append(
                (
                    w.site.start_byte,
                    w.site.end_byte,
                    fn.aliases.get(w.target_root, w.target_root),
                    w.site,
                )
            )
    for fn in fns:
        if not fn.read_only and fn.kind not in ("modifier", "constructor"):
            if "assembly" in fn.site.text:
                _assembly_handoffs(fn)
            _statement_writes(fn, state)
    return fns


def _propagate_locks(fns: list[_Fn]) -> None:
    """An internal function every caller of which holds a reentrancy lock is entered under that
    lock."""
    callers: dict[str, list[_Fn]] = {}
    for fn in fns:
        for _site, callee in fn.internal_calls:
            if callee != fn.name:
                callers.setdefault(callee, []).append(fn)
    for _ in range(3):
        for fn in fns:
            above = callers.get(fn.name)
            if (
                fn.kind == "function"
                and not fn.reachable
                and not fn.locked
                and above
                and all(c.locked for c in above)
            ):
                fn.locked = True


def _link_internal_writes(fns: list[_Fn]) -> None:
    """A call to an internal function that writes state, or to a standard token base's mutator, is a
    write too."""
    writes = {fn.name for fn in fns if fn.kind == "function" and fn.writes}
    for _ in range(2):
        for fn in fns:
            if fn.kind == "function" and any(callee in writes for _s, callee in fn.internal_calls):
                writes.add(fn.name)
    for fn in fns:
        for site, callee in fn.internal_calls:
            if callee in writes or callee in _STATE_MUTATORS:
                fn.writes.append((site.start_byte, site.end_byte, callee + "()", site))


def _link_internal_calls(fns: list[_Fn]) -> None:
    """A call to an internal function that hands control away is itself a hand-off, through the
    file's own calls."""
    reach: dict[str, int] = {}
    for fn in fns:
        if fn.kind == "function" and fn.handoffs:
            reach[fn.name] = max(reach.get(fn.name, 0), max(h.strength for h in fn.handoffs))
    reach = {name: r for name, r in reach.items() if r >= 3}
    for _ in range(3):
        for fn in fns:
            if fn.kind != "function":
                continue
            for _site, callee in fn.internal_calls:
                if callee != fn.name and reach.get(callee, 0) > reach.get(fn.name, 0):
                    reach[fn.name] = reach[callee]
    for fn in fns:
        for site, callee in fn.internal_calls:
            if callee != fn.name and reach.get(callee, 0) >= 3:
                fn.handoffs.append(
                    _Handoff(site.start_byte, site.end_byte, reach[callee], "internal_call", site)
                )


class _Facts(TypedDict):
    top: int
    direct: bool
    extra: int
    after: list[tuple[int, int, str, Site]]
    consulted: bool
    balance_span: bool


def _facts(fn: _Fn) -> _Facts:
    """The structural facts of one function that the ordering reads."""
    hand = sorted(fn.handoffs, key=lambda h: h.start)
    top = max((h.strength for h in hand), default=0)
    anchor = next(
        (h for h in hand if h.strength >= min(top, 3)), None
    )  # the first hand-off that matters
    after: list[tuple[int, int, str, Site]] = []
    consulted = spans_balance = False
    if anchor is not None:
        after = sorted(
            (
                w
                for w in fn.writes
                if w[0] >= anchor.end or (w[0] < anchor.start and w[1] >= anchor.end)
            ),
            key=lambda w: w[0],
        )
        seen: set[str] = set()
        for start, ids in fn.guards:
            if start < anchor.start:
                seen |= {fn.aliases.get(i, i) for i in ids}
        seen |= {fn.aliases.get(i, i) for i in _IDENT.findall(anchor.site.text)}
        consulted = any(w[2] in seen for w in after)
        spans_balance = any(b < anchor.start for b in fn.balances) and any(
            b > anchor.start for b in fn.balances
        )
    return {
        "top": top,
        "direct": any(h.kind != "internal_call" for h in hand),
        "extra": max(sum(1 for h in hand if h.strength >= 3) - 1, 0),
        "after": after,
        "consulted": consulted,
        "balance_span": spans_balance,
    }


def _eligible(f: _Facts) -> bool:
    """A hand-off to a receiver with a hook or an untrusted address, or any other state-changing
    call that leaves state unsettled."""
    return f["top"] >= 3 or (f["top"] >= 1 and bool(f["after"] or f["balance_span"]))


def _score(fn: _Fn, f: _Facts, lock_elsewhere: bool) -> float:
    """The function's ordering score (higher is listed first)."""
    w = WEIGHTS
    s = float(f["top"])
    if f["after"]:
        s += w["write_after"] + (w["consulted_written"] if f["consulted"] else 0.0)
    if f["balance_span"]:
        s += w["balance_span"]
    if f["top"] >= 3:
        s += w["extra_handoffs"] * min(f["extra"], 3)
    if not fn.reachable:
        s *= w["internal_only"]
    if fn.locked:
        s *= w["guarded"]
    elif lock_elsewhere and f["top"] >= 2:
        s *= w["guard_elsewhere"]
    if f["top"] and not f["direct"]:
        s *= w["indirect"]
    return s


def candidates(parsed: Syntax) -> list[Candidate]:
    fns = [fn for fn in _functions(parsed) if fn.kind not in ("modifier", "constructor")]
    _link_internal_writes(fns)
    _link_internal_calls(fns)
    _propagate_locks(fns)
    lock_elsewhere = any(fn.locked for fn in fns)
    out: list[Candidate] = []
    for fn in fns:
        f = _facts(fn)
        if not _eligible(f):
            continue
        shared = {
            "score": round(_score(fn, f, lock_elsewhere), 3),
            "strength": f["top"],
            "guarded": fn.locked,
        }
        # the strongest hand-off is the function's citation, then the first write that follows it
        for place, h in enumerate(sorted(fn.handoffs, key=lambda h: (-h.strength, h.start))[:3]):
            out.append(
                Candidate(
                    "external_call",
                    _span(fn, h.site),
                    {**shared, "kind": h.kind, "rank": 4 if place == 0 else 2},
                )
            )
        if f["after"]:
            w = f["after"][0]
            out.append(
                Candidate(
                    "state_write_after_an_external_call",
                    _span(fn, w[3]),
                    {**shared, "target": w[2], "rank": 3},
                )
            )
    return out


def priority(ref: Candidate) -> float:
    """The function's score (higher is listed first), with the citation rank to choose its site."""
    return float(ref.detail.get("score", 0.0)) * 100 + float(ref.detail.get("rank", 0))
