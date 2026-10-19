"""access_control: an action that changes state or moves value or authority, with nothing (or
nothing sound) establishing that the caller may take it.

`candidates(parsed)` lists the sites and `priority(ref)` orders the functions that hold them (one
finding per function). Names are read as words (camelCase and snake_case split), never as
substrings. A user identifier is only ever correlated (is it a parameter, a state variable, the
caller), never reported. "Restricted" means the function or one of its modifiers establishes who the
caller is (msg.sender, an authority-named check, an `onlyX` modifier whose body reads the caller); a
pause, a reentrancy lock or an initializer does not restrict anybody.

Predicates
  weak_caller_check          a check on the caller that anybody can satisfy: tx.origin, a comparison
                             of the caller with a parameter the caller chose, a verdict asked of a
                             contract the caller chose, an authorization hook with an empty body, or
                             an authority-named modifier that never reads the caller
  arbitrary_call             a low-level call whose target is a parameter, so the caller picks what
                             runs
  value_or_authority_exit    value, tokens, allowance, supply or authority leave the contract
                             (transfer, send, call with value, mint, burn, approve, selfdestruct,
                             grant ...); `guarded` says whether a restriction exists
  open_initializer           an initializer-like function that writes state and has no restriction
                             on the caller
  unrestricted_state_change  a state write in a reachable function with no restriction on the caller
  restricted_state_change    a state write behind a restriction in a function that does more than
                             copy parameters into state
  unrestricted_external_call a call into another contract from a reachable function with no
                             restriction on the caller
  effect_through_helper      a reachable function whose only effect is a call to a helper that
                             writes state or moves value
  authorization_decision     a function that hands the caller to an authority-named check (a role,
                             an allowance, an owner)
  helper_acts_as_caller      an internal function that reads msg.sender as the identity it acts for
                             while it writes or pays

A restricted function that only copies parameters into state (a configuration setter), or only
forwards to one helper in a single statement, is the control working as designed and is not listed.

Ordering features (WEIGHTS: ten numbers set by hand from the reasoning below, then checked on the
development part, which dropped two features, softened one and sized one)
  moves_value          value, tokens, supply or authority leave: what a missing check costs
  strong_primitive     a low-level call or selfdestruct: the caller may steer arbitrary execution
  external_calls       calls into other contracts (up to four): authority exercised elsewhere on
                       this contract's behalf
  unrestricted         no restriction on the caller in the function or in its modifiers
  weak_check           a check exists but anybody can satisfy it
  pays_chosen_account  a payment, mint, burn or allowance to or from an account the caller named,
                       not the caller
  open_authority       an unrestricted function named for configuring, granting, upgrading, paying
                       out or initializing
  size                 log2 of the non-blank, non-comment lines: more behaviour behind the same
                       missing check
  protections          modifiers on the function (up to three): independent layers that a function
                       without them lacks
  helper               an internal function: reachable only through a caller that this check does
                       not see
"""

from __future__ import annotations

import math
import re
from collections import defaultdict
from dataclasses import replace

from sc_sentry.candidate import Candidate
from sc_sentry.solidity import Site, Syntax
from sc_sentry.solidity.syntax import CallSite, FunctionSite, GuardSite

# ---------------------------------------------------------------------------------------------
# Vocabulary of the language, its standard libraries and the common names of authority.

_CAMEL_1 = re.compile(r"([a-z0-9])([A-Z])")
_CAMEL_2 = re.compile(r"([A-Z]+)([A-Z][a-z])")
_SPLIT = re.compile(r"[^A-Za-z0-9]+")
_IDENT = re.compile(r"[A-Za-z_]\w*")
_TOKEN = re.compile(r"[A-Za-z_][A-Za-z_0-9]*|\d+|[^\sA-Za-z_0-9]")


def _words(name: str) -> list[str]:
    spaced = _CAMEL_2.sub(r"\1 \2", _CAMEL_1.sub(r"\1 \2", name))
    return [w.lower() for w in _SPLIT.split(spaced.replace(" ", "_")) if w]


_CALLER = re.compile(r"\bmsg\s*\.\s*sender\b|\b_msgSender\s*\(|\bmsgSender\s*\(")
_ORIGIN = re.compile(r"\btx\s*\.\s*origin\b")
_SUBSCRIPT = re.compile(r"\[[^\[\]]*\]")

_AUTH_WORDS = frozenset(
    {
        "only",
        "auth",
        "authorized",
        "authorised",
        "authorize",
        "authorise",
        "admin",
        "admins",
        "owner",
        "owners",
        "ownership",
        "role",
        "roles",
        "governance",
        "governor",
        "gov",
        "restricted",
        "manager",
        "managers",
        "operator",
        "operators",
        "guardian",
        "keeper",
        "keepers",
        "controller",
        "whitelisted",
        "whitelist",
        "allowed",
        "permitted",
        "permission",
        "permissioned",
        "privileged",
        "minter",
        "minters",
        "authority",
        "executor",
        "trusted",
        "relayer",
        "multisig",
        "council",
        "timelock",
        "dao",
        "signer",
        "signers",
        "access",
        "legit",
        "approved",
    }
)
"""Words that say who may act. `only` stands for any `onlyX` modifier."""

_CHECK_WORDS = frozenset(
    {
        "check",
        "require",
        "requires",
        "ensure",
        "verify",
        "validate",
        "enforce",
        "assert",
        "only",
        "auth",
        "authorize",
        "authorise",
    }
)
"""Verbs of a call made for the sake of stopping a caller who may not proceed."""

_PROOF_WORDS = frozenset({"recover", "ecrecover", "signature", "signer", "verify", "proof"})
"""Words of a call that establishes authority by a signature or a proof rather than by
msg.sender."""

_LANGUAGE = frozenset(
    {
        "function", "returns", "return", "if", "else", "for", "while", "do", "break", "continue",
        "require", "assert", "revert", "emit", "new", "delete", "public", "external", "internal",
        "private", "view", "pure", "payable", "virtual", "override", "constant", "immutable",
        "memory", "storage", "calldata", "unchecked", "try", "catch", "is", "using", "mapping",
        "struct", "enum", "event", "error", "modifier", "constructor", "contract", "interface",
        "library", "import", "pragma", "true", "false", "this", "super", "msg", "block", "tx",
        "abi", "sender", "value", "timestamp", "number", "origin", "address", "bool", "string",
        "bytes", "uint", "int", "uint8", "uint16", "uint32", "uint64", "uint128", "uint256", "int8",
        "int16", "int32", "int64", "int128", "int256", "bytes4", "bytes32", "length", "push", "pop",
        "encode", "encodePacked", "decode", "i", "j", "k",
    }
)  # fmt: skip

_BUILTIN_RECEIVERS = frozenset({"abi", "msg", "block", "tx", "type", "super", "this"})
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
        "suicide",
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
        "bytes",
        "string",
        "emit",
    }
)
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
    }
)
_CAST = frozenset({"address", "payable", "uint160", "uint256", "uint", "_msgSender", "msgSender"})

_MOVERS = frozenset(
    {
        "transfer",
        "send",
        "transferFrom",
        "safeTransfer",
        "safeTransferFrom",
        "sendValue",
        "safeTransferETH",
        "transferETH",
        "forceSafeTransferETH",
        "mint",
        "burn",
        "burnFrom",
        "safeMint",
        "approve",
        "safeApprove",
        "forceApprove",
        "setApprovalForAll",
        "withdraw",
        "redeem",
        "release",
    }
)
"""Members that move value, tokens, supply or allowance away from where the caller stands."""

_MOVER_WORDS = frozenset(
    {
        "transfer",
        "send",
        "mint",
        "burn",
        "withdraw",
        "approve",
        "release",
        "sweep",
        "grant",
        "revoke",
        "upgrade",
        "renounce",
        "payout",
        "refund",
    }
)
"""Words of an unqualified call to something this file does not define (an inherited `_mint`,
`_transfer`)."""

_LOW_LEVEL = frozenset({"call", "delegatecall", "callcode"})

_INITIALISER_WORDS = frozenset({"initialize", "initialise", "init", "setup"})
_AUTHORITY_VERBS = frozenset(
    {
        "set",
        "add",
        "remove",
        "change",
        "update",
        "grant",
        "revoke",
        "renounce",
        "transfer",
        "upgrade",
        "migrate",
        "configure",
        "enable",
        "disable",
        "whitelist",
        "blacklist",
        "authorize",
        "register",
        "pause",
        "unpause",
        "delegate",
        "withdraw",
        "sweep",
        "rescue",
        "recover",
        "mint",
        "burn",
        "execute",
        "emergency",
    }
)
"""Verbs of a function that configures, grants, upgrades or pays out: authority, not use."""

# The weights of the function ordering. Each multiplies one structural feature of `_Fn.score`.
WEIGHTS = {
    "moves_value": 1.5,
    "strong_primitive": 1.0,
    "external_calls": 0.5,
    "unrestricted": 1.0,
    "weak_check": 2.0,
    "pays_chosen_account": 0.5,
    "open_authority": 1.0,
    "size": 0.8,
    "protections": -1.0,
    "helper": -1.0,
}


class _Fn:
    """What one function (one overload of a name in a contract) says about who may run it and what
    it can do."""

    def __init__(self) -> None:
        self.key: tuple[str | None, str | None] = (None, None)
        self.nodes: list[FunctionSite] = []
        self.reachable = False
        self.read_only = True
        self.lines = 0
        self.params: set[str] = set()
        self.words: list[str] = []
        self.modifiers: list[str] = []
        self.restrict_mod = False
        self.misleading_mod = False
        self.empty_hook = False
        self.strong_guards: list[tuple[GuardSite | None, str]] = []
        self.weak_guards: list[tuple[GuardSite, str]] = []
        self.caller_sites: list[Site] = []
        self.auth_calls: list[CallSite] = []
        self.writes: list[Site] = []
        self.computed_writes = 0
        self.scalar_writes = 0
        self.ext: list[CallSite] = []
        self.moves: list[CallSite] = []
        self.low_level: list[CallSite] = []
        self.arbitrary: list[CallSite] = []
        self.selfdestruct: list[CallSite] = []
        self.helper_calls: list[CallSite] = []
        self.inherited_calls: list[CallSite] = []
        self.pays_chosen_account = False
        self.inherited_write = False
        self.inherited_move = False
        self.inherited_ext = False

    @property
    def restricted(self) -> bool:
        return self.restrict_mod or bool(self.strong_guards)

    @property
    def weak(self) -> bool:
        return self.misleading_mod or self.empty_hook or bool(self.weak_guards)

    @property
    def moves_value(self) -> bool:
        return bool(self.moves or self.selfdestruct) or self.inherited_move

    @property
    def writes_state(self) -> bool:
        return bool(self.writes) or self.inherited_write or bool(self.inherited_calls)

    @property
    def reaches_out(self) -> bool:
        return bool(
            self.ext
            or self.moves
            or self.selfdestruct
            or self.low_level
            or self.inherited_move
            or self.inherited_ext
        )

    def score(self) -> float:
        w = WEIGHTS
        authority_named = bool(set(self.words) & (_AUTHORITY_VERBS | _INITIALISER_WORDS))
        return (
            w["moves_value"] * self.moves_value
            + w["strong_primitive"] * bool(self.low_level or self.selfdestruct)
            + w["external_calls"] * min(len(self.ext) + self.inherited_ext, 4)
            + w["unrestricted"] * (not self.restricted)
            + w["weak_check"] * self.weak
            + w["pays_chosen_account"] * self.pays_chosen_account
            + w["open_authority"] * (not self.restricted and authority_named)
            + w["size"] * math.log2(max(self.lines, 1))
            + w["protections"] * min(len(self.modifiers), 3)
            + w["helper"] * (not self.reachable)
        )


# ---------------------------------------------------------------------------------------------
# Reading text.


def _balanced(text: str, open_at: int) -> str:
    """The text inside the parentheses that open at `open_at`."""
    depth = 0
    for i in range(open_at, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[open_at + 1 : i]
    return text[open_at + 1 :]


def _first_argument(inner: str) -> str:
    depth = 0
    for i, ch in enumerate(inner):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            return inner[:i]
    return inner


def _condition(guard: GuardSite) -> str:
    """The condition of a require, an assert or an if, without the branch or the message."""
    text = guard.site.text.lstrip()
    open_at = text.find("(")
    if open_at < 0:
        return text
    inner = _balanced(text, open_at)
    return inner if text.startswith("if") else _first_argument(inner)


def _calls_in(condition: str) -> set[str]:
    """Names called in a condition, other than casts of the caller."""
    return set(re.findall(r"([A-Za-z_]\w*)\s*\(", condition)) - _CAST


_MEMBER_CALL = re.compile(
    r"([A-Za-z_]\w*)\s*(?:\(\s*([A-Za-z_]\w*)\s*\))?\s*\.\s*([A-Za-z_]\w*)\s*\("
)


def _asks_chosen_contract(condition: str, params: set[str]) -> bool:
    """Whether a verdict on who may act is asked of a contract named by a parameter:
    `IFoo(p).owner() == msg.sender`."""
    for m in _MEMBER_CALL.finditer(condition):
        receiver = m.group(2) or m.group(1)
        if receiver in params and set(_words(m.group(3))) & _AUTH_WORDS:
            return True
    return False


_ETHER_HELPERS = frozenset(
    {"safeTransferETH", "transferETH", "forceSafeTransferETH", "sendValue", "sendETH"}
)


def _names_chosen_account(call: CallSite, params: set[str]) -> bool:
    """Whether a value-moving call pays, charges, mints to or burns from an account the caller named
    by parameter."""
    args = [a.text for a in call.arguments]
    receiver = (call.receiver or "").strip()
    callee = call.callee
    library = bool(receiver) and receiver[:1].isupper() and _IDENT.fullmatch(receiver) is not None
    if (callee in ("transfer", "send") and len(args) == 1) or callee == "call":
        named = [receiver]  # address.transfer(amount), address.call{value: amount}("")
    elif callee in _ETHER_HELPERS:
        named = args[:1]
    elif "from" in _words(callee) or callee == "transferFrom":
        named = args[1:3] if library and len(args) >= 4 else args[:2]
    elif receiver in ("", "this", "super"):
        named = (
            args[:2]
            if "transfer" in _words(callee) and len(args) >= 3
            else args[:1]
            if len(args) >= 2
            else []
        )
    elif callee in (
        "transfer",
        "safeTransfer",
        "mint",
        "safeMint",
        "approve",
        "safeApprove",
        "forceApprove",
        "burn",
    ):
        named = args[1:2] if library and len(args) >= 3 else args[:1] if len(args) >= 2 else []
    else:
        named = []
    return any(set(_IDENT.findall(t)) & params for t in named)


def _count_lines(text: str) -> int:
    n = 0
    in_block = False
    for raw in text.split("\n"):
        line = raw.strip()
        if in_block:
            if "*/" in line:
                in_block = False
            continue
        if not line or line.startswith("//"):
            continue
        if line.startswith("/*"):
            in_block = "*/" not in line
            continue
        n += 1
    return n


def _citable(text: str) -> bool:
    """Whether whole lines of this text could be cited: six tokens, one naming something of the
    file's own."""
    tokens = _TOKEN.findall(text)
    return len(tokens) >= 6 and any(
        (t[0].isalpha() or t[0] == "_") and t not in _LANGUAGE for t in tokens
    )


def _header(f: FunctionSite) -> Site:
    """The declaration of a function up to its opening brace, as a site."""
    site = f.site
    head = site.text.split("{", 1)[0]
    return replace(
        site, end_line=site.start_line + head.count("\n"), text=head, start_byte=-1, end_byte=-1
    )


def _span(fn: _Fn, site: Site) -> Site:
    """`site`, widened by whole lines inside its function until it is citable; the declaration if
    nothing else is."""
    node = next(
        (n for n in fn.nodes if n.site.start_line <= site.start_line <= n.site.end_line),
        fn.nodes[0],
    )
    rows = node.site.text.split("\n")
    base = node.site.start_line
    lo, hi = site.start_line, min(site.end_line, site.start_line + 12)
    for _ in range(3):
        text = "\n".join(rows[lo - base : hi - base + 1])
        if _citable(text):
            if (lo, hi) == (site.start_line, site.end_line):
                return site
            return replace(site, start_line=lo, end_line=hi, text=text, start_byte=-1, end_byte=-1)
        if lo > base + 1:
            lo -= 1
        elif hi < node.site.end_line:
            hi += 1
    return _header(node)


def _guard_site(guard: GuardSite, condition: str) -> Site:
    """A guard cited at the lines of its condition, not of the branch it protects."""
    site = guard.site
    if not site.text.lstrip().startswith("if"):
        return site
    head = site.text.split(condition, 1)[0] + condition
    return replace(
        site, end_line=site.start_line + head.count("\n"), text=head, start_byte=-1, end_byte=-1
    )


def _line_site(parsed: Syntax, line: int, row: str) -> Site:
    return Site(
        node_type="expression_statement",
        text=row.strip(),
        start_line=line,
        end_line=line,
        host=parsed.host_at(line),
    )


_STATEMENT_WRITE = re.compile(
    r"(?:\+\+|--)\s*([A-Za-z_]\w*)|([A-Za-z_]\w*)(?:\s*\[[^\]]*\]|\.\w+)*\s*(?:\+\+|--)|\bdelete\s+([A-Za-z_]\w*)"
)
"""An increment, a decrement or a delete, which the assignment index does not list."""

_STORAGE_POINTER = re.compile(r"\b[\w.\[\]]+\s+storage\s+(\w+)\s*=")
"""A local that points into storage: a write through it is a write of state."""

_PLAIN_VALUE = re.compile(r"[0-9_.]+|0x[0-9a-fA-F]+|address\(0\)|true|false")


# ---------------------------------------------------------------------------------------------
# What each function says.


def _facts(parsed: Syntax) -> list[_Fn]:
    state = parsed.state_variables
    kinds: dict[str | None, str] = {
        d.names[0]: d.kind.value for d in parsed.index.declarations if d.kind.is_type
    }
    defined_modifiers: dict[str, FunctionSite] = {}
    fns: dict[tuple[str | None, str | None], _Fn] = {}
    fn: _Fn | None
    for f in parsed.functions:
        if not f.site.text.rstrip().endswith("}"):
            continue
        kind = f.declaration.kind.value
        if kind == "modifier":
            defined_modifiers[f.declaration.names[0]] = f
            continue
        if kind in ("constructor", "receive_or_fallback") or kinds.get(f.site.host.contract) in (
            "library",
            "interface",
        ):
            continue
        fn = fns.setdefault((f.site.host.contract, f.site.host.function_signature), _Fn())
        if not fn.nodes:
            fn.key = (f.site.host.contract, f.site.host.function)
            fn.words = _words(fn.key[1] or "")
        fn.nodes.append(f)
        fn.reachable = fn.reachable or f.is_externally_reachable
        fn.read_only = fn.read_only and f.is_read_only
        fn.params |= set(f.parameter_names)
        fn.modifiers += list(f.modifiers)
    at_line: dict[int, _Fn] = {}
    for fn in fns.values():
        fn.lines = max(_count_lines(n.site.text) for n in fn.nodes)
        for n in fn.nodes:
            for ln in range(n.site.start_line, n.site.end_line + 1):
                at_line[ln] = fn
    declared = {fn.key[1] for fn in fns.values()}
    calls_by_line: dict[int, list[CallSite]] = defaultdict(list)
    for c in parsed.calls:
        calls_by_line[c.site.start_line].append(c)

    def calls_between(lo: int, hi: int) -> list[CallSite]:
        return [c for ln in range(lo, hi + 1) for c in calls_by_line.get(ln, ())]

    # -- modifiers: which ones restrict the caller, which only look as if they do ------------------
    reads_caller: dict[str, bool] = {}
    pretends: dict[str, bool] = {}
    for name, m in defined_modifiers.items():
        inside = calls_between(m.site.start_line, m.site.end_line)
        reads = bool(_CALLER.search(m.site.text)) or any(
            set(_words(c.callee)) & (_AUTH_WORDS | _PROOF_WORDS) for c in inside
        )
        reads_caller[name] = reads
        pretends[name] = (
            not reads
            and not any(c.callee not in _NOT_A_CALL for c in inside)
            and bool(set(_words(name)) & (_AUTH_WORDS - {"only"}))
        )
    for fn in fns.values():
        looks_restricted = False
        for text in fn.modifiers:
            name = re.split(r"[\s(]", text.strip(), maxsplit=1)[0]
            if name in defined_modifiers:
                if reads_caller[name]:
                    fn.restrict_mod = True
                elif pretends[name]:
                    looks_restricted = True
            elif set(_words(name)) & _AUTH_WORDS:
                fn.restrict_mod = True
        fn.misleading_mod = looks_restricted and not fn.restrict_mod

    # -- checks inside the body: sound authorisation, or a check anybody can satisfy ---------------
    param_compared: list[tuple[_Fn, GuardSite, str, bool]] = []
    for g in parsed.guards:
        fn = at_line.get(g.site.start_line)
        if fn is None:
            continue
        cond = _condition(g)
        direct = bool(_CALLER.search(_SUBSCRIPT.sub("[]", cond))) or bool(_ORIGIN.search(cond))
        membership = any(
            _CALLER.search(m.group(0))
            and set(_words(m.group(1))) & (_AUTH_WORDS | {"is", "can", "has"})
            for m in re.finditer(r"([A-Za-z_]\w*)\s*(\[[^\[\]]*\])", cond)
        )
        asks = any(
            set(_words(m.group(1))) & (_AUTH_WORDS | _PROOF_WORDS)
            for m in re.finditer(r"([A-Za-z_]\w*)\s*\(", cond)
        )
        if not (direct or membership or asks):
            continue
        names = set(_IDENT.findall(cond)) - _LANGUAGE
        is_if = g.site.text.lstrip().startswith("if")
        if direct and not is_if and "!=" in cond and "==" not in cond:
            # `require(x != msg.sender)` keeps somebody out; it does not say who may come in
            continue
        if _ORIGIN.search(cond):
            weak = True
        elif (
            direct
            and names & fn.params
            and not ((names & state) - fn.params)
            and not _calls_in(cond)
        ):
            if is_if or ("==" in cond and "!=" not in cond):
                # the caller equals a name the caller chose: sound for acting on one's own account,
                # vacuous for global state, which the effects below decide
                param_compared.append((fn, g, cond, bool(names & state)))
                continue
            weak = False
        else:
            weak = (direct or membership) and _asks_chosen_contract(cond, fn.params)
        if weak:
            fn.weak_guards.append((g, cond))
        else:
            fn.strong_guards.append((g, cond))
    for fn in fns.values():
        for node in fn.nodes:
            for c in calls_between(node.site.start_line, node.site.end_line):
                if c.callee in _NOT_A_CALL:
                    continue
                words = set(_words(c.callee))
                if c.is_bare_statement and words & _AUTH_WORDS and words & _CHECK_WORDS:
                    fn.strong_guards.append((None, c.callee))
        # an authorization hook that checks nothing authorizes anybody
        if (
            set(fn.words) & {"authorize", "authorise"}
            and not fn.strong_guards
            and not fn.weak_guards
            and not fn.restrict_mod
        ):
            body = [
                c
                for n in fn.nodes
                for c in calls_between(n.site.start_line, n.site.end_line)
                if c.callee not in _NOT_A_CALL
            ]
            fn.empty_hook = not body

    # -- effects -----------------------------------------------------------------------------------
    pointers = {
        id(fn): {m.group(1) for n in fn.nodes for m in _STORAGE_POINTER.finditer(n.site.text)}
        for fn in fns.values()
    }
    for w in parsed.writes:
        fn = at_line.get(w.site.start_line)
        if fn is None or not (w.writes_state or w.target_root in pointers[id(fn)]):
            continue
        fn.writes.append(w.site)
        if w.target == "state_variable":
            fn.scalar_writes += 1
        right = re.split(r"(?<![=!<>])=(?!=)", w.site.text, maxsplit=1)[-1].strip()
        if not (w.operator == "=" and (right in fn.params or _PLAIN_VALUE.fullmatch(right))):
            fn.computed_writes += 1
    written_lines = {(id(fn), s.start_line) for fn in fns.values() for s in fn.writes}
    for fn in fns.values():
        for node in fn.nodes:
            for offset, row in enumerate(node.site.text.split("\n")):
                line = node.site.start_line + offset
                if (id(fn), line) in written_lines or at_line.get(line) is not fn:
                    continue
                for hit in _STATEMENT_WRITE.finditer(row):
                    root = next(g for g in hit.groups() if g)
                    if root in state or root in pointers[id(fn)]:
                        fn.writes.append(_line_site(parsed, line, row))
                        fn.computed_writes += 1
                        break
    for c in parsed.calls:
        fn = at_line.get(c.site.start_line)
        if fn is None:
            continue
        root = re.split(r"[.\[(]", (c.receiver or "").strip(), maxsplit=1)[0]
        if _CALLER.search(c.site.text):
            fn.caller_sites.append(c.site)
            if set(_words(c.callee)) & (_AUTH_WORDS | _PROOF_WORDS) and c.callee not in _NOT_A_CALL:
                fn.auth_calls.append(c)
        if c.callee in ("push", "pop") and root in state:
            fn.writes.append(c.site)
            fn.computed_writes += 1
            continue
        if c.callee in ("selfdestruct", "suicide"):
            fn.selfdestruct.append(c)
            continue
        if c.callee in _NOT_A_CALL or c.callee in _ARITHMETIC:
            continue
        if c.receiver is None or c.receiver in ("this", "super"):
            if c.callee[:1].isupper():
                # an event, error, struct or type conversion: functions are lowerCamelCase
                continue
            if c.callee in declared:
                fn.helper_calls.append(c)
                continue
            words = set(_words(c.callee))
            if words & _MOVER_WORDS:
                fn.moves.append(c)
                fn.pays_chosen_account = fn.pays_chosen_account or _names_chosen_account(
                    c, fn.params
                )
            elif words & _AUTHORITY_VERBS:
                fn.inherited_calls.append(c)
            continue
        if root in _BUILTIN_RECEIVERS:
            continue
        fn.ext.append(c)
        if c.callee in _LOW_LEVEL:
            fn.low_level.append(c)
            if root in fn.params:
                fn.arbitrary.append(c)
            if c.has_call_options:
                fn.moves.append(c)
                fn.pays_chosen_account = fn.pays_chosen_account or _names_chosen_account(
                    c, fn.params
                )
        elif c.callee in _MOVERS:
            fn.moves.append(c)
            fn.pays_chosen_account = fn.pays_chosen_account or _names_chosen_account(c, fn.params)

    for fn, g, cond, shadows in param_compared:
        weak = shadows or fn.scalar_writes > 0 or fn.moves_value
        if weak:
            fn.weak_guards.append((g, cond))
        else:
            fn.strong_guards.append((g, cond))

    # -- effects that arrive through helpers defined in the same file ------------------------------
    by_name: dict[str | None, list[_Fn]] = defaultdict(list)
    for fn in fns.values():
        by_name[fn.key[1]].append(fn)
    for _ in range(6):
        changed = False
        for fn in fns.values():
            for c in fn.helper_calls:
                for callee in by_name.get(c.callee, ()):
                    if callee is fn:
                        continue
                    wr = bool(callee.writes or callee.inherited_calls) or callee.inherited_write
                    mv = bool(callee.moves or callee.selfdestruct) or callee.inherited_move
                    ex = bool(callee.ext) or callee.inherited_ext
                    if (
                        (wr and not fn.inherited_write)
                        or (mv and not fn.inherited_move)
                        or (ex and not fn.inherited_ext)
                    ):
                        fn.inherited_write |= wr
                        fn.inherited_move |= mv
                        fn.inherited_ext |= ex
                        changed = True
        if not changed:
            break
    return list(fns.values())


# ---------------------------------------------------------------------------------------------
# The candidates.

_RANK = {
    "weak_caller_check": 10,
    "arbitrary_call": 9,
    "value_or_authority_exit": 8,
    "open_initializer": 7,
    "unrestricted_state_change": 6,
    "restricted_state_change": 5,
    "unrestricted_external_call": 4,
    "effect_through_helper": 3,
    "authorization_decision": 2,
    "helper_acts_as_caller": 1,
}


def _is_plain_setter(fn: _Fn) -> bool:
    """A restricted function that only copies parameters into state, or forwards to one helper in
    one statement."""
    if not fn.restricted or fn.weak or fn.reaches_out:
        return False
    if fn.writes:
        return not fn.computed_writes and not fn.inherited_calls and not fn.inherited_write
    return fn.lines <= 3


def candidates(parsed: Syntax) -> list[Candidate]:
    out: list[Candidate] = []
    for fn in _facts(parsed):
        score = round(fn.score(), 4)
        before = len(out)

        def add(
            predicate: str,
            site: Site,
            _fn: _Fn = fn,
            _score: float = score,
            **detail: str | int | float | bool,
        ) -> None:
            detail.update(
                score=_score,
                rank=_RANK[predicate],
                restricted=_fn.restricted,
                reachable=_fn.reachable,
            )
            out.append(Candidate(predicate, _span(_fn, site), detail))

        if fn.weak and not fn.read_only:
            if fn.weak_guards:
                guard, cond = fn.weak_guards[0]
                add("weak_caller_check", _guard_site(guard, cond))
            else:
                add("weak_caller_check", _header(fn.nodes[0]))
        for c in fn.arbitrary[:1]:
            add("arbitrary_call", c.site, callee=c.callee)
        if not fn.read_only and fn.reachable:
            effectful = fn.writes_state or fn.reaches_out
            if effectful and not _is_plain_setter(fn):
                for c in (fn.moves + fn.selfdestruct)[:1]:
                    add("value_or_authority_exit", c.site, callee=c.callee, guarded=fn.restricted)
                if fn.writes:
                    initialiser = bool(set(fn.words) & _INITIALISER_WORDS) or any(
                        "initializer" in m for m in fn.modifiers
                    )
                    if not fn.restricted and initialiser:
                        add("open_initializer", fn.writes[0], writes=len(fn.writes))
                    elif not fn.restricted:
                        add("unrestricted_state_change", fn.writes[0], writes=len(fn.writes))
                    else:
                        add("restricted_state_change", fn.writes[0], writes=len(fn.writes))
                if fn.ext and not fn.restricted:
                    add("unrestricted_external_call", fn.ext[0].site, callee=fn.ext[0].callee)
                if not (fn.writes or fn.moves or fn.selfdestruct):
                    for c in (fn.inherited_calls + fn.helper_calls)[:1]:
                        add("effect_through_helper", c.site, callee=c.callee)
        elif not fn.read_only and (fn.writes_state or fn.moves_value or fn.ext) and fn.caller_sites:
            add("helper_acts_as_caller", fn.caller_sites[0])
        if len(out) == before and fn.auth_calls:
            add("authorization_decision", fn.auth_calls[0].site, callee=fn.auth_calls[0].callee)
    return out


def priority(ref: Candidate) -> float:
    """The function's score (higher is listed first), with the citation rank to choose its site."""
    return float(ref.detail.get("score", 0.0)) * 100 + float(ref.detail.get("rank", 0))
