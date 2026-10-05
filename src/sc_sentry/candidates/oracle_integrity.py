"""oracle_integrity: a value read from outside the contract and used without establishing it can be
trusted.

A function is a candidate when a value measured elsewhere (a price, rate, pool reserve, share value,
feed round, reported answer, signed quote) enters it, is derived and served by it, or its trust is
decided in it. Names are read as words (camelCase and snake_case split), never as substrings. A
candidate is cited at whole lines that could be quoted (six tokens, one naming something of the
file's own), widened inside its function if it must be.

Predicates
  external_value_read   a call on an oracle/feed receiver, or to a price/rate/reserve/share-value
                        read, in a function body
  oracle_consumer_call  a use of the result of an internal function that reads or serves such a
                        value
  price_computation     a function named for a price or rate that derives and returns it by calls or
                        arithmetic
  freshness_check       block.timestamp is combined with a feed update-time, heartbeat or staleness
                        quantity
  feed_round_signature  a function takes or returns a feed round id (uint80, the aggregator
                        interface's round type)
  signed_value_payload  a signature is recovered or verified in a function that handles a price,
                        rate or oracle value
  oracle_input_write    a function named for setting or updating a price, rate, oracle or feed
                        stores its input in state
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import replace

from sc_sentry.candidate import Candidate
from sc_sentry.solidity.syntax import CallSite, FunctionSite, Site, Syntax

_CAMEL_1 = re.compile(r"([a-z0-9])([A-Z])")
_CAMEL_2 = re.compile(r"([A-Z]+)([A-Z][a-z])")
_SPLIT = re.compile(r"[^A-Za-z0-9]+")
_IDENT = re.compile(r"[A-Za-z_]\w*")
_TOKEN = re.compile(r"[A-Za-z_][A-Za-z_0-9]*|\d+|[^\sA-Za-z_0-9]")
_INDEXED = frozenset({"price", "twap", "oracle", "feed"})


def _words(name: str) -> list[str]:
    spaced = _CAMEL_2.sub(r"\1 \2", _CAMEL_1.sub(r"\1 \2", name))
    out: list[str] = []
    for w in _SPLIT.split(spaced.replace(" ", "_")):
        w = w.lower()
        if w:
            # price0, price1: the index belongs to the token pair, not to the word
            stem = w.rstrip("0123456789")
            out.append(stem if stem in _INDEXED else w)
    return out


# A word that names a quantity measured outside this contract.
_VALUE_WORDS = frozenset(
    {
        "price",
        "prices",
        "twap",
        "quote",
        "quotes",
        "answer",
        "reserves",
        "slot0",
        "consult",
        "observe",
        "oracle",
        "oracles",
        "feed",
        "feeds",
    }
)
# Compound reads whose words alone would be too common to match one by one.
_VALUE_COMPOUNDS = (
    "latestrounddata",
    "latestround",
    "getrounddata",
    "latesttimestamp",
    "timeweighted",
    "converttoassets",
    "converttoshares",
    "previewredeem",
    "previewdeposit",
    "previewmint",
    "previewwithdraw",
    "totalassets",
    "sharevalue",
    "sharesperasset",
    "assetspershare",
    "exchangerate",
    "getrate",
    "virtualprice",
    "getamountsout",
    "getamountsin",
    "getamountout",
    "getamountin",
    "getpooltokens",
    "sqrtprice",
    "referencedata",
    "getdy",
)
# A leading word that makes a call or a function a write or a lookup of configuration, not a read of
# a value.
_CONFIG_VERBS = frozenset(
    {
        "set",
        "add",
        "remove",
        "init",
        "initialize",
        "register",
        "update",
        "enable",
        "disable",
        "pause",
        "reactivate",
        "is",
        "only",
    }
)
# What a call on a feed returns that is metadata, not the measured value.
_METADATA_WORDS = frozenset(
    {"decimals", "decimal", "description", "version", "symbol", "name", "fee", "owner"}
)
_SOURCE_WORDS = frozenset(
    {
        "oracle",
        "oracles",
        "feed",
        "feeds",
        "pricefeed",
        "twap",
        "pyth",
        "chainlink",
        "redstone",
        "api3",
    }
)
_FRESHNESS_JOINED = ("updatedat", "heartbeat", "stale", "maxage", "answeredinround", "maxdelay")
_RECOVERS = frozenset(
    {"ecrecover", "recover", "tryRecover", "isValidSignature", "isValidSignatureNow"}
)
_VERIFIES = frozenset({"verify", "verifySignature", "checkSignature"})
_ROUND_ID = re.compile(r"\buint80\b")
_PRICE_ISH = frozenset({"price", "rate", "answer", "quote", "oracle", "twap"})

# Words the language supplies; a line naming nothing else says nothing about any file in particular.
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


def _names_value(name: str) -> bool:
    ws = _words(name)
    if any(w in _VALUE_WORDS for w in ws):
        return True
    joined = "".join(ws)
    return any(c in joined for c in _VALUE_COMPOUNDS)


def _is_config(name: str) -> bool:
    ws = _words(name)
    return bool(ws) and (ws[0] in _CONFIG_VERBS or "init" in ws or "initialize" in ws)


def _is_value_call(callee: str, receiver: str | None) -> bool:
    ws = _words(callee)
    if not ws or ws[0] in _CONFIG_VERBS:
        return False
    if _names_value(callee):
        return True
    if any(w in _METADATA_WORDS for w in ws):
        return False
    if not receiver:
        return False
    return any(w in _SOURCE_WORDS for w in _words(receiver))


def _passes_signature(c: CallSite) -> bool:
    """A verify call (not a Merkle proof check) is one that is handed something named a
    signature."""
    return any(
        {"signature", "sig"} & set(_words(i)) for a in c.arguments for i in _IDENT.findall(a.text)
    )


def _citable(text: str) -> bool:
    """Whether whole lines of this text could be cited: six tokens, one naming something of the
    file's own."""
    tokens = _TOKEN.findall(text)
    return len(tokens) >= 6 and any(
        (t[0].isalpha() or t[0] == "_") and t not in _LANGUAGE for t in tokens
    )


def _header(f: FunctionSite) -> Site:
    """The declaration line(s) of a function, up to its opening brace: a citation, not a whole
    body."""
    site = f.site
    head = site.text.split("{", 1)[0]
    return replace(
        site, end_line=site.start_line + head.count("\n"), text=head, start_byte=-1, end_byte=-1
    )


def _span(f: FunctionSite, site: Site) -> Site:
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


def _used(c: CallSite, tests: list[Site]) -> bool:
    """The call's result takes part in arithmetic or a test: it is inside one, or a name it is bound
    to is in one."""
    mine = [t for t in tests if t.host.function == c.site.host.function]
    if any(t.contains(c.site) for t in mine):
        return True
    names = set(c.bound_names)
    return any(names & set(_IDENT.findall(t.text)) for t in mine)


def candidates(parsed: Syntax) -> list[Candidate]:
    out: list[Candidate] = []
    fns = [f for f in parsed.functions if f.site.text.rstrip().endswith("}")]
    by_name: dict[str, list[FunctionSite]] = {}
    at_line: dict[int, FunctionSite] = {}
    for f in fns:
        by_name.setdefault(f.declaration.names[0], []).append(f)
        for line in range(f.site.start_line, f.site.end_line + 1):
            at_line[line] = f

    def add(predicate: str, site: Site, score: int, **detail: str | int | float | bool) -> None:
        f = at_line.get(site.start_line)
        out.append(Candidate(predicate, _span(f, site) if f else site, {"score": score, **detail}))

    def owner(site: Site) -> str | None:
        name = site.host.function
        return name if name in by_name else None

    calls_in: Counter[str | None] = Counter()
    arith_in: Counter[str | None] = Counter()
    for c in parsed.calls:
        if owner(c.site):
            calls_in[c.site.host.function] += 1
    for a in parsed.arithmetic:
        if owner(a.site):
            arith_in[a.site.host.function] += 1

    # -- a value is read from outside ----------------------------------------
    direct: dict[str, list[CallSite]] = {}
    for c in parsed.calls:
        fn = owner(c.site)
        if not fn:
            continue
        if c.receiver not in (None, "this") and _is_value_call(c.callee, c.receiver):
            direct.setdefault(fn, []).append(c)
    for calls in direct.values():
        for c in calls:
            add("external_value_read", c.site, 80, callee=c.callee)

    # -- a value is derived and served ----------------------------------------
    serving: set[str] = set()
    for f in fns:
        name = f.declaration.names[0]
        if _is_config(name) or not _names_value(name) or name in direct:
            continue
        if "returns" not in f.site.text.split("{", 1)[0]:
            continue
        if calls_in[name] + arith_in[name]:
            serving.add(name)
            add("price_computation", _header(f), 50)

    # -- the value is used in a function that did not read it itself ---------
    sources = set(direct) | serving
    tests = [a.site for a in parsed.arithmetic] + [g.site for g in parsed.guards]
    for c in parsed.calls:
        fn = owner(c.site)
        if (
            fn
            and c.receiver in (None, "this")
            and c.callee in sources
            and c.callee != fn
            and fn not in sources
            and not c.is_bare_statement
            and _used(c, tests)
        ):
            add("oracle_consumer_call", c.site, 45, callee=c.callee)

    # -- freshness of a feed answer is decided here ----------------------------
    now: dict[str | None, Site] = {}
    for site, obj, member in parsed.member_reads:
        if obj == "block" and member == "timestamp" and owner(site):
            now.setdefault(owner(site), site)
    for f in fns:
        name = f.declaration.names[0]
        if name not in now:
            continue
        idents = {"".join(_words(i)) for i in _IDENT.findall(f.site.text)}
        if any(k in i for i in idents for k in _FRESHNESS_JOINED):
            add("freshness_check", now[name], 85)

    # -- the function speaks the feed interface -----------------------------------
    for f in fns:
        if _ROUND_ID.search(f.site.text.split("{", 1)[0]):
            add("feed_round_signature", _header(f), 70)

    # -- a signed payload is trusted next to a price ---------------------------
    signed: dict[str | None, Site] = {}
    for c in parsed.calls:
        if owner(c.site) and (
            c.callee in _RECOVERS or (c.callee in _VERIFIES and _passes_signature(c))
        ):
            signed.setdefault(c.site.host.function, c.site)
    for f in fns:
        name = f.declaration.names[0]
        if name in signed:
            words = {w for i in _IDENT.findall(f.site.text) for w in _words(i)}
            if words & _PRICE_ISH:
                add("signed_value_payload", signed[name], 85)

    # -- an input that becomes the trusted value or source is stored ------------
    for w in parsed.writes:
        fn = owner(w.site)
        if (
            fn
            and w.writes_state
            and fn not in ("constructor", "initialize")
            and _is_config(fn)
            and _names_value(fn)
        ):
            add("oracle_input_write", w.site, 20, target=w.target_root)

    return out


def priority(ref: Candidate) -> float:
    return float(ref.detail.get("score", 0))
