"""Slippage candidates: where what comes back from an exchange, a liquidity change, a mint or
redeem, or an oracle-converted amount has a bound that is missing, zero, hard-coded, computed or
compared.

Predicates:
  zero_bound           a literal zero (or an unfilled new array) stands where a min/max/price-limit
                       bound belongs: a call argument of an exchange-like call, a struct field, or a
                       local
  exchange_call        a call to a swap / exchange / liquidity-change / pool join-exit / redeem
                       style callee
  bound_check          a require/if compares something against a min/max-amount, slippage or bips
                       quantity
  bound_computation    a statement (or a function named for a min/max amount) that computes such a
                       quantity
  bound_use            a statement that passes or stores a min/max-amount, slippage, bips or
                       price-limit quantity
  bound_configuration  a state variable is assigned a min/max-amount, slippage or bips quantity (a
                       setter or initialiser)
  unused_bound_param   a parameter named like a bound is never read in its function
  price_conversion     an amount scaled (multiplied or divided) by a price or rate the function read
                       from an oracle-like call, in a function that is not itself a price accessor

Keyed on Solidity shape and common domain vocabulary; identifiers are split into
camelCase/underscore tokens. The word "slippage" stands on its own. Min/max-amount, bips and
price-limit names count in a function that exchanges, changes liquidity, mints or redeems, or
measures a receipt by a balance difference, or when set to a literal zero; ALL_CAPS constants
(denominators, protocol caps) never count. Every site is widened to a construct whose whole lines
are a substantive citation (at least six tokens), never past its function.

Uses Syntax internals (`_nodes`, `_site`, `_tree`, `_data`) for the tree-level queries the public
API lacks.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from tree_sitter import Node

from sc_sentry.candidate import Candidate
from sc_sentry.solidity.syntax import Host, Site, Syntax

# --- vocabulary ----------------------------------------------------------------------------------

_TOKEN = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")
_IDENT = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_ZERO = re.compile(r"(?:0|0x0+|0e\d+)(?:\s*(?:wei|gwei|ether))?")


def _tokens(name: str) -> tuple[str, ...]:
    return tuple(t.lower() for part in name.split("_") for t in _TOKEN.findall(part))


_MINMAX = {"min", "minimum", "max", "maximum"}
_AMOUNTISH = {
    "amount",
    "amounts",
    "out",
    "output",
    "return",
    "returns",
    "received",
    "receive",
    "shares",
    "share",
    "liquidity",
    "collateral",
    "token",
    "tokens",
    "asset",
    "assets",
    "price",
    "lp",
    "in",
    "input",
    "desired",
    "expected",
    "proceeds",
    "payout",
}
_NOT_A_BOUND = {"fee", "fees", "tax", "reward", "rewards", "commission", "protocol", "royalty"}
_BIPS = {"bips", "bip", "bps", "bp"}


def bound_kind(name: str) -> str | None:
    """What kind of swap/liquidity bound a name spells, or None."""
    if name.isupper() and "SLIPPAGE" not in name:
        return None  # a denominator or a protocol cap, not a bound the caller supplies
    ts = set(_tokens(name))
    if ts & {"slippage", "slippages", "tolerance"}:
        return "slippage"
    if ts & _BIPS and not ts & _NOT_A_BOUND:
        return "bips"
    if ts & _MINMAX and ts & _AMOUNTISH:
        return "minmax"
    if "limit" in ts and ts & {"price", "sqrt"}:
        return "price_limit"
    return None


_NOT_AN_OPERATION = {
    "get",
    "calc",
    "calculate",
    "quote",
    "preview",
    "estimate",
    "is",
    "has",
    "fee",
    "fees",
    "rate",
    "price",
    "check",
}


def _is_exchange(callee: str) -> bool:
    """A callee that trades, changes liquidity, or joins/exits a pool (not a cast or a struct
    constructor)."""
    if callee[:1].isupper():
        return False
    t = set(_tokens(callee))
    if t & {"join", "exit"} and "pool" in t:
        return True
    if t & _NOT_AN_OPERATION:
        return False
    if t & {"swap", "swaps", "exchange"} or ("exact" in t and t & {"input", "output"}):
        return True
    return "liquidity" in t and bool(
        t
        & {
            "add",
            "remove",
            "increase",
            "decrease",
            "provide",
            "withdraw",
            "deposit",
            "mint",
            "burn",
        }
    )


_MOVERS = {"redeem", "mint", "burn", "zap", "convert"}


_TOKEN_ISSUE = {"mint", "_mint", "burn", "_burn", "safeMint", "_safeMint"}


def _is_mover(callee: str, receiver: str | None = None) -> bool:
    """A call that mints, burns, redeems or converts; an unqualified ERC20-style mint or burn is
    bookkeeping."""
    t = set(_tokens(callee))
    if callee[:1].isupper() or not t & _MOVERS or t & _NOT_AN_OPERATION:
        return False
    return not (callee in _TOKEN_ISSUE and receiver in (None, "this", "super"))


_PRICE = {"price", "prices", "rate", "rates", "oracle", "answer", "twap", "quote", "latest"}


def _is_price_read(callee: str) -> bool:
    """A callee that reads a price, a rate, a quote or a TWAP."""
    t = set(_tokens(callee))
    if t & {
        "price",
        "prices",
        "rate",
        "oracle",
        "quote",
        "twap",
        "consult",
        "answer",
        "latest",
        "slot",
    }:
        return True
    return "amounts" in t and bool(t & {"out", "in"})


# --- tree helpers ---------------------------------------------------------------------------------

_STATEMENTS = {
    "expression_statement",
    "variable_declaration_statement",
    "return_statement",
    "emit_statement",
    "revert_statement",
}
_CONDITIONAL = {"if_statement", "while_statement", "for_statement", "do_while_statement"}
_FUNCTIONS = {"function_definition", "modifier_definition", "constructor_definition"}


def _walk(node: Node) -> Iterator[Node]:
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(n.children)


def _statement_of(node: Node) -> tuple[Node | None, bool]:
    """(statement-or-condition node, whether it is a guard) for the place an identifier sits in."""
    guard = False
    prev, cur = node, node.parent
    while cur is not None:
        if cur.type == "call_expression" and not guard:
            callee = next((c for c in cur.children if c.type == "expression"), None)
            guard = callee is not None and callee.text in (b"require", b"assert")
        if cur.type in _STATEMENTS:
            return cur, guard
        if cur.type in _CONDITIONAL and prev.type == "expression":
            return prev, True
        prev, cur = cur, cur.parent
    return None, False


def _enclosing_function(node: Node) -> Node | None:
    cur = node.parent
    while cur is not None and cur.type not in _FUNCTIONS:
        cur = cur.parent
    return cur


def _names_an_error_or_event(node: Node) -> bool:
    p = node.parent
    return (
        p is not None
        and p.type == "expression"
        and p.parent is not None
        and p.parent.type
        in (
            "revert_statement",
            "emit_statement",
        )
    )


_QUOTE_TOKEN = re.compile(r"[A-Za-z_][A-Za-z_0-9]*|\d+|[^\sA-Za-z_0-9]")
_MIN_QUOTE_TOKENS = 6


def _citable_site(parsed: Syntax, lines: list[str], site: Site) -> Site:
    """The smallest enclosing statement or expression whose whole lines are a substantive quote.

    A citation is whole lines and needs at least six tokens, so a struct field or a one-line setter
    is widened to the construct it belongs to (never past its function).
    """
    root = parsed.root
    node = root.descendant_for_byte_range(site.start_byte, site.end_byte)
    current = site
    while True:
        quote = "\n".join(lines[current.start_line - 1 : current.end_line])
        if len(_QUOTE_TOKEN.findall(quote)) >= _MIN_QUOTE_TOKENS:
            return current
        if node is None or node.parent is None or node.type in _FUNCTIONS:
            return current
        node = node.parent
        current = parsed.site_of(node)


# --- the finder -----------------------------------------------------------------------------------

_SITE_WEIGHT = {
    "zero_bound": 9,
    "unused_bound_param": 8,
    "bound_check": 7,
    "bound_computation": 6,
    "exchange_call": 5,
    "bound_use": 4,
    "price_conversion": 3,
    "bound_configuration": 2,
}
_FUNCTION_WEIGHT = {
    "zero_bound": 6.0,
    "unused_bound_param": 4.0,
    "exchange_call": 3.0,
    "bound_check": 2.0,
    "bound_computation": 2.0,
    "price_conversion": 1.5,
    "bound_use": 1.0,
    "bound_configuration": 0.5,
}


def candidates(parsed: Syntax) -> list[Candidate]:
    lines = parsed.lines
    raw: list[tuple[str, Site, dict[str, object]]] = []
    seen: set[tuple[str, int, int]] = set()

    def add(predicate: str, site: Site, **detail: object) -> None:
        if site.host.function is None:
            return
        key = (predicate, site.start_byte, site.end_byte)
        if key not in seen:
            seen.add(key)
            raw.append((predicate, site, detail))

    # What each function does: trades, mints/redeems, measures a receipt; and which locals hold a
    # price it read.
    operates: set[Host] = set()
    price_names: dict[Host, set[str]] = {}
    balance_reads: dict[Host, int] = {}
    for c in parsed.calls:
        host = c.site.host
        if c.callee == "balanceOf":
            balance_reads[host] = balance_reads.get(host, 0) + 1
        if _is_exchange(c.callee) or _is_mover(c.callee, c.receiver):
            operates.add(host)
        if _is_price_read(c.callee):
            price_names.setdefault(host, set()).update(c.bound_names)
    # Receipt measured as a balance difference (read, act, read again) is what a swap or redeem
    # looks like when the operation is an opaque call.
    operates.update(host for host, n in balance_reads.items() if n >= 2)
    for f in parsed.functions:
        if f.site.host.function and _is_exchange(f.site.host.function):
            operates.add(f.site.host)

    def counts(name: str, host: Host) -> bool:
        kind = bound_kind(name)
        return kind == "slippage" or (kind is not None and host in operates)

    # 1. Calls to exchange-like callees; a literal zero argument is where the bound should be.
    for c in parsed.calls:
        exchange, mover = _is_exchange(c.callee), _is_mover(c.callee, c.receiver)
        if not (exchange or mover):
            continue
        zero = [a for a in c.arguments if a.is_zero_literal]
        if zero:
            add("zero_bound", c.site, callee=c.callee, zero_args=len(zero))
        elif exchange or "redeem" in _tokens(c.callee):
            add("exchange_call", c.site, callee=c.callee)

    # 2. Struct fields and locals set to zero where a bound belongs.
    for node in parsed.nodes("call_struct_argument"):
        ident = next((c for c in node.children if c.type == "identifier"), None)
        value = next((c for c in node.children if c.type == "expression"), None)
        if ident is None or value is None:
            continue
        site = parsed.site_of(node)
        if bound_kind(parsed.text(ident)) and _ZERO.fullmatch(parsed.text(value).strip()):
            add("zero_bound", site, field=parsed.text(ident))
    for node in parsed.nodes("variable_declaration_statement", "assignment_expression"):
        if node.type == "variable_declaration_statement":
            decl = next((c for c in node.children if c.type == "variable_declaration"), None)
            name_node = decl.child_by_field_name("name") if decl is not None else None
            value = node.child_by_field_name("value")
        else:
            name_node, value = node.child_by_field_name("left"), node.child_by_field_name("right")
        if name_node is None or value is None:
            continue
        site = parsed.site_of(node)
        name, text = parsed.text(name_node), parsed.text(value).strip()
        if not bound_kind(name):
            continue
        if _ZERO.fullmatch(text):
            add("zero_bound", site, name=name)
        elif text.startswith("new ") and node.type == "variable_declaration_statement":
            # A min/max array allocated and never filled is all zeros.
            fn = _enclosing_function(node)
            filled = fn is not None and any(
                n.type == "assignment_expression"
                and parsed.text(n).replace(" ", "").startswith(name + "[")
                for n in _walk(fn)
            )
            if not filled:
                add("zero_bound", site, name=name, allocated_unfilled=True)

    # 3. Identifiers that spell a bound, cited at their statement (or at the condition they sit in).
    for node in parsed.nodes("identifier"):
        name = parsed.text(node)
        if bound_kind(name) is None or _names_an_error_or_event(node):
            continue
        if node.parent is not None and node.parent.type == "parameter":
            fn = _enclosing_function(node)
            site = parsed.site_of(node)
            if fn is not None and counts(name, site.host):
                reads = sum(
                    1 for n in _walk(fn) if n.type == "identifier" and parsed.text(n) == name
                )
                if reads <= 1:
                    add("unused_bound_param", site, name_kind=bound_kind(name) or "")
            continue
        if node.parent is not None and node.parent.type in _FUNCTIONS:
            continue  # the function's own name
        stmt, guard = _statement_of(node)
        if stmt is None:
            continue
        site = parsed.site_of(stmt)
        if not counts(name, site.host):
            continue
        arithmetic = any(n.type in ("+", "-", "*", "/") for n in _walk(stmt))
        kind = bound_kind(name) or ""
        if guard:
            add("bound_check", site, name_kind=kind)
        elif arithmetic:
            add("bound_computation", site, name_kind=kind)
        elif any(w.writes_state and site.contains(w.site) for w in parsed.writes):
            add("bound_configuration", site, name_kind=kind)
        else:
            add("bound_use", site, name_kind=kind)

    # 3b. A function whose own name spells a bound and which does arithmetic computes that bound.
    for f in parsed.functions:
        name = f.site.host.function or ""
        t = set(_tokens(name))
        spelled = bound_kind(name)
        if spelled is None or t & {"set", "is", "has", "check", "update", "validate"}:
            continue
        inside = [
            a for a in parsed.arithmetic if a.site.host == f.site.host and a.operator in ("*", "/")
        ]
        if inside:
            add("bound_computation", inside[0].site, name_kind=spelled, by_function_name=True)

    # 4. Amounts scaled by a price or rate that this function read from an oracle-like call.
    for a in parsed.arithmetic:
        if a.operator not in ("*", "/") and not set(a.operand_operators) & {"*", "/"}:
            continue
        names = price_names.get(a.site.host)
        if set(_tokens(a.site.host.function or "")) & _PRICE:
            # the function is itself a price accessor: it defines a price rather than converting an
            # amount
            continue
        if names and names & set(_IDENT.findall(a.site.text)):
            add("price_conversion", a.site)

    # Cite each at a whole construct, and weigh each function by how many distinct kinds of signal
    # it holds.
    widened: list[tuple[str, Site, dict[str, object]]] = []
    keys: set[tuple[str, int, int]] = set()
    for predicate, site, detail in raw:
        site = _citable_site(parsed, lines, site)
        key = (predicate, site.start_byte, site.end_byte)
        if key not in keys:
            keys.add(key)
            widened.append((predicate, site, detail))
    score: dict[Host, set[str]] = {}
    for predicate, site, _ in widened:
        score.setdefault(site.host, set()).add(predicate)
    return [
        Candidate(
            predicate,
            site,
            {
                **{k: v for k, v in detail.items() if isinstance(v, str | int | float | bool)},
                "fn_score": sum(_FUNCTION_WEIGHT[p] for p in score[site.host]),
            },
        )
        for predicate, site, detail in widened
    ]


def priority(ref: Candidate) -> float:
    """Functions with more distinct kinds of signal first; within a function, the most specific
    site."""
    return float(ref.detail.get("fn_score", 0.0)) * 100 + _SITE_WEIGHT.get(ref.predicate, 0)
