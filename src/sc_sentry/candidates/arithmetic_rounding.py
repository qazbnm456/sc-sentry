"""arithmetic_rounding: arithmetic whose result is wrong in a direction that matters because of
rounding or truncation.

A function is a candidate when it computes a quantity in a way that loses or reshapes precision: a
quotient that rounds down, a quotient scaled again, a fixed-point or decimals conversion, a cast
that can truncate or change sign, an unchecked block, a shift, a fee taken off an amount. Each
candidate is cited at the whole statement it sits in (widened by neighbouring lines inside its
function if the statement is too short to quote: six tokens, one naming something of the file's
own). Names are split into camelCase / snake_case words and never matched as substrings.

Predicates
  division_before_scaling  a quotient is multiplied again (a / b * c, a.div(b).mul(c)), so its
                           truncation is amplified
  scaled_division          a division in an expression with a power-of-ten or percent-base literal
                           (1e18, 10 ** d, 10000)
  product_division         a division whose numerator is a product, or a mulDiv / wad-math helper
                           call (a * b / c)
  division                 any other division, division-assignment or SafeMath-style div call,
                           except halving a sum
  rounding_helper          a call to a ceil / floor / round-up / round-down named helper
  lossy_cast               a cast of a computed value to a narrower integer or to a signed one (not
                           a literal, a block value, a hash or an address conversion), or a
                           SafeCast-style toUintN call
  unchecked_arithmetic     addition, subtraction, multiplication or power inside an unchecked block
  bit_shift                a right or left shift, which truncates or scales by a power of two
  fee_deduction            a subtraction one of whose operands is named for a fee, tax, premium,
                           discount or refund
  decimals_scaling         a power of ten whose exponent is not a literal (10 ** decimals): a
                           decimals conversion

Ordering (`priority`)
  statements_weighed       the function's score is the sum, over its distinct arithmetic statements,
                           of the weight of the most specific predicate in each
                           (division_before_scaling 3, scaled / product division 2, rounding helper
                           2, division 1.5, casts, shifts, unchecked, fee deduction 1, decimals
                           0.5), capped at 10: a function with more rounding-prone statements is
                           listed first
  most_specific_site       within a function the site cited is the one with the highest weight, then
                           the earliest
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import replace

from tree_sitter import Node

from sc_sentry.candidate import Candidate
from sc_sentry.solidity.syntax import Site, Syntax

_TOKEN = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")
_QTOKEN = re.compile(r"[A-Za-z_][A-Za-z_0-9]*|\d+|[^\sA-Za-z_0-9]")
_IDENT = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")

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

_FUNCTIONS = {
    "function_definition",
    "modifier_definition",
    "constructor_definition",
    "fallback_receive_definition",
}
_STATEMENTS = {
    "expression_statement",
    "variable_declaration_statement",
    "return_statement",
    "emit_statement",
    "revert_statement",
}
_CONDITIONAL = {"if_statement", "while_statement", "for_statement", "do_while_statement"}

_NARROW = re.compile(
    r"u?int(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248)"
)
_SIGNED = frozenset({"int", "int256"})
_SAFECAST = re.compile(r"^to(?:U?Int)\d+$")
_PLAIN_NUMBER = re.compile(r"0[xX][0-9a-fA-F_]+|[\d_.]+(?:[eE]\d+)?")
_NOT_LOSSY_ARGUMENT = re.compile(
    r"block\.(?:timestamp|number|chainid)|keccak|\bbytes\d*\(|\baddress\("
)
_SCALE_LITERAL = re.compile(
    r"(?:1e\d+|10{2,}|\d{1,3}(?:_\d{3})+)(?:\s*(?:wei|gwei|ether))?|\d+\s*ether"
)
_HALF = re.compile(r"\(?\s*2\s*\)?")
_TIME_DELTA = re.compile(r"block\.timestamp")
_ROUNDING_WORDS = frozenset(
    {
        "ceil",
        "floor",
        "round",
        "rounding",
        "up",
        "down",
        "half",
        "nearest",
        "even",
        "trunc",
        "truncate",
        "div",
        "mul",
        "wad",
        "ray",
        "safe",
        "unsafe",
        "to",
        "u",
    }
)
_FEE_WORDS = frozenset(
    {"fee", "fees", "commission", "tax", "premium", "discount", "refund", "royalty", "penalty"}
)

_WEIGHT = {
    "division_before_scaling": 3.0,
    "scaled_division": 2.0,
    "product_division": 2.0,
    "rounding_helper": 2.0,
    "division": 1.5,
    "lossy_cast": 1.0,
    "unchecked_arithmetic": 1.0,
    "bit_shift": 1.0,
    "fee_deduction": 1.0,
    "decimals_scaling": 0.5,
}
_CAP = 10.0


def _tokens(name: str) -> tuple[str, ...]:
    return tuple(t.lower() for part in name.split("_") for t in _TOKEN.findall(part))


def _walk(node: Node) -> Iterator[Node]:
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(n.children)


def _ops(node: Node) -> list[str]:
    return [c.type for c in node.children]


def _inner(node: Node | None) -> Node | None:
    """The expression with its wrapper nodes and parentheses stripped."""
    while node is not None:
        kids = [c for c in node.children if c.type not in ("(", ")")]
        if node.type in ("expression", "parenthesized_expression") and len(kids) == 1:
            node = kids[0]
        else:
            return node
    return node


def _member(function: Node | None) -> tuple[Node | None, Node | None]:
    """(receiver node, member name) of a call's callee when it is `receiver.name`.

    Any other callee gives (None, None).
    """
    inside = _inner(function)
    if inside is not None and inside.type == "member_expression":
        prop = inside.child_by_field_name("property")
        return inside.child_by_field_name("object"), prop
    return None, None


def _arguments(call: Node) -> list[Node]:
    return [c for c in call.children if c.type == "call_argument"]


def _citable(text: str) -> bool:
    """Whether whole lines of this text could be cited.

    They need six tokens, and one of them has to name something of the file's own.
    """
    tokens = _QTOKEN.findall(text)
    return len(tokens) >= 6 and any(
        (t[0].isalpha() or t[0] == "_") and t not in _LANGUAGE for t in tokens
    )


def _is_mul_div_helper(tokens: tuple[str, ...]) -> bool:
    """A product-then-quotient helper: mulDiv, mulDivUp, mulWadDown, divWad, wmul, rdiv, divUp."""
    t = set(tokens)
    if t & {"wmul", "wdiv", "rmul", "rdiv"}:
        return True
    if {"mul", "div"} <= t:
        return True
    return bool(t & {"mul", "div"}) and bool(t & {"wad", "ray", "up", "down"})


def _is_rounding_helper(tokens: tuple[str, ...]) -> bool:
    """A helper named only for the rounding it applies (ceilDiv, roundUp, floor).

    A noun that merely contains the word does not count.
    """
    t = set(tokens)
    if not t or not t <= _ROUNDING_WORDS:
        return False
    return bool(t & {"ceil", "floor"}) or (
        "round" in t and bool(t & {"up", "down", "half", "nearest"} or len(t) == 1)
    )


def candidates(parsed: Syntax) -> list[Candidate]:
    lines = parsed.lines  # the whole file: the root node skips leading blank lines
    raw: list[tuple[str, Site, int, dict[str, object]]] = []
    seen: set[tuple[str, int, int]] = set()

    def statement_of(node: Node) -> Node:
        prev, cur = node, node.parent
        while cur is not None:
            if cur.type in _STATEMENTS:
                return cur
            if cur.type in _CONDITIONAL and prev.type == "expression":
                return prev
            if cur.type in _FUNCTIONS:
                return node
            prev, cur = cur, cur.parent
        return node

    def widened(site: Site) -> Site:
        """`site`, widened to the whole lines around it inside its function until they quote."""
        enclosing = parsed.callable_at(site.start_line)
        span = (enclosing.start_line, enclosing.end_line) if enclosing is not None else None
        lo, hi = site.start_line, site.end_line
        for _ in range(4):
            text = "\n".join(lines[lo - 1 : hi])
            if _citable(text):
                if (lo, hi) == (site.start_line, site.end_line):
                    return site
                return replace(
                    site, start_line=lo, end_line=hi, text=text, start_byte=-1, end_byte=-1
                )
            if span is None:
                break
            if lo > span[0] + 1:
                lo -= 1
            elif hi < span[1]:
                hi += 1
        return site

    def add(predicate: str, node: Node, **detail: object) -> None:
        statement = parsed.site_of(statement_of(node))
        if statement.host.function is None:
            return
        key = (predicate, statement.start_byte, statement.end_byte)
        if key in seen:
            return
        seen.add(key)
        # A long statement (an emit, a call with many arguments) is cited at the expression.
        site = parsed.site_of(node) if statement.end_line - statement.start_line >= 4 else statement
        raw.append((predicate, site, statement.start_line, detail))

    def scaled(node: Node) -> bool:
        for n in _walk(node):
            if n.type == "number_literal" and _SCALE_LITERAL.fullmatch(parsed.text(n).strip()):
                return True
            if n.type == "binary_expression" and "**" in _ops(n):
                return True
        return False

    def multiplies(node: Node) -> bool:
        for m in _walk(node):
            if m.type == "binary_expression" and "*" in _ops(m):
                return True
            if m.type == "call_expression":
                fn = m.child_by_field_name("function")
                if fn is not None and "mul" in _tokens(
                    parsed.text(fn).split(".")[-1].split("{")[0].strip()
                ):
                    return True
        return False

    def divide(node: Node, numerator: Node, denominator: Node) -> None:
        if (
            _HALF.fullmatch(parsed.text(denominator).strip())
            and not multiplies(numerator)
            and not scaled(node)
        ):
            return  # halving a sum or a difference: a midpoint, not a rounded quantity
        add(
            "scaled_division"
            if scaled(node)
            else "product_division"
            if multiplies(numerator)
            else "division",
            node,
        )

    for n in parsed.nodes(
        "binary_expression",
        "augmented_assignment_expression",
        "type_cast_expression",
        "call_expression",
        "block_statement",
    ):
        t = n.type
        if t == "binary_expression":
            op = next(
                (c.type for c in n.children if c.type in ("*", "/", "-", "**", "<<", ">>")), None
            )
            parts = [c for c in n.children if c.type == "expression"]
            if op == "*":
                for operand in parts:
                    inside = _inner(operand)
                    if (
                        inside is not None
                        and inside.type == "binary_expression"
                        and "/" in _ops(inside)
                    ):
                        quotient = [
                            parsed.text(c).strip()
                            for c in inside.children
                            if c.type == "expression"
                        ]
                        others = [parsed.text(c).strip() for c in parts if c is not operand]
                        if not (
                            len(quotient) == 2 and quotient[1] in others
                        ):  # (a / b) * b rounds to a multiple on purpose
                            add("division_before_scaling", n)
                            break
            elif op == "/" and len(parts) == 2:
                divide(n, parts[0], parts[1])
            elif op in ("<<", ">>"):
                add("bit_shift", n)
            elif op == "**" and len(parts) == 2:
                if parsed.text(parts[0]).strip() == "10" and not re.fullmatch(
                    r"\(?\s*\d+\s*\)?", parsed.text(parts[1]).strip()
                ):
                    add("decimals_scaling", n)
            elif op == "-":
                text = parsed.text(n)
                if (
                    not _TIME_DELTA.search(text)
                    and {w for i in _IDENT.findall(text) for w in _tokens(i)} & _FEE_WORDS
                ):
                    add("fee_deduction", n)
        elif t == "augmented_assignment_expression":
            op = next((c.type for c in n.children if c.type in ("/=", ">>=", "<<=")), None)
            parts = [c for c in n.children if c.type == "expression"]
            if op == "/=" and len(parts) == 2:
                divide(n, parts[0], parts[1])
            elif op in (">>=", "<<="):
                add("bit_shift", n)
        elif t == "type_cast_expression" and n.children:
            target = parsed.text(n.children[0])
            args = [c for c in n.children if c.type == "call_argument"]
            argument = parsed.text(args[0]).strip() if args else ""
            if (_NARROW.fullmatch(target) or target in _SIGNED) and not _PLAIN_NUMBER.fullmatch(
                argument
            ):
                holder = n.parent
                while holder is not None and holder.type in (
                    "expression",
                    "call_argument",
                    "parenthesized_expression",
                ):
                    holder = holder.parent
                converts_address = (
                    holder is not None
                    and holder.type == "type_cast_expression"
                    and parsed.text(holder.children[0]) in ("address", "payable")
                )
                if _NOT_LOSSY_ARGUMENT.search(argument) or converts_address:
                    continue
                add("lossy_cast", n, to=target)
        elif t == "call_expression":
            function = n.child_by_field_name("function")
            if function is None:
                continue
            text = parsed.text(function)
            name = text.split(".")[-1].split("{")[0].strip()
            tokens = _tokens(name)
            if _SAFECAST.match(name):
                add("lossy_cast", n, to=name)
            elif _is_rounding_helper(tokens):
                add("rounding_helper", n, callee=name)
            elif _is_mul_div_helper(tokens):
                add("product_division", n, callee=name)
            elif name == "div":
                receiver, _ = _member(function)
                args = _arguments(n)
                if receiver is not None and args:
                    divide(n, receiver, args[0])
            elif name == "mul":
                receiver, _ = _member(function)
                inside = _inner(receiver) if receiver is not None else None
                if inside is not None and inside.type == "call_expression":
                    _, inner_name = _member(inside.child_by_field_name("function"))
                    if inner_name is not None and parsed.text(inner_name) == "div":
                        divisor = [parsed.text(a).strip() for a in _arguments(inside)]
                        factor = [parsed.text(a).strip() for a in _arguments(n)]
                        if divisor != factor:
                            add("division_before_scaling", n)
        elif t == "block_statement" and any(c.type == "unchecked" for c in n.children):
            for m in _walk(n):
                if m.type in ("binary_expression", "augmented_assignment_expression") and any(
                    c.type in ("+", "-", "*", "**", "+=", "-=", "*=") for c in m.children
                ):
                    add("unchecked_arithmetic", m)
                    break

    # Weigh each function by its distinct rounding-prone statements, each at its most specific
    # predicate.
    best: dict[tuple[str | None, str | None], dict[int, float]] = {}
    for predicate, site, statement_line, _ in raw:
        per_statement = best.setdefault((site.host.contract, site.host.function), {})
        per_statement[statement_line] = max(
            per_statement.get(statement_line, 0.0), _WEIGHT[predicate]
        )
    score = {key: min(sum(per_statement.values()), _CAP) for key, per_statement in best.items()}

    return [
        Candidate(
            predicate,
            widened(site),
            {
                **{k: v for k, v in detail.items() if isinstance(v, str | int | float | bool)},
                "fn_score": score[(site.host.contract, site.host.function)],
            },
        )
        for predicate, site, _, detail in raw
    ]


def priority(ref: Candidate) -> float:
    """Functions with more rounding-prone statements first.

    Within a function, the most specific site comes first.
    """
    return float(ref.detail.get("fn_score", 0.0)) * 100 + _WEIGHT.get(ref.predicate, 0.0)
