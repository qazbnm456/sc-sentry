"""Widening a site until its whole lines are a quote the benchmark will accept.

A citation is whole lines of the source, and the benchmark refuses one that is shorter than six
tokens or names nothing the language does not supply: a quote of keywords and punctuation names no
file in particular. A finding at `owner = o;` or at a bare call is therefore a finding that was
right and scored nothing, so a site is widened to the smallest enclosing statement or expression
whose lines pass, and never past the function it sits in.
"""

from __future__ import annotations

import re

from sc_sentry.solidity import Site, Syntax

__all__ = ["citable_site", "is_substantive"]

_TOKEN = re.compile(r"[A-Za-z_][A-Za-z_0-9]*|\d+|[^\sA-Za-z_0-9]")
_MINIMUM_TOKENS = 6
_FUNCTION_NODES = frozenset(
    {"function_definition", "modifier_definition", "constructor_definition"}
)
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


def is_substantive(text: str) -> bool:
    """Whether these lines are a quote the benchmark accepts: six tokens, one the file's own."""
    tokens = _TOKEN.findall(text)
    return len(tokens) >= _MINIMUM_TOKENS and any(
        (t[0].isalpha() or t[0] == "_") and t not in _LANGUAGE for t in tokens
    )


def citable_site(parsed: Syntax, site: Site) -> Site:
    """`site`, or the smallest enclosing construct whose whole lines are substantive."""
    node = parsed.root.descendant_for_byte_range(site.start_byte, site.end_byte)
    current = site
    while True:
        quote = "\n".join(parsed.lines[current.start_line - 1 : current.end_line])
        if is_substantive(quote):
            return current
        if node is None or node.parent is None or node.type in _FUNCTION_NODES:
            return current
        node = node.parent
        current = parsed.site_of(node)
