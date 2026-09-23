"""Syntactic backend: what a Solidity file declares, and where.

This is the floor. It requires no compiler, no dependency resolution and no
network, so it is available for every source unit regardless of whether the
project builds. Everything that needs types, data flow or a call graph belongs
to the semantic backend; everything that needs only "is this symbol declared
here, and where" belongs here.

Why a parser and not a pattern match
------------------------------------
Text matching cannot tell a declaration from a mention of one. These all contain
the characters of a declaration and none of them declares anything::

    // The old function withdraw() used to live here
    /* function drain() external { selfdestruct(x); } */
    require(ok, "function withdraw() reverted");

A verifier built on text matching certifies locations that contain no code,
which is the opposite of its purpose. It also *rejects* real declarations that
do not fit the pattern -- a modern `constructor(address owner)` carries no
visibility keyword and no `function` keyword, so exactly the access-control
cases most worth annotating are the ones it turns away.

The parser is error-tolerant. A file with a syntax error still yields the
declarations it could read, which matters because corpus sources are pinned at
historical commits and may predate or postdate any given grammar revision.

Why a name is not an identity
-----------------------------
Solidity permits overloading, so a function name does not identify a function.
A contract declaring both ``swap(uint256)`` and ``swap(uint256,address)`` has two
different functions that a name-keyed index cannot tell apart, and every
consequence of that confusion runs in the direction this project exists to
prevent: a record can be verified against the overload it did not mean, and a
detector pointing at the wrong overload matches ground truth on the name it
shares. Declarations therefore carry their parameter types.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tree_sitter import Node, Parser, Tree

__all__ = [
    "NODE_KINDS",
    "Declaration",
    "DeclarationIndex",
    "DeclarationKind",
    "SolidityUnavailable",
    "index_source",
    "parse_bytes",
]


class SolidityUnavailable(RuntimeError):
    """The syntactic backend could not be loaded."""


class DeclarationKind(StrEnum):
    CONTRACT = "contract"
    LIBRARY = "library"
    INTERFACE = "interface"
    FUNCTION = "function"
    CONSTRUCTOR = "constructor"
    MODIFIER = "modifier"
    RECEIVE_OR_FALLBACK = "receive_or_fallback"

    @property
    def is_type(self) -> bool:
        return self in (
            DeclarationKind.CONTRACT,
            DeclarationKind.LIBRARY,
            DeclarationKind.INTERFACE,
        )


# Nodes whose presence we care about, and the kind each maps to. The grammar
# emits a single node type for `receive` and `fallback`; both are unnamed in the
# source, so a synthetic name is supplied below.
#
# Public because the shape-query layer needs the same answer to "is this node a
# declaration, and of what kind". Two modules maintaining private copies of that
# question is how they come to disagree about it.
NODE_KINDS: dict[str, DeclarationKind] = {
    "contract_declaration": DeclarationKind.CONTRACT,
    "library_declaration": DeclarationKind.LIBRARY,
    "interface_declaration": DeclarationKind.INTERFACE,
    "function_definition": DeclarationKind.FUNCTION,
    "constructor_definition": DeclarationKind.CONSTRUCTOR,
    "modifier_definition": DeclarationKind.MODIFIER,
    "fallback_receive_definition": DeclarationKind.RECEIVE_OR_FALLBACK,
}

# Declarations the grammar leaves unnamed, because the keyword *is* the name.
_IMPLICIT_NAMES: dict[DeclarationKind, tuple[str, ...]] = {
    DeclarationKind.CONSTRUCTOR: ("constructor",),
    DeclarationKind.RECEIVE_OR_FALLBACK: ("receive", "fallback"),
}


@dataclass(frozen=True, slots=True)
class Declaration:
    """One declaration, its 1-indexed inclusive line span, and its enclosing type."""

    kind: DeclarationKind
    names: tuple[str, ...]
    start_line: int
    end_line: int
    parent: str | None
    parameter_types: tuple[str, ...] = ()
    """Declared parameter types, in order. Empty for a type declaration."""

    def is_named(self, name: str) -> bool:
        return name in self.names

    @property
    def arity(self) -> int:
        """Number of declared parameters."""
        return len(self.parameter_types)

    @property
    def signature(self) -> str:
        """The declaration as written, e.g. ``swap(uint256,address)``.

        This is the *declared* form, not the ABI-canonical one. `uint` and
        `uint256` are the same ABI type but different declared text, so this
        string must not be fed to a selector computation, which needs real
        canonicalisation (`uint` widened, enums to `uint8`, structs to tuples).

        It is nonetheless sufficient for the job it is used for -- telling two
        declarations in the same file apart -- because the compiler rejects a
        contract that declares the same signature twice. Two overloads that
        survive compilation necessarily differ in their parameter types, and
        therefore in this string.

        Degenerate for a type declaration, which has no parameters: a contract
        named `Vault` yields `Vault()`. Reach for it through `callables`, which
        only ever returns function-like declarations.
        """
        return f"{self.names[0]}({','.join(self.parameter_types)})"

    def spans(self, start_line: int, end_line: int) -> bool:
        """True if this declaration's span intersects the given one."""
        return self.start_line <= end_line and start_line <= self.end_line


def parse_bytes(data: bytes) -> Tree:
    """Parse UTF-8 source bytes. Never raises on malformed input.

    Callers pass bytes rather than `str` and keep them, because every node
    position is a byte offset into exactly these bytes. Re-encoding the same
    `str` a second time to read a node's text is safe only as long as both
    encodings agree, and a caller that slices a different buffer gets silently
    shifted text.
    """
    return _parser().parse(data)


@lru_cache(maxsize=1)
def _parser() -> Parser:
    try:
        import tree_sitter_solidity
        from tree_sitter import Language
        from tree_sitter import Parser as TSParser
    except ImportError as exc:  # pragma: no cover - exercised only without the dep
        raise SolidityUnavailable(
            "the syntactic backend requires tree-sitter and tree-sitter-solidity"
        ) from exc

    with warnings.catch_warnings():
        # tree-sitter-solidity still hands back an int rather than a capsule.
        # Harmless, and not ours to fix; suppressed so it does not surface on
        # every parse.
        warnings.simplefilter("ignore", DeprecationWarning)
        language = Language(tree_sitter_solidity.language())

    return TSParser(language)


@dataclass(frozen=True, slots=True)
class DeclarationIndex:
    """Every declaration in one source file.

    `parsed` is False when the file yielded nothing a parser could recognise.
    Callers that verify ground truth must treat that as a refusal to confirm,
    not as an absence of the symbol: "I could not read this" and "this is not
    here" are different answers, and only the second is evidence.
    """

    declarations: tuple[Declaration, ...]
    parsed: bool

    def types(self, name: str) -> list[Declaration]:
        return [d for d in self.declarations if d.kind.is_type and d.is_named(name)]

    def declares_type(self, name: str) -> bool:
        return bool(self.types(name))

    def callables(
        self,
        name: str,
        *,
        within: tuple[int, int] | None = None,
        inside_type: str | None = None,
        signature: str | None = None,
    ) -> list[Declaration]:
        """Function-like declarations matching `name`, optionally constrained.

        `within` restricts to declarations whose span intersects a line range;
        `inside_type` restricts to those lexically inside a named contract,
        library or interface; `signature` restricts to one overload, given as
        the declared form (see `Declaration.signature`).

        More than one result means the name is overloaded across whatever
        constraints were given. A caller that needs to identify a single
        function must narrow further or treat the name as ambiguous -- picking
        the first would silently choose an overload.
        """
        found = [d for d in self.declarations if not d.kind.is_type and d.is_named(name)]
        if within is not None:
            found = [d for d in found if d.spans(*within)]
        if inside_type is not None:
            found = [d for d in found if d.parent == inside_type]
        if signature is not None:
            found = [d for d in found if d.signature == signature]
        return found


def _name_of(node: Node, source: bytes, kind: DeclarationKind) -> tuple[str, ...]:
    if implicit := _IMPLICIT_NAMES.get(kind):
        return implicit
    name_node = node.child_by_field_name("name")
    if name_node is None:
        return ()
    return (source[name_node.start_byte : name_node.end_byte].decode("utf-8", "replace"),)


def _parameter_types(node: Node, source: bytes) -> tuple[str, ...]:
    """Declared parameter types, in order.

    The grammar hangs `parameter` nodes directly off the definition rather than
    wrapping them in a parameter list, so they are read from the children.

    Runs of whitespace inside a type are collapsed to one space rather than
    removed. Removing them would fuse adjacent keywords in a function type into
    a single token, and collapsing is enough: the two spellings this leaves
    distinct, `mapping(address => uint256)` and `mapping(address=>uint256)`,
    cannot both appear as overloads of one function, because the compiler sees
    one signature and rejects the duplicate.
    """
    found: list[str] = []
    for child in node.children:
        if child.type != "parameter":
            continue
        type_node = child.child_by_field_name("type")
        if type_node is None:  # pragma: no cover - no current grammar path reaches it
            # Unreachable with the pinned grammar, which attaches a type to every
            # `parameter` node it emits -- even on malformed input, where it reads
            # a bare name as a type. Kept because this module promises never to
            # raise on malformed input, and corpus sources are pinned at
            # historical commits across grammar revisions.
            continue
        text = source[type_node.start_byte : type_node.end_byte].decode("utf-8", "replace")
        found.append(" ".join(text.split()))
    return tuple(found)


def index_source(source: str) -> DeclarationIndex:
    """Parse `source` and index every declaration it contains.

    Never raises on malformed input: a file the grammar cannot fully read still
    yields whatever declarations it recovered, with `parsed` reflecting whether
    anything was recognised at all.
    """
    if not source.strip():
        return DeclarationIndex(declarations=(), parsed=False)

    data = source.encode("utf-8")
    tree = parse_bytes(data)

    found: list[Declaration] = []
    # Explicit stack rather than recursion: contract sources are occasionally
    # deep enough to matter, and a parse must not be able to exhaust the stack.
    stack: list[tuple[Node, str | None]] = [(tree.root_node, None)]
    while stack:
        node, parent = stack.pop()
        enclosing = parent

        if (kind := NODE_KINDS.get(node.type)) is not None:
            names = _name_of(node, data, kind)
            if names:
                found.append(
                    Declaration(
                        kind=kind,
                        names=names,
                        start_line=node.start_point[0] + 1,
                        end_line=node.end_point[0] + 1,
                        parent=parent,
                        parameter_types=() if kind.is_type else _parameter_types(node, data),
                    )
                )
            if kind.is_type and names:
                enclosing = names[0]

        stack.extend((child, enclosing) for child in reversed(node.children))

    found.sort(key=lambda d: (d.start_line, d.end_line))
    return DeclarationIndex(declarations=tuple(found), parsed=bool(found))
