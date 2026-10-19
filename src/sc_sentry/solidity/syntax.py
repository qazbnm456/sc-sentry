"""Shape-level queries over a parsed source unit.

The declaration index answers one question: what does this file declare, and where. Predicates need
more than that: where the calls are, what is passed to them, what is written, which functions are
reachable from outside, and what guards them. This module answers those questions.

Everything here is syntactic. There are no types, no data flow and no call graph, so a query can say
"this argument is the literal zero" but never "this argument is always zero at run time". The
distinction matters, because a fact established here is weaker than the same fact established from
compiled output.

Shapes, not names
-----------------
An identifier is chosen by whoever wrote the contract and can be changed without changing behaviour,
so a query keyed on one measures naming habits rather than code. The queries below are therefore
keyed on node shape and on *language* tokens (`call`, `delegatecall`, `block.timestamp`,
`external`), which no author can rename because they are not theirs to rename.

Where a user identifier is unavoidable, it is carried as a separate field and labelled as such, so
that a caller can correlate on it without being tempted to report it. Solidity is case-sensitive
throughout: nothing here case-folds an identifier, because `owner` and `Owner` are different symbols
and folding them manufactures matches the compiler would never make.

Every site carries its host
---------------------------
A site without an enclosing contract and function is nearly useless downstream: scoring is at
function granularity, so evidence that knows only a line number cannot be compared against anything.
Host resolution reuses the declaration index rather than re-deriving scope: the innermost callable
whose span contains a node is its host, which is unambiguous because Solidity has no nested
functions.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from functools import cached_property
from typing import TYPE_CHECKING

from sc_sentry.solidity.parser import (
    Declaration,
    DeclarationIndex,
    index_source,
    parse_bytes,
)

if TYPE_CHECKING:
    from tree_sitter import Node

__all__ = [
    "CHAIN_STATE_MEMBERS",
    "LOW_LEVEL_CALL_MEMBERS",
    "VALUE_TRANSFER_MEMBERS",
    "Argument",
    "CallSite",
    "FunctionSite",
    "Host",
    "Site",
    "Syntax",
    "WriteSite",
    "WriteTarget",
]


LOW_LEVEL_CALL_MEMBERS = frozenset({"call", "delegatecall", "staticcall", "callcode"})
"""Members whose result is a success flag the caller must inspect.

Language members, not identifiers: a contract cannot rename `delegatecall`, so matching on these is
renaming-invariant in a way that matching on a helper's name never is.
"""

VALUE_TRANSFER_MEMBERS = frozenset({"send", "transfer"})
"""Value-moving members. `send` returns a flag; `transfer` reverts instead."""

CHAIN_STATE_MEMBERS: dict[str, frozenset[str]] = {
    "block": frozenset(
        {"timestamp", "number", "difficulty", "prevrandao", "coinbase", "gaslimit", "basefee"}
    ),
    "tx": frozenset({"gasprice", "origin"}),
}
"""Chain state readable from a contract and influenced by whoever orders the block.

Grouped by receiver so that a query matches `block.timestamp` as a shape rather than searching for
the word `timestamp`, which a local variable may also carry.
"""

_NUMBER_UNITS = frozenset(
    {
        "wei",
        "gwei",
        "szabo",
        "finney",
        "ether",
        "seconds",
        "minutes",
        "hours",
        "days",
        "weeks",
        "years",
    }
)
"""Denomination suffixes a numeric literal may carry.

They have to be stripped before a literal can be compared to zero. `0 ether` is zero, and a check
that only understood bare digits would read it as not-a-number and report the same coverage while
missing the case.
"""

_BARE_STATEMENT = "expression_statement"

# The grammar wraps most expressions in an `expression` node, so an ancestor walk has to step over
# them to find the statement an expression belongs to.
_TRANSPARENT = frozenset({"expression"})


@dataclass(frozen=True, slots=True)
class Host:
    """The contract and function a site sits inside.

    `function_signature` is the declared form, which is what distinguishes one overload from
    another. `function` alone does not: Solidity permits overloading, so two different functions can
    share a name.
    """

    contract: str | None
    function: str | None
    function_signature: str | None


@dataclass(frozen=True, slots=True)
class Locator:
    """Where a site is: a file, its host contract and function, and a line span."""

    file: str
    contract: str | None
    function: str | None
    start_line: int
    end_line: int


@dataclass(frozen=True, slots=True)
class Site:
    """One node of interest, with where it is."""

    node_type: str
    text: str
    start_line: int
    end_line: int
    host: Host

    start_byte: int = -1
    end_byte: int = -1
    """Byte offsets, for asking whether one site is *inside* another.

    Lines cannot answer that, because two nodes on one line contain each other by line number. A
    line-only check makes "the selection contains the read" mean "they share a line", and
    `lastEarn[token][id] = block.timestamp;` then reads as a timestamp used as an index, which over
    one corpus is 21 of 88 sites.

    Defaulted to -1 so a `Site` built without them answers `contains` as false rather than as true,
    which is the direction that refuses rather than asserts.
    """

    def contains(self, other: Site) -> bool:
        """Whether `other` lies inside this site's own extent."""
        if self.start_byte < 0 or other.start_byte < 0:
            return False
        return self.start_byte <= other.start_byte and other.end_byte <= self.end_byte

    def locator(self, file: str) -> Locator:
        """A `Locator` for this site, naming its host contract and function."""
        return Locator(
            file=file,
            contract=self.host.contract,
            function=self.host.function,
            start_line=self.start_line,
            end_line=self.end_line,
        )


@dataclass(frozen=True, slots=True)
class Argument:
    """One positional call argument, described by shape."""

    position: int
    text: str
    node_type: str

    @property
    def is_number_literal(self) -> bool:
        return self.node_type == "number_literal"

    @property
    def is_zero_literal(self) -> bool:
        """True for a literal zero in any of the spellings the compiler accepts.

        `0`, `0x0`, `0x0000...` and `0 ether` are the same value written four ways, and a check that
        recognised only the first would miss the rest while reporting the same coverage.
        """
        if not self.is_number_literal:
            return False
        text = self.text.replace("_", "").strip().lower()
        parts = text.split()
        if len(parts) == 2 and parts[1] in _NUMBER_UNITS:
            text = parts[0]
        elif len(parts) != 1:
            return False
        if text.startswith(("0x", "0b", "0o")):
            body = text[2:]
            return bool(body) and set(body) == {"0"}
        try:
            return float(text) == 0.0
        except ValueError:  # pragma: no cover - no current grammar path reaches it
            # Unreachable with the pinned grammar: anything it labels a `number_literal` parses, and
            # malformed text such as `1e` is labelled an identifier instead. Kept because the
            # alternative to a guard here is a crash inside a predicate.
            return False

    @property
    def is_identifier(self) -> bool:
        return self.node_type == "identifier"


@dataclass(frozen=True, slots=True)
class CallSite:
    """One call, described by what is being called and how."""

    site: Site
    callee: str
    """The member name, or the plain function name for an unqualified call."""

    receiver: str | None
    """Text of the part before the dot, or None for an unqualified call.

    A user identifier in most cases, so it is here to be correlated on, not to be reported.
    """

    arguments: tuple[Argument, ...]
    is_bare_statement: bool
    """True when the call is an entire statement, so its result is discarded."""

    has_call_options: bool
    """True when the call carries `{value: ...}` or `{gas: ...}` options."""

    bound_names: tuple[str, ...]
    """Names the call's result is bound to. Empty when the result is discarded.

    These are user identifiers, so they are for correlating inside a function (asking whether a
    bound result is ever read again) and not for reporting.
    """

    @property
    def is_low_level(self) -> bool:
        return self.callee in LOW_LEVEL_CALL_MEMBERS

    @property
    def is_value_transfer(self) -> bool:
        return self.callee in VALUE_TRANSFER_MEMBERS

    def argument(self, position: int) -> Argument | None:
        return next((a for a in self.arguments if a.position == position), None)


class WriteTarget:
    """What an assignment writes to, as a shape rather than a name."""

    STATE_VARIABLE = "state_variable"
    STATE_COLLECTION_ELEMENT = "state_collection_element"
    STATE_MEMBER = "state_member"
    LOCAL = "local"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class WriteSite:
    """One assignment, and what kind of thing it writes to."""

    site: Site
    target: str
    """A `WriteTarget` constant."""

    target_root: str
    """Base identifier written through. A user identifier: correlate, do not report."""

    operator: str
    """The assignment operator as written, e.g. `=` or `-=`. A language token."""

    @property
    def writes_state(self) -> bool:
        return self.target in (
            WriteTarget.STATE_VARIABLE,
            WriteTarget.STATE_COLLECTION_ELEMENT,
            WriteTarget.STATE_MEMBER,
        )


_HASHES = frozenset({"keccak256", "sha256", "ripemd160", "sha3", "blockhash"})
"""Calls that turn a value into an unpredictable-looking one."""

_ARITHMETIC_OPERATORS = frozenset({"*", "/", "%", "+", "-", "**", "<<", ">>"})


def _normalised(text: str) -> str:
    """Whitespace collapsed and redundant outer parentheses removed.

    Enough for `(WEEK)` and `WEEK ` to compare equal, and deliberately no more: an expression
    normaliser that tried to see through arithmetic would be deciding value identity, which is a
    different and much larger claim.
    """
    stripped = " ".join(text.split())
    while stripped.startswith("(") and stripped.endswith(")") and stripped.count("(") == 1:
        stripped = stripped[1:-1].strip()
    return stripped


@dataclass(frozen=True, slots=True)
class LoopSite:
    """One loop, described by what bounds it rather than by what it does."""

    site: Site
    bound_identifiers: tuple[str, ...]
    """Identifiers in the continuation condition. For correlation, never for reporting."""


@dataclass(frozen=True, slots=True)
class Destructuring:
    """One multi-return unpacked into named bindings."""

    site: Site
    bindings: tuple[tuple[str, str], ...]
    """(declared type, name) for each *named* binding, in source order."""

    source_text: str
    """The expression the values came from. Diagnostic: never correlate on text."""

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(name for _, name in self.bindings)


@dataclass(frozen=True, slots=True)
class ArithmeticSite:
    """One binary arithmetic expression, its operator, and what it divides by."""

    site: Site
    operator: str
    operand_operators: tuple[str, ...]

    divisors: tuple[str, ...] = ()
    """What a divided operand of this expression divided by, normalised.

    The text is compared for *identity*, which is a shape question (did this divide and then
    multiply by the same thing?) and not a name lookup, because no external list of names is
    consulted. What text comparison costs is a divisor and a multiplier that are the same value
    written differently, `WEEK` against `7 days`. Those are not recognised as identical, so the
    expression is reported, which is the safe direction: evidence over-reports and the verdict layer
    is the strict side.
    """

    multipliers: tuple[str, ...] = ()
    """What this expression multiplies by, normalised the same way."""

    @property
    def divides_then_scales(self) -> bool:
        """Whether it multiplies a divided value by something *else*.

        `(a / b) * b` rounds down to a multiple of `b`, and the truncation is intended: an epoch
        boundary or a tick size. `(a / b) * c` discards precision that `(a * c) / b` would have
        kept, and only the second is the property this class is about. Over one corpus, treating the
        two alike makes the rounding idiom twenty-two of twenty-six reported sites.
        """
        return bool(self.divisors) and bool(set(self.multipliers) - set(self.divisors))


@dataclass(frozen=True, slots=True)
class GuardSite:
    """One condition that decides whether execution proceeds."""

    site: Site
    identifiers: tuple[str, ...]
    """Every identifier the condition mentions, sorted and deduplicated.

    For correlation, never for reporting: these are user identifiers. They tell a guard from a
    mention, that is, whether the thing `msg.sender` is compared against is something the caller
    supplied.
    """

    call_receivers: tuple[str, ...] = ()
    """Identifiers appearing in the *receiver* position of a call in this condition.

    This field makes a distinction that a flat list of identifiers cannot. A condition may mention
    something the caller supplied in two quite different roles:

    *   as the **subject** of a check, as in `isApprovedOrOwner(msg.sender, id)`, where the caller
        passes an id and the contract resolves it against its own state. That guard is sound.
    *   as the **address answered from**, as in `IVisor(from).owner() == msg.sender`, where the
        contract asks a caller-chosen contract to adjudicate a check on itself. That guard is
        satisfiable by construction.

    Over the corpus, treating the two alike fires nineteen times where the sharper property fires
    twice, and seventeen of the nineteen are sound guards.
    """

    def reads_any(self, names: Iterable[str]) -> bool:
        return bool(frozenset(self.identifiers) & frozenset(names))

    def answers_from_any(self, names: Iterable[str]) -> bool:
        return bool(frozenset(self.call_receivers) & frozenset(names))


@dataclass(frozen=True, slots=True)
class FunctionSite:
    """One function-like declaration, with what the language says about its reach."""

    site: Site
    declaration: Declaration
    visibility: str | None
    """`external`, `public`, `internal`, `private`, or None when not written.

    None is not the same as private. Before Solidity 0.5 an omitted visibility defaulted to public,
    and corpus sources are pinned at historical commits, so reading the absence as restrictive would
    silently exempt the most exposed functions in exactly the oldest code.
    """

    state_mutability: str | None
    modifiers: tuple[str, ...]
    """Modifier invocations as written. User identifiers: correlate, do not report."""

    parameter_names: tuple[str, ...] = ()
    """Names of the declared parameters, in order.

    Kept apart from `Declaration.parameter_types`, which identifies the function for overload
    resolution and must be stable under a rename. These are for *correlation*: a value an outside
    caller supplied enters the function under one of these names, so an expression mentioning one is
    an expression reading something the caller chose. That is the shallowest useful form of taint,
    and it needs no types and no compiled backend.

    These are user identifiers, so correlate on them and do not report them.
    """

    returns_value: bool = False
    """True when the declaration has a `returns (...)` clause, so a caller can discard something."""

    @property
    def is_externally_reachable(self) -> bool:
        """True when the language permits an outside caller, absent visibility included."""
        return self.visibility in (None, "external", "public")

    @property
    def is_read_only(self) -> bool:
        return self.state_mutability in ("view", "pure", "constant")


class Syntax:
    """A parsed source unit, queryable by shape.

    Construct with `Syntax.of(source)`. Queries are computed once and cached, because a detector
    runs several predicates over the same unit and each one would otherwise re-walk the whole tree.
    """

    def __init__(self, source: str) -> None:
        self._data = source.encode("utf-8")
        self._tree = parse_bytes(self._data)
        self.index: DeclarationIndex = index_source(source)

    @classmethod
    def of(cls, source: str) -> Syntax | None:
        """Parse `source`, or return None if nothing could be read from it.

        None means "this unit is not analysable", which the caller handles. It is deliberately
        different from an empty query result, which means the unit was read and the shape is not
        present.
        """
        syntax = cls(source)
        return syntax if syntax.index.parsed else None

    # -- primitives -------------------------------------------------------

    def text(self, node: Node) -> str:
        return self._data[node.start_byte : node.end_byte].decode("utf-8", "replace")

    @cached_property
    def lines(self) -> list[str]:
        """The source split into lines, so a citation can be read back as whole lines."""
        return self._data.decode("utf-8", "replace").split("\n")

    @property
    def root(self) -> Node:
        return self._tree.root_node

    def nodes(self, *types: str) -> list[Node]:
        """Every node of these tree-sitter types, in source order."""
        return self._nodes(*types)

    def site_of(self, node: Node) -> Site:
        """A syntax node as a site: its text, its lines and the callable it sits in."""
        return self._site(node)

    def _nodes(self, *types: str) -> list[Node]:
        wanted = frozenset(types)
        found: list[Node] = []
        stack: list[Node] = [self._tree.root_node]
        while stack:
            node = stack.pop()
            if node.type in wanted:
                found.append(node)
            stack.extend(reversed(node.children))
        found.sort(key=lambda n: (n.start_point[0], n.start_byte))
        return found

    def _site(self, node: Node) -> Site:
        return Site(
            node_type=str(node.type),
            text=self.text(node),
            start_line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            host=self.host_at(node.start_point[0] + 1),
            start_byte=node.start_byte,
            end_byte=node.end_byte,
        )

    def host_at(self, line: int) -> Host:
        """The innermost contract and callable whose span contains `line`."""
        return self._hosts.get(line, Host(None, None, None))

    @cached_property
    def _hosts(self) -> dict[int, Host]:
        """Host per line, precomputed.

        A dict rather than a scan per node: several predicates each resolve a host for every site
        they find, and repeating a linear scan over all declarations for each one is the shape of an
        accidental quadratic.
        """
        spans = {
            line: Host(None, None, None)
            for decl in self.index.declarations
            for line in range(decl.start_line, decl.end_line + 1)
        }
        # Widest first, so an inner declaration overwrites an outer one.
        for decl in sorted(
            self.index.declarations, key=lambda d: d.end_line - d.start_line, reverse=True
        ):
            for line in range(decl.start_line, decl.end_line + 1):
                current = spans[line]
                if decl.kind.is_type:
                    spans[line] = Host(decl.names[0], current.function, current.function_signature)
                else:
                    spans[line] = Host(
                        decl.parent or current.contract, decl.names[0], decl.signature
                    )
        return spans

    def _statement_of(self, node: Node) -> Node | None:
        """The nearest ancestor that is a statement, stepping over `expression` wrappers."""
        parent = node.parent
        while parent is not None and parent.type in _TRANSPARENT:
            parent = parent.parent
        return parent

    # -- queries ----------------------------------------------------------

    @cached_property
    def state_variables(self) -> frozenset[str]:
        """Names declared at contract scope.

        Used to tell a state write from a local one. A name, so it stays inside this module's
        classification and does not travel outward.
        """
        names: set[str] = set()
        for node in self._nodes("state_variable_declaration"):
            name = node.child_by_field_name("name")
            if name is not None:
                names.add(self.text(name))
        return frozenset(names)

    @cached_property
    def state_variable_types(self) -> Mapping[str, str]:
        """Declared type text for each contract-scope name.

        The declaration says whether a collection is dynamic, fixed or a mapping, and for one class
        that is all it needs, with no compiled backend.
        """
        types: dict[str, str] = {}
        for node in self._nodes("state_variable_declaration"):
            name = node.child_by_field_name("name")
            declared = next((c for c in node.children if c.type == "type_name"), None)
            if name is not None and declared is not None:
                types[self.text(name)] = self.text(declared)
        return types

    @cached_property
    def loops(self) -> tuple[LoopSite, ...]:
        """Every loop, with the identifiers its continuation condition mentions.

        The condition is what bounds the loop, so it is kept apart from the body: a loop over
        `voters.length` and one that merely touches `voters` inside are different facts, and merging
        them would make every loop in a contract look bounded by whatever it uses.
        """
        found: list[LoopSite] = []
        for node in self._nodes("for_statement", "while_statement"):
            if node.type == "while_statement":
                conditions = [c for c in node.children if c.type == "expression"][:1]
            else:
                # A `for` header is `init; condition; update`, and the condition is the
                # `expression_statement`. The bare `expression` child is the *update*, which
                # mentions only the counter. A `for (;;)` has no `expression_statement` and so no
                # bound, which is the right answer for it.
                conditions = [c for c in node.children if c.type == "expression_statement"][:1]
            names = {
                self.text(i)
                for condition in conditions
                for i in self._descendants(condition, "identifier")
            }
            found.append(LoopSite(site=self._site(node), bound_identifiers=tuple(sorted(names))))
        return tuple(found)

    @cached_property
    def length_aliases(self) -> Mapping[int, Mapping[str, str]]:
        """Local names assigned a collection's length, keyed by declaring line.

        `uint256 n = items.length;` and then a loop bounded by `n`. Following that means tracking
        one assignment inside one body, the same depth-one tracking that caller taint uses, and it
        needs no compiled backend.

        An alias assigned more than once in a body is **omitted**: the second assignment may come
        from anywhere, and a name whose value depends on control flow is exactly what def-use is
        for. Refusing beats guessing, which is the discipline the declaration index already applies
        to an overloaded name.
        """
        assignments: dict[str, list[tuple[int, str]]] = {}
        for statement in self._nodes("variable_declaration_statement", "expression_statement"):
            targets: list[str] = []
            source: Node | None = None
            for declaration in self._descendants(statement, "variable_declaration"):
                targets += [self.text(i) for i in declaration.children if i.type == "identifier"]
            if targets:
                source = next((c for c in statement.children if c.type == "expression"), None)
            else:
                # A plain re-assignment, `n = other.length;`, which carries no
                # `variable_declaration`. It is collected because otherwise a twice-assigned alias
                # looks singly assigned, and the tracking then follows the declaration while
                # ignoring the assignment that actually reaches the loop.
                for assignment in self._descendants(statement, "assignment_expression"):
                    left = next((c for c in assignment.children if c.is_named), None)
                    if left is None:
                        continue
                    names = [self.text(i) for i in self._descendants(left, "identifier")]
                    if len(names) == 1:
                        targets += names
                        source = assignment
            if not targets or source is None:
                continue
            members = self._descendants(source, "member_expression")
            lengths = [m for m in members if self.text(m).endswith(".length")]
            if len(lengths) != 1 or len(members) != 1:
                continue
            collection = self.text(lengths[0]).removesuffix(".length").strip()
            if not collection.isidentifier():
                continue
            for target in targets:
                assignments.setdefault(target, []).append(
                    (statement.start_point[0] + 1, collection)
                )

        by_function: dict[int, dict[str, str]] = {}
        for function in self.functions:
            scoped = {}
            for name, sites in assignments.items():
                inside = [
                    collection
                    for line, collection in sites
                    if function.site.start_line <= line <= function.site.end_line
                ]
                # Assigned once in this body, and nowhere else in the file under the same name.
                # Anything else makes the value depend on control flow, which this depth cannot
                # follow.
                if len(inside) == 1 and len(sites) == 1:
                    scoped[name] = inside[0]
            by_function[function.site.start_line] = scoped
        return by_function

    def callers_of(self, name: str) -> tuple[str, ...]:
        """Functions in this unit that call `name` with no receiver.

        Name lookup, which is what resolving a call within one file amounts to when the name is
        declared once and carries no overload. Compilation earns its place on an inheritance chain,
        a library, or an overload set; `declarations_of` is how a caller checks that none of those
        apply before trusting this.
        """
        found = {
            self.host_at(call.site.start_line).function
            for call in self.calls
            if call.callee == name and call.receiver is None
        }
        return tuple(sorted(f for f in found if f))

    def declarations_of(self, name: str) -> int:
        """How many function-like declarations in this unit carry `name`.

        More than one is an overload or an override, and a syntactic answer must refuse rather than
        pick, the same rule the declaration index applies when a report names an overloaded
        function.
        """
        return sum(1 for f in self.functions if f.declaration.names[0] == name)

    @cached_property
    def destructurings(self) -> tuple[Destructuring, ...]:
        """Every multi-return unpacked into named bindings, with the call behind it.

        Positional and partial by nature: `(, price, , updatedAt, )` names two of five returns and
        skips three. Only the named ones can be referred to later, so only they are recorded.
        """
        found: list[Destructuring] = []
        for node in self._nodes("variable_declaration_statement"):
            group = next((c for c in node.children if c.type == "variable_declaration_tuple"), None)
            if group is None:
                continue
            bindings: list[tuple[str, str]] = []
            for declaration in (c for c in group.children if c.type == "variable_declaration"):
                name = next(
                    (self.text(i) for i in declaration.children if i.type == "identifier"), None
                )
                declared = next(
                    (self.text(t) for t in declaration.children if t.type == "type_name"), None
                )
                if name is not None:
                    bindings.append((declared or "", name))
            if not bindings:
                continue
            source = next((c for c in node.children if c.type == "expression"), None)
            found.append(
                Destructuring(
                    site=self._site(node),
                    bindings=tuple(bindings),
                    source_text=self.text(source) if source is not None else "",
                )
            )
        return tuple(found)

    @cached_property
    def arithmetic(self) -> tuple[ArithmeticSite, ...]:
        """Every binary arithmetic expression, with its operator and its operands'.

        `operand_operators` is what makes evaluation order visible: an outer `*` whose left operand
        contains a `/` divides first and loses precision that multiplying first would have kept.
        That is the shape of one expression, and it needs no types.
        """
        found: list[ArithmeticSite] = []
        for node in self._nodes("binary_expression"):
            operator = next(
                (c.type for c in node.children if c.type in _ARITHMETIC_OPERATORS), None
            )
            if operator is None:
                continue
            operand_operators: set[str] = set()
            divisors: set[str] = set()
            multipliers: set[str] = set()
            for operand in (c for c in node.children if c.type == "expression"):
                inner = self._descendants(operand, "binary_expression")
                for expression in inner:
                    operand_operators |= {
                        c.type for c in expression.children if c.type in _ARITHMETIC_OPERATORS
                    }
                    if not any(c.type == "/" for c in expression.children):
                        continue
                    parts = [c for c in expression.children if c.type == "expression"]
                    if len(parts) == 2:
                        divisors.add(_normalised(self.text(parts[1])))
                # The operand that is *not* the divided one is what this expression scales by.
                # Gating on "has no arithmetic at all" would miss `(a / b) * (c + d)`, whose
                # multiplier has a `+` of its own, and that turns a real corpus record from a match
                # into a miss.
                if not any(c.type == "/" for expression in inner for c in expression.children):
                    multipliers.add(_normalised(self.text(operand)))
            found.append(
                ArithmeticSite(
                    site=self._site(node),
                    operator=operator,
                    operand_operators=tuple(sorted(operand_operators)),
                    divisors=tuple(sorted(divisors)),
                    multipliers=tuple(sorted(multipliers)),
                )
            )
        return tuple(found)

    @cached_property
    def calls(self) -> tuple[CallSite, ...]:
        """Every call in the unit, outermost member first."""
        found: list[CallSite] = []
        for node in self._nodes("call_expression"):
            function = node.child_by_field_name("function")
            if function is None:
                continue
            callee, receiver = self._split_callee(function)
            if callee is None:
                continue
            arguments = tuple(
                Argument(
                    position=position,
                    text=self.text(child),
                    node_type=self._expression_type(child),
                )
                for position, child in enumerate(
                    c for c in node.children if c.type == "call_argument"
                )
            )
            statement = self._statement_of(node)
            found.append(
                CallSite(
                    site=self._site(node),
                    callee=callee,
                    receiver=receiver,
                    arguments=arguments,
                    bound_names=self._bound_names(statement),
                    is_bare_statement=statement is not None and statement.type == _BARE_STATEMENT,
                    has_call_options=any(c.type == "struct_expression" for c in function.children)
                    or "{" in self.text(function),
                )
            )
        return tuple(found)

    def _expression_type(self, node: Node) -> str:
        """Node type of an argument, looking through `expression` wrappers."""
        current = node
        while current.type in _TRANSPARENT or current.type == "call_argument":
            children = [c for c in current.children if c.is_named]
            if len(children) != 1:
                break
            current = children[0]
        return str(current.type)

    def _split_callee(self, function: Node) -> tuple[str | None, str | None]:
        """Split a call's function expression into member name and receiver text.

        The outermost member is the one being called: in `a.b().c()` the callee is `c`, and taking
        the innermost would report `b`.
        """
        current = function
        while current.type in _TRANSPARENT:
            named = [c for c in current.children if c.is_named]
            if len(named) != 1:
                break
            current = named[0]

        if current.type == "member_expression":
            prop = current.child_by_field_name("property")
            obj = current.child_by_field_name("object")
            if prop is not None:
                return self.text(prop), (self.text(obj) if obj is not None else None)
            return None, None
        if current.type == "identifier":
            return self.text(current), None
        # A call through something with no name of its own: a cast, an index or a call option
        # wrapper. Find the outermost member inside it, if any.
        stack: list[Node] = [current]
        while stack:
            node = stack.pop(0)
            if node.type == "member_expression":
                prop = node.child_by_field_name("property")
                obj = node.child_by_field_name("object")
                if prop is not None:
                    return self.text(prop), (self.text(obj) if obj is not None else None)
            stack.extend(node.children)
        return None, None

    @cached_property
    def member_reads(self) -> tuple[tuple[Site, str, str], ...]:
        """Every `object.property` access, as (site, receiver text, property name)."""
        found: list[tuple[Site, str, str]] = []
        for node in self._nodes("member_expression"):
            obj = node.child_by_field_name("object")
            prop = node.child_by_field_name("property")
            if obj is None or prop is None:
                continue
            found.append((self._site(node), self.text(obj), self.text(prop)))
        return tuple(found)

    @cached_property
    def writes(self) -> tuple[WriteSite, ...]:
        """Every assignment, classified by what it writes to."""
        found: list[WriteSite] = []
        for node in self._nodes("assignment_expression", "augmented_assignment_expression"):
            left = node.child_by_field_name("left")
            if left is None:
                continue
            operator = next(
                (self.text(c) for c in node.children if not c.is_named and self.text(c).strip()),
                "=",
            )
            site = self._site(node)
            for target_node in self._assignment_targets(left):
                kind, root = self._classify_target(target_node)
                found.append(
                    WriteSite(
                        site=site,
                        target=kind,
                        target_root=root,
                        operator=operator.strip(),
                    )
                )
        return tuple(found)

    def _assignment_targets(self, left: Node) -> list[Node]:
        """Every target an assignment writes to, not just the first.

        `(a, b) = (1, 2)` writes twice. Descending to the leftmost identifier would report only `a`,
        so a tuple assignment in which the second element is the state variable would drop that
        write entirely, an omission that looks like an absence of evidence rather than a failure to
        look.
        """
        current = left
        while current.type in _TRANSPARENT:
            named = [c for c in current.children if c.is_named]
            if len(named) != 1:
                break
            current = named[0]
        if current.type == "tuple_expression":
            return [c for c in current.children if c.is_named]
        return [current]

    def _classify_target(self, left: Node) -> tuple[str, str]:
        current = left
        while current.type in _TRANSPARENT:
            named = [c for c in current.children if c.is_named]
            if len(named) != 1:
                break
            current = named[0]

        shape = str(current.type)
        root = self._leftmost_identifier(current)
        if root is None:
            return WriteTarget.UNKNOWN, ""
        is_state = root in self.state_variables
        if not is_state:
            return WriteTarget.LOCAL, root
        if shape == "array_access":
            return WriteTarget.STATE_COLLECTION_ELEMENT, root
        if shape == "member_expression":
            return WriteTarget.STATE_MEMBER, root
        return WriteTarget.STATE_VARIABLE, root

    def _leftmost_identifier(self, node: Node) -> str | None:
        current = node
        while current.type != "identifier":
            named = [c for c in current.children if c.is_named]
            if not named:
                return None
            current = named[0]
        return self.text(current)

    def _parameter_names(self, function: Node) -> tuple[str, ...]:
        """Declared parameter names, in order, skipping any left unnamed.

        A parameter may be declared with a type and no name, which is legal and names nothing an
        expression could mention, so it contributes no entry rather than an empty one.
        """
        names: list[str] = []
        for parameters in (c for c in function.children if c.type == "parameter"):
            identifier = next(
                (c for c in parameters.children if c.type == "identifier"),
                None,
            )
            if identifier is not None:
                names.append(self.text(identifier))
        return tuple(names)

    @cached_property
    def selections(self) -> tuple[Site, ...]:
        """Places a value is turned into a choice rather than read as a quantity.

        Three shapes, and they are the only ways an integer becomes a selection without leaving the
        expression: a cryptographic hash, a modulo, and a subscript. A value that reaches none of
        them is being read as a quantity (a deadline, a stamp, a balance), however unpredictable its
        source.

        The depth is one expression and the limitation is the same one that caller-taint and length
        aliases have: a value assigned to a local and selected on later is not seen, and following
        it needs def-use. The shallow form needs no data flow.
        """
        found: list[Site] = []
        for node in self._nodes("call_expression"):
            callee = next((c for c in node.children if c.type == "expression"), None)
            if callee is not None and self.text(callee).strip() in _HASHES:
                found.append(self._site(node))
        for node in self._nodes("binary_expression"):
            if any(c.type == "%" for c in node.children):
                found.append(self._site(node))
        for node in self._nodes("array_access", "index_access", "subscript_expression"):
            # The *index*, not the whole node. The grammar gives a subscript a base expression that
            # can swallow a surrounding comparison (`block.timestamp > locked[id]` parses as a
            # subscript whose base is `block.timestamp > locked`), so the node's extent contains
            # reads that are nowhere near the index. The index child is small and right, and
            # indexing *by* a value is the property anyway.
            after_bracket = False
            for child in node.children:
                if child.type == "[":
                    after_bracket = True
                    continue
                if child.type == "]":
                    break
                if after_bracket:
                    found.append(self._site(child))
        return tuple(sorted(found, key=lambda site: (site.start_line, site.text)))

    @cached_property
    def identity_lookups(self) -> tuple[Site, ...]:
        """Subscript indices whose collection is keyed by an address.

        A subset of `selections`, reported apart because indexing *by an identity* is not choosing
        among candidates. `adminGasSpentInWei[tx.origin]` has the same shape as
        `candidates[block.timestamp]` and the opposite meaning: one looks up the row belonging to a
        party, the other picks a row by a number a producer chose. The collection's declared key
        type says which it is.
        """
        found: list[Site] = []
        for node in self._nodes("array_access", "index_access", "subscript_expression"):
            base = next((c for c in node.children if c.type not in ("[", "]")), None)
            if base is None:
                continue
            declared = self.state_variable_types.get(self.text(base).strip())
            if declared is None or not declared.replace(" ", "").startswith("mapping(address"):
                continue
            after_bracket = False
            for child in node.children:
                if child.type == "[":
                    after_bracket = True
                    continue
                if child.type == "]":
                    break
                if after_bracket:
                    found.append(self._site(child))
        return tuple(sorted(found, key=lambda site: (site.start_line, site.text)))

    @cached_property
    def guards(self) -> tuple[GuardSite, ...]:
        """Every condition the code uses to decide whether to proceed.

        `require`, `assert` and `if`: the places a contract asks a question before acting. Collected
        together because what matters downstream is that a condition gates behaviour, not which
        keyword expressed it.

        Each carries the identifiers its condition mentions, which is what makes a *guard*
        distinguishable from a *mention*: a condition comparing `msg.sender` to a state variable and
        one comparing it to something the caller passed in are the same shape and opposite facts.
        """
        found: list[GuardSite] = []
        for node in self._nodes("call_expression", "if_statement"):
            # Shapes read off the grammar rather than assumed: a call's callee sits under an
            # `expression` child and its arguments are `call_argument` nodes, and an `if`'s
            # condition is its `expression` child. Selecting "the first child that is not the
            # keyword" would pick the opening parenthesis, which mentions nothing, and a shape read
            # wrong here reports an absent guard when the guard was there and went unread.
            if node.type == "call_expression":
                callee = next((c for c in node.children if c.type == "expression"), None)
                if callee is None or self.text(callee).strip() not in ("require", "assert"):
                    continue
                conditions = [c for c in node.children if c.type == "call_argument"]
            else:
                # The condition only. The body is a sibling `statement`, and including it would
                # count every identifier the branch touches as something the condition asked about.
                conditions = [c for c in node.children if c.type == "expression"][:1]
            if not conditions:
                continue
            names = {
                self.text(identifier)
                for condition in conditions
                for identifier in self._descendants(condition, "identifier")
            }
            receivers: set[str] = set()
            for condition in conditions:
                for member in self._descendants(condition, "member_expression"):
                    # The receiver is everything before the dot. Selecting a child of type
                    # `expression` would miss `from.owner()`, whose receiver is a bare identifier.
                    for child in member.children:
                        if child.type == ".":
                            break
                        receivers |= {self.text(i) for i in self._descendants(child, "identifier")}
            found.append(
                GuardSite(
                    site=self._site(node),
                    identifiers=tuple(sorted(names)),
                    call_receivers=tuple(sorted(receivers)),
                )
            )
        return tuple(sorted(found, key=lambda g: (g.site.start_line, g.site.text)))

    def _descendants(self, node: Node, node_type: str) -> list[Node]:
        found: list[Node] = []
        stack = [node]
        while stack:
            current = stack.pop()
            if current.type == node_type:
                found.append(current)
            stack.extend(current.children)
        return found

    @cached_property
    def functions(self) -> tuple[FunctionSite, ...]:
        """Every function-like declaration, with visibility, mutability and modifiers."""
        by_line = {d.start_line: d for d in self.index.declarations if not d.kind.is_type}
        found: list[FunctionSite] = []
        for node in self._nodes(
            "function_definition",
            "constructor_definition",
            "modifier_definition",
            "fallback_receive_definition",
        ):
            declaration = by_line.get(node.start_point[0] + 1)
            if declaration is None:
                continue
            found.append(
                FunctionSite(
                    site=self._site(node),
                    declaration=declaration,
                    visibility=next(
                        (self.text(c) for c in node.children if c.type == "visibility"), None
                    ),
                    state_mutability=next(
                        (self.text(c) for c in node.children if c.type == "state_mutability"),
                        None,
                    ),
                    modifiers=tuple(
                        self.text(c) for c in node.children if c.type == "modifier_invocation"
                    ),
                    parameter_names=self._parameter_names(node),
                    returns_value=any(c.type == "return_type_definition" for c in node.children),
                )
            )
        return tuple(found)

    def returns_of(self, name: str, inside_type: str | None = None) -> bool | None:
        """Whether the functions this unit declares under `name` return a value.

        None when the unit declares no such function, because the callee then lives in a file this
        unit imports and nothing here says what it returns. An overload that returns counts as
        returning: the call is only certain to discard nothing when every declaration returns none.
        `inside_type` limits the answer to one contract, interface or library.
        """
        declared = [
            f
            for f in self.functions
            if f.declaration.names[0] == name
            and (inside_type is None or f.declaration.parent == inside_type)
        ]
        return any(f.returns_value for f in declared) if declared else None

    def callable_at(self, line: int) -> Declaration | None:
        """The innermost function-like declaration containing `line`.

        Predicates need it to ask function-scoped questions (whether a bound name is read again,
        whether a write follows a call), and resolving it here keeps one definition of "which
        function is this in", shared with host resolution.
        """
        containing = [
            d
            for d in self.index.declarations
            if not d.kind.is_type and d.start_line <= line <= d.end_line
        ]
        return min(containing, key=lambda d: d.end_line - d.start_line, default=None)

    def within(self, declaration: Declaration, sites: tuple[Site, ...]) -> list[Site]:
        """Sites whose line falls inside a declaration's span."""
        return [s for s in sites if declaration.start_line <= s.start_line <= declaration.end_line]

    def identifier_uses(self, declaration: Declaration, name: str) -> int:
        """How many times `name` appears as an identifier inside a declaration.

        Counted for shallow reachability questions ("is this bound result ever read again"), which
        is as far as a syntactic reading can go. It cannot tell a read from a shadowed rebinding, so
        a caller should treat a count of one as evidence and a higher count as absence of it.
        """
        total = 0
        for node in self._nodes("identifier"):
            line = node.start_point[0] + 1
            if declaration.start_line <= line <= declaration.end_line and self.text(node) == name:
                total += 1
        return total

    def _bound_names(self, statement: Node | None) -> tuple[str, ...]:
        """Names the statement binds, read from the tree rather than from text.

        Destructuring is what makes the text approach wrong rather than merely ugly: `(, uint256
        price, , , )` has four omitted slots, and splitting on commas cannot tell an omitted binding
        from a present one. The grammar already distinguishes them: only a filled slot produces a
        `variable_declaration` node.

        The `value` subtree is excluded, or a call on the right-hand side would contribute any names
        declared inside it.
        """
        if statement is None:
            return ()
        if statement.type == "variable_declaration_statement":
            value = statement.child_by_field_name("value")
            # Keyed by byte offset and sorted, because the traversal below pops from a stack and
            # would otherwise return source order reversed.
            names: list[tuple[int, str]] = []
            stack: list[Node] = [c for c in statement.children if value is None or c.id != value.id]
            while stack:
                node = stack.pop()
                if node.type == "variable_declaration":
                    name = node.child_by_field_name("name")
                    if name is not None:
                        names.append((int(name.start_byte), self.text(name)))
                stack.extend(node.children)
            return tuple(name for _, name in sorted(names))
        if statement.type in ("assignment_expression", "augmented_assignment_expression"):
            left = statement.child_by_field_name("left")
            root = self._leftmost_identifier(left) if left is not None else None
            return (root,) if root else ()
        return ()
