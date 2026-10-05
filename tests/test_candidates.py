"""The per-class finders on small sources: what each lists, and what each leaves alone.

The finders were tuned against a public corpus, and these do not repeat that. They pin the
shapes each class is about, so a change that stops listing the textbook case, or starts
listing a function that has nothing to do with the class, fails here without needing the
corpus. Every source is a few lines, because a finder that needs a page of context to
fire is a finder nobody can reason about.
"""

from __future__ import annotations

import pytest

from sc_sentry.checks import CHECKS
from sc_sentry.classes import VulnClass as V

CASES: dict[str, tuple[V, str, list[tuple[str, str]]]] = {
    "an unrestricted setter": (
        V.ACCESS_CONTROL,
        "contract A {\n    address owner;\n    function setOwner(address o) external {\n"
        "        owner = o;\n    }\n}\n",
        [("setOwner", "unrestricted_state_change")],
    ),
    "a setter behind a caller check": (
        V.ACCESS_CONTROL,
        "contract A {\n    address owner;\n    function setOwner(address o) external {\n"
        '        require(msg.sender == owner, "no");\n        owner = o;\n    }\n}\n',
        [],
    ),
    "a value call before the balance is cleared": (
        V.REENTRANCY,
        "contract A {\n    mapping(address => uint256) bal;\n    function withdraw() external {\n"
        '        (bool ok, ) = msg.sender.call{value: bal[msg.sender]}("");\n'
        '        require(ok, "fail");\n        bal[msg.sender] = 0;\n    }\n}\n',
        [("withdraw", "external_call")],
    ),
    "a view that only reads": (
        V.REENTRANCY,
        "contract A {\n    uint256 total;\n    function read() external view returns (uint256) {\n"
        "        return total;\n    }\n}\n",
        [],
    ),
    "a price read from a feed": (
        V.ORACLE_INTEGRITY,
        "interface F { function latestRoundData() external view returns "
        "(uint80, int256, uint256, uint256, uint80); }\ncontract A {\n    F feed;\n"
        "    function price() external view returns (uint256) {\n"
        "        (, int256 answer, , , ) = feed.latestRoundData();\n"
        "        return uint256(answer);\n    }\n}\n",
        [("price", "external_value_read")],
    ),
    "a function that touches no outside value": (
        V.ORACLE_INTEGRITY,
        "contract A {\n    uint256 total;\n    function add(uint256 x) external {\n"
        "        total += x;\n    }\n}\n",
        [],
    ),
    "a payment inside a loop over a growing array": (
        V.DENIAL_OF_SERVICE,
        "contract A {\n    address[] users;\n    function payAll() external {\n"
        "        for (uint256 i = 0; i < users.length; i++) {\n"
        "            payable(users[i]).transfer(1 ether);\n        }\n    }\n}\n",
        [("payAll", "external_call_inside_a_loop")],
    ),
    "a function with no loop, call or revert": (
        V.DENIAL_OF_SERVICE,
        "contract A {\n    uint256 total;\n    function add(uint256 x) external {\n"
        "        total += x;\n    }\n}\n",
        [],
    ),
    "a division before a multiplication": (
        V.ARITHMETIC_ROUNDING,
        "contract A {\n    function share(uint256 a, uint256 b, uint256 c) public pure "
        "returns (uint256) {\n        return a / b * c;\n    }\n}\n",
        [("share", "division_before_scaling")],
    ),
    "an addition": (
        V.ARITHMETIC_ROUNDING,
        "contract A {\n    function sum(uint256 a, uint256 b) public pure returns (uint256) {\n"
        "        return a + b;\n    }\n}\n",
        [],
    ),
    "a swap with a literal zero minimum": (
        V.SLIPPAGE,
        "contract A {\n    function swapIt(uint256 amountIn, uint256 amountOutMin) external {\n"
        "        router.swapExactTokensForTokens(amountIn, 0, path, msg.sender, block.timestamp);\n"
        "    }\n}\n",
        [("swapIt", "zero_bound")],
    ),
    "a function with nothing to exchange": (
        V.SLIPPAGE,
        "contract A {\n    uint256 total;\n    function add(uint256 x) external {\n"
        "        total += x;\n    }\n}\n",
        [],
    ),
}


@pytest.mark.parametrize("case", CASES)
def test_each_finder_lists_the_textbook_case_and_leaves_the_rest(case: str) -> None:
    vuln, source, expected = CASES[case]
    found = [(e.function, e.best.predicate) for e in CHECKS[vuln].functions(source)]
    assert found == expected


@pytest.mark.parametrize("case", [name for name, (_, _, want) in CASES.items() if want])
def test_every_candidate_is_cited_inside_a_function_at_whole_lines(case: str) -> None:
    vuln, source, _ = CASES[case]
    lines = source.split("\n")
    for entry in CHECKS[vuln].functions(source):
        site = entry.best.site
        assert entry.function is not None
        assert 1 <= site.start_line <= site.end_line <= len(lines)
        # The quote a finding carries is exactly these lines, so they must not be empty.
        assert "".join(lines[site.start_line - 1 : site.end_line]).strip()


def test_a_class_with_a_priority_lists_the_likelier_function_first() -> None:
    # Two functions both qualify. The one paying out inside a loop over a growing array is
    # what the class is about, and the one that merely calls out once is a weaker candidate.
    source = (
        "contract A {\n    address[] users;\n    IToken token;\n"
        "    function ping(address to) external {\n        token.notify(to);\n    }\n"
        "    function payAll() external {\n"
        "        for (uint256 i = 0; i < users.length; i++) {\n"
        "            payable(users[i]).transfer(1 ether);\n        }\n    }\n}\n"
    )
    ordered = [e.function for e in CHECKS[V.DENIAL_OF_SERVICE].functions(source)]
    assert ordered[0] == "payAll"
    assert set(ordered) <= {"payAll", "ping"}


def test_every_class_still_has_a_finder_and_a_priority_where_one_was_tuned() -> None:
    assert set(CHECKS) == set(V)
    tuned = {
        V.ACCESS_CONTROL,
        V.ARITHMETIC_ROUNDING,
        V.DENIAL_OF_SERVICE,
        V.ORACLE_INTEGRITY,
        V.REENTRANCY,
        V.SLIPPAGE,
    }
    assert {v for v, check in CHECKS.items() if check.priority is not None} == tuned
