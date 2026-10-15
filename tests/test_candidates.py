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
    "a low-level call whose result is dropped": (
        V.UNCHECKED_EXTERNAL_CALL,
        "contract A {\n    function pay(address to, uint256 amount) external {\n"
        '        to.call{value: amount}("");\n    }\n}\n',
        [("pay", "flag_of_a_call_never_read")],
    ),
    "a low-level call whose flag is read": (
        V.UNCHECKED_EXTERNAL_CALL,
        "contract A {\n    function pay(address to, uint256 amount) external {\n"
        '        (bool ok, ) = to.call{value: amount}("");\n        require(ok, "failed");\n'
        "    }\n}\n",
        [],
    ),
    "a low-level call whose flag is bound and never read": (
        V.UNCHECKED_EXTERNAL_CALL,
        "contract A {\n    function pay(address to, uint256 amount) external {\n"
        '        (bool ok, ) = to.call{value: amount}("");\n    }\n}\n',
        [("pay", "flag_of_a_call_never_read")],
    ),
    "a low-level call that leaves the flag out": (
        V.UNCHECKED_EXTERNAL_CALL,
        "contract A {\n    function pay(address to, bytes calldata data) external {\n"
        "        (, bytes memory back) = to.call(data);\n        emit Done(back);\n    }\n}\n",
        [("pay", "flag_of_a_call_never_read")],
    ),
    "a token transfer whose bool is dropped": (
        V.UNCHECKED_EXTERNAL_CALL,
        "contract A {\n    function pay(address to, uint256 amount) external {\n"
        "        IERC20(token).transfer(to, amount);\n    }\n}\n",
        [("pay", "token_bool_discarded")],
    ),
    "a safe transfer": (
        V.UNCHECKED_EXTERNAL_CALL,
        "contract A {\n    function pay(address to, uint256 amount) external {\n"
        "        IERC20(token).safeTransfer(to, amount);\n    }\n}\n",
        [],
    ),
    "a native transfer, which reverts by itself": (
        V.UNCHECKED_EXTERNAL_CALL,
        "contract A {\n    function pay(address to, uint256 amount) external {\n"
        "        payable(to).transfer(amount);\n    }\n}\n",
        [],
    ),
    "a require, which returns nothing": (
        V.UNCHECKED_EXTERNAL_CALL,
        "contract A {\n    function check(address who) external view {\n"
        '        require(who != address(0), "zero address");\n    }\n}\n',
        [],
    ),
    "a call to a function of the same unit that returns nothing": (
        V.UNCHECKED_EXTERNAL_CALL,
        "contract A {\n    function run(uint256 x) external {\n        _record(x, msg.sender);\n"
        "    }\n    function _record(uint256 x, address who) internal {\n"
        "        last = x;\n    }\n}\n",
        [],
    ),
    "a call to a function of the same unit that returns a value": (
        V.UNCHECKED_EXTERNAL_CALL,
        "contract A {\n    function run(uint256 x) external {\n        _record(x, msg.sender);\n"
        "    }\n    function _record(uint256 x, address who) internal returns (bool) {\n"
        "        last = x;\n        return true;\n    }\n}\n",
        [("run", "returned_value_discarded")],
    ),
    "a call on a contract this unit only imports": (
        V.UNCHECKED_EXTERNAL_CALL,
        "contract A {\n    function run(uint256 x) external {\n"
        "        IRouter(router).enterMarkets(markets, x);\n    }\n}\n",
        [("run", "call_into_an_imported_contract_as_a_statement")],
    ),
    "a call that shares its name with a void function of this unit": (
        V.UNCHECKED_EXTERNAL_CALL,
        "contract A {\n    function create(uint256 x) external {\n"
        "        Pool(pool).create(x, msg.sender, deadline);\n    }\n}\n",
        [("create", "call_into_an_imported_contract_as_a_statement")],
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


def test_a_dropped_flag_comes_before_a_call_nothing_here_describes() -> None:
    # `note` calls into an imported contract and may return nothing. `pay` drops the flag the
    # language says a low-level call returns, which is what the class is about.
    source = (
        "contract A {\n    function note(uint256 x) external {\n"
        "        log.record(x, msg.sender);\n    }\n"
        "    function pay(address to, uint256 amount) external {\n"
        '        to.call{value: amount}("");\n    }\n}\n'
    )
    ordered = [e.function for e in CHECKS[V.UNCHECKED_EXTERNAL_CALL].functions(source)]
    assert ordered == ["pay", "note"]


def test_every_class_still_has_a_finder_and_a_priority_where_one_was_tuned() -> None:
    assert set(CHECKS) == set(V)
    tuned = {
        V.ACCESS_CONTROL,
        V.ARITHMETIC_ROUNDING,
        V.DENIAL_OF_SERVICE,
        V.ORACLE_INTEGRITY,
        V.REENTRANCY,
        V.SLIPPAGE,
        V.UNCHECKED_EXTERNAL_CALL,
    }
    assert {v for v, check in CHECKS.items() if check.priority is not None} == tuned
