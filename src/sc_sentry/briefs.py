"""One brief per class: what to look for, and which skill and tools answer it.

Short on purpose. The knowledge is in the skills, where it can be read and
edited by somebody who is not reading Python, and where the planner pulls it
just in time. A brief's job is to name the class, point at its skill, and say
which tools are the cheap way in -- so the planner does not have to discover
that by trying all nine.
"""

from __future__ import annotations

from sc_sentry.classes import VulnClass as V

BRIEFS: dict[V, str] = {
    V.ACCESS_CONTROL: (
        "Class: access_control. Read the `access-control` skill. A state-changing path "
        "reachable by an account that should not be able to take it. Start from "
        "`state_writes()`, then `guards()` to see what authorises each, then "
        "`outline()`/`callers_of()` for reachability. A modifier counts as a guard."
    ),
    V.REENTRANCY: (
        "Class: reentrancy. Read the `reentrancy` skill. State read or written across an "
        "external call that can hand control back. Start from `external_calls()`, then "
        "`state_writes()` to see which writes land AFTER a call in the same function."
    ),
    V.UNCHECKED_EXTERNAL_CALL: (
        "Class: unchecked_external_call. Read the `unchecked-external-call` skill. A call "
        "whose failure is discarded. Start from `external_calls()`: `low_level` with empty "
        "or unread `bound_names`, and interface calls returning a discardable bool."
    ),
    V.ORACLE_INTEGRITY: (
        "Class: oracle_integrity. Read the `oracle-integrity` skill. A price or rate used "
        "without establishing freshness, sanity or resistance to manipulation. Start from "
        "`member_reads()` for the read, then `guards()` for what checks it, then cite the "
        "line that USES the value."
    ),
    V.ARITHMETIC_ROUNDING: (
        "Class: arithmetic_rounding. Read the `arithmetic-rounding` skill. Start from "
        "`arithmetic()`, especially `divides_then_scales`. A rounding DIRECTION claim needs "
        "the protocol's own intent -- if the source does not state it, do not report it."
    ),
    V.SLIPPAGE: (
        "Class: slippage. Read the `slippage` skill. An exchange with no enforced bound on "
        "what comes back. Start from `external_calls()` and read the `arguments`: a literal "
        "zero minimum, or a minimum derived from the pool being swapped against."
    ),
    V.DENIAL_OF_SERVICE: (
        "Class: denial_of_service. Read the `denial-of-service` skill. A path an outsider "
        "can make permanently unusable FOR SOMEBODY ELSE. Start from `external_calls()`: a "
        "push transfer or callback on a path a third party needs, where the recipient can "
        "revert. Auctions, bids, refunds, claims, distributions and debt repayment are where "
        "this lives -- one recipient that reverts freezes everybody. Then `guards()` for a "
        "`require` on state an outsider can set, and for a state the protocol cannot leave. "
        "Loops are the SMALLEST family here, so check `loops()` last."
    ),
    V.INSECURE_RANDOMNESS: (
        "Class: insecure_randomness. A value used as unpredictable that a miner, validator "
        "or caller can influence: `block.timestamp`, `blockhash`, `block.prevrandao`, "
        "`block.difficulty`, a hash of those, or a caller-supplied seed. Start from "
        "`member_reads()` and `arithmetic()`."
    ),
}
