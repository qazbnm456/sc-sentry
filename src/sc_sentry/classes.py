"""The vulnerability classes this harness hunts, by name.

The names are plain strings a person can type at the command line. The spellings are the ones
most smart-contract taxonomies already use, so a report reads without a key.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = ["VulnClass"]


class VulnClass(StrEnum):
    ACCESS_CONTROL = "access_control"
    ARITHMETIC_ROUNDING = "arithmetic_rounding"
    DENIAL_OF_SERVICE = "denial_of_service"
    INSECURE_RANDOMNESS = "insecure_randomness"
    ORACLE_INTEGRITY = "oracle_integrity"
    REENTRANCY = "reentrancy"
    SLIPPAGE = "slippage"
    UNCHECKED_EXTERNAL_CALL = "unchecked_external_call"
