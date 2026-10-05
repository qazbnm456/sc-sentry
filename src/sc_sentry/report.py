"""What `sc-sentry audit` writes: its own JSON, or SARIF 2.1.0.

SARIF is the OASIS standard for static-analysis results, and what GitHub code
scanning and most security tooling read, so a report can go wherever such
reports go without an adapter. Two mappings are worth stating:

- A finding the class definition rejected is emitted as a **suppressed** result
  with the reason as its justification -- SARIF's own way of saying "reported,
  and not standing" -- rather than dropped. A reader judging whether the screen
  is too strict needs to see what it took.
- The model's confidence (1-5) is the result's `rank` (20-100), SARIF's field
  for "how much this result should be believed", and is also kept verbatim in
  `properties`.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sc_sentry import __version__
from sc_sentry.audit import Finding, Report
from sc_sentry.checks import CHECKS

__all__ = ["to_json", "to_sarif"]

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _finding(finding: Finding) -> dict[str, Any]:
    return {
        "class": finding.vuln.value,
        "file": finding.file,
        "start_line": finding.start_line,
        "end_line": finding.end_line,
        "contract": finding.contract,
        "function": finding.function,
        "quote": finding.quote,
        "reasoning": finding.reasoning,
        "confidence": finding.confidence,
        "rejected": finding.rejected,
        "origin": finding.origin,
    }


def to_json(reports: Sequence[Report]) -> dict[str, Any]:
    """Everything the run knows, per file and per class."""
    return {
        "tool": "sc-sentry",
        "version": __version__,
        "files": [
            {
                "file": report.file,
                "model": report.model,
                "classes": [
                    {
                        "class": result.vuln.value,
                        "candidates": result.candidates,
                        "asked": result.asked,
                        "tokens": result.tokens,
                        "seconds": round(result.seconds, 1),
                        "failed": result.failed,
                        "findings": [_finding(f) for f in result.findings],
                    }
                    for result in report.results
                ],
            }
            for report in reports
        ],
    }


def to_sarif(reports: Sequence[Report]) -> dict[str, Any]:
    """One SARIF run, one rule per class, one result per finding."""
    rules = [
        {
            "id": vuln.value,
            "name": vuln.value,
            "shortDescription": {"text": check.summary},
        }
        for vuln, check in CHECKS.items()
    ]
    results = []
    for report in reports:
        for finding in report.findings:
            result: dict[str, Any] = {
                "ruleId": finding.vuln.value,
                "level": "warning",
                "message": {"text": finding.reasoning},
                "rank": float(finding.confidence * 20),
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file},
                            "region": {
                                "startLine": finding.start_line,
                                "endLine": finding.end_line,
                                "snippet": {"text": finding.quote},
                            },
                        },
                        "logicalLocations": [{"name": finding.function, "kind": "function"}]
                        if finding.function
                        else [],
                    }
                ],
                "properties": {"confidence": finding.confidence, "model": report.model},
            }
            if finding.rejected is not None:
                result["suppressions"] = [
                    {
                        "kind": "external",
                        "justification": (
                            f"{finding.vuln.value}: no {finding.rejected.replace('_', ' ')} "
                            "was established at the cited lines"
                        ),
                    }
                ]
            results.append(result)
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "sc-sentry",
                        "version": __version__,
                        "informationUri": "https://github.com/qazbnm456/sc-sentry",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
