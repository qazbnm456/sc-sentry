"""Which units to audit, and in what order.

A sweep of the whole corpus is the honest measurement and costs real money, so most runs are a
slice, and the slice has to be chosen with care. The largest class holds 200 of the corpus's 478
records, so the first N units of the corpus measure that one class under the corpus's name.

`slice_of` covers every class once before it covers any class twice, and it is deterministic, so
two runs of the loop compare. The units are read by the benchmark's own `units_from`, which checks
each file against the digest its record pins. A checkout that has drifted therefore shortens the
slice and says so, instead of scoring a different text from the one the records locate.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from contract_assay.corpus.records import load_records
from contract_assay.harness import SourceUnit, units_from


def slice_of(records_dir: Path, source_root: Path, want: int) -> tuple[list[SourceUnit], list[str]]:
    """Round-robin over the classes, and the units that could not be read.

    `want=0` means every unit that is readable. A unit absent from the checkout, or whose file does
    not match its pinned digest, is returned in the second list and takes no slot. The checkout is
    fetched separately and may be partial, and a partial checkout should shorten the slice, though
    never silently: the caller says how many units it got and how many it could not read.
    """
    positives = [
        record
        for record in sorted(load_records(records_dir), key=lambda r: r.record_id)
        if record.is_positive and record.locator is not None
    ]
    units, missing = units_from(positives, source_root)
    available = {unit.source_id: unit for unit in units}
    by_class: dict[str, list[str]] = defaultdict(list)
    for record in positives:
        source_id = record.pin.source_id
        if source_id not in available:
            continue
        for cls in record.classes:
            if source_id not in by_class[cls.value]:
                by_class[cls.value].append(source_id)

    chosen: list[str] = []
    depth = 0
    while len(chosen) < want or want == 0:
        added = False
        for class_id in sorted(by_class):
            ids = by_class[class_id]
            if depth < len(ids) and ids[depth] not in chosen:
                chosen.append(ids[depth])
                added = True
                if want and len(chosen) >= want:
                    break
        if not added:
            break
        depth += 1
    return [available[source_id] for source_id in chosen], missing
