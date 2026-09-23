"""Which units to audit, and in what order.

A sweep of the whole corpus is the honest measurement and costs real money, so
most runs are a slice. The slice is the part worth getting right: the first N
units of a corpus whose largest class holds 190 of 435 records is a measurement
of that one class wearing the corpus's name.

`slice_of` covers every class once before covering any class twice, and is
deterministic, so two runs of the loop compare.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from contract_assay.corpus.records import load_records


@dataclass(frozen=True, slots=True)
class Unit:
    """One source file, already read. `path` is the pin's path, not a local one."""

    source_id: str
    path: str
    source: str


def slice_of(records_dir: Path, source_root: Path, want: int) -> list[Unit]:
    """Round-robin over the classes. `want=0` means every unit that is readable.

    A record whose file is absent under `source_root` is skipped rather than
    raised on: the checkout is fetched separately and may be partial, and a
    partial checkout should shorten the slice rather than end the run. What it
    must not do is silently shorten it -- the caller prints how many units it
    got, and `contract-assay score` states how many of the corpus's units the
    figures cover.
    """
    records = load_records(records_dir)
    by_class: dict[str, list[str]] = defaultdict(list)
    units: dict[str, Unit] = {}
    for record in sorted(records, key=lambda r: r.record_id):
        if not (record.is_positive and record.locator is not None):
            continue
        path = source_root / record.pin.path
        if not path.is_file():
            continue
        source_id = record.pin.source_id
        if source_id not in units:
            units[source_id] = Unit(
                source_id=source_id,
                path=record.pin.path,
                source=path.read_text(encoding="utf-8"),
            )
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
    return [units[source_id] for source_id in chosen]
