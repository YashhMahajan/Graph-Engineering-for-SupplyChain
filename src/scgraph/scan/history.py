"""Scan history in the bitemporal ledger: "when were we first exposed to this advisory?"

``scgraph scan --history DIR`` records each scan in a ``scgraph.core.Ledger``: an edge
``lockfile --exposed_to--> advisory`` opens when a scan first alerts on the advisory and
closes when a later scan no longer does. ``scgraph history --advisory ID`` reads the episodes
back, and the ledger's own receipt makes the answer verifiable: the log is hash-chained, so
editing or deleting a past scan breaks ``verify``.

What a recorded exposure means, exactly: *the first scan that was recorded here alerted on it
at that time*. It is not "the first moment the code was vulnerable", which the lockfile could
have been since long before anyone scanned it. The window starts at the scan, never earlier.

Every id of a finding (its GHSA, CVE and PYSEC aliases) gets an edge, so a question can use
any of them. Each recorded scan gets a strictly increasing timestamp, so an exposure that
opens and closes within one second is not silently erased by the ledger.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from ..core.graph import OPEN, EdgeBatch, TypedGraph
from ..core.ledger import Ledger, LedgerError, Receipt, to_ts
from .engine import ScanResult

__all__ = [
    "RELATION",
    "Episode",
    "LedgerError",
    "check_receipt",
    "episodes",
    "open_history",
    "record_scan",
    "verify",
]

RELATION = "exposed_to"


@dataclass(frozen=True)
class Episode:
    lockfile: str
    exposed_from: str  # ISO-8601 UTC: the first recorded scan that alerted
    exposed_until: str | None  # the first recorded scan that no longer alerted, or None

    def to_dict(self) -> dict:
        return {
            "lockfile": self.lockfile,
            "exposed_from": self.exposed_from,
            "exposed_until": self.exposed_until,
        }


def _iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, UTC).isoformat(timespec="seconds")


def open_history(path: str | Path, now: datetime | None = None) -> Ledger:
    """The ledger at ``path``, created empty on first use."""
    p = Path(path)
    if (p / "base").is_dir():
        return Ledger(p)
    base = TypedGraph.build([], {RELATION: EdgeBatch([], [])}, meta={"kind": "scgraph-history"})
    p.mkdir(parents=True, exist_ok=True)
    return Ledger.create(p, base, now or datetime.now(UTC))


def _head_time(ledger: Ledger) -> int:
    """The latest recorded time in the ledger. The ledger refuses a ``recorded_at`` before it,
    so a scan is stamped after it. This reads ledger internals because the ledger exposes the
    head's sequence and hash but not its time."""
    ledger.refresh()
    return ledger._deltas[-1].recorded_at if ledger._deltas else ledger._bases[0][1]


def _lockfile_key(path: str, root: Path | None) -> str:
    p = Path(path)
    try:
        rel = p.resolve().relative_to((root or Path.cwd()).resolve()).as_posix()
    except ValueError:
        rel = p.name  # outside the root: the name only, so no absolute path is stored
    return f"lockfile:{rel}"


def record_scan(
    ledger: Ledger,
    results: list[ScanResult],
    root: Path | None = None,
    now: datetime | None = None,
) -> dict[str, int]:
    """Record one scan. Opens an exposure for each new alert id and closes each one that is
    no longer an alert. Returns ``{"opened": n, "closed": n}``."""
    ts = max(to_ts(now or datetime.now(UTC)) or 0, _head_time(ledger) + 1)  # strictly increasing
    g, _ = ledger.view()
    rel = g.relations.get(RELATION)
    made: set[str] = set()
    counts = {"opened": 0, "closed": 0}

    def node(key: str, kind: str) -> None:
        if g.node(key) < 0 and key not in made:
            ledger.add_node(key, kind, recorded_at=ts)
            made.add(key)

    for r in results:
        lf = _lockfile_key(r.path, root)
        current = {f"advisory:{i}" for f in r.alerts for i in f.all_ids()}
        open_now: set[str] = set()
        src = g.node(lf)
        if src >= 0 and rel is not None:
            nbrs, eids = rel.out_edges(src)
            open_now = {
                g.keys[int(n)]
                for n, e in zip(nbrs, eids, strict=True)
                if rel.valid_to[int(e)] == OPEN
            }
        for adv in sorted(current - open_now):
            node(lf, "lockfile")
            node(adv, "advisory")
            ledger.add_edge(RELATION, lf, adv, valid_from=ts, source="scgraph scan", recorded_at=ts)
            counts["opened"] += 1
        for adv in sorted(open_now - current):
            ledger.retire_edge(RELATION, lf, adv, valid_to=ts, recorded_at=ts)
            counts["closed"] += 1
    return counts


def _query(advisory: str):
    """The ledger query for one advisory. A receipt records only the advisory id, so
    ``check_receipt`` rebuilds exactly this function from it."""
    key = f"advisory:{advisory}"

    def query(g: TypedGraph, _valid_at: int | None) -> list[dict]:
        node = g.node(key)
        rel = g.relations.get(RELATION)
        if node < 0 or rel is None:
            return []
        srcs, eids = rel.in_edges(node)
        out = [
            {
                "lockfile": str(g.keys[int(s)]).removeprefix("lockfile:"),
                "from": int(rel.valid_from[int(e)]),
                "until": None if rel.valid_to[int(e)] == OPEN else int(rel.valid_to[int(e)]),
            }
            for s, e in zip(srcs, eids, strict=True)
        ]
        return sorted(out, key=lambda d: (d["lockfile"], d["from"]))

    return query


def episodes(ledger: Ledger, advisory: str) -> tuple[list[Episode], Receipt]:
    """Every exposure episode for ``advisory`` (any of its ids), with a verifiable receipt."""
    rows, receipt = ledger.answer(
        {"op": "exposure_episodes", "advisory": advisory}, _query(advisory)
    )
    eps = [
        Episode(r["lockfile"], _iso(r["from"]), None if r["until"] is None else _iso(r["until"]))
        for r in rows
    ]
    return eps, receipt


def check_receipt(ledger: Ledger, receipt: Receipt) -> bool:
    """True iff the answer the receipt describes is what this ledger gives today, and the
    receipt's log position is part of the ledger's verified, untampered chain."""
    q = receipt.query
    if q.get("op") != "exposure_episodes" or not isinstance(q.get("advisory"), str):
        raise LedgerError("not a scgraph history receipt")
    return ledger.check(receipt, _query(q["advisory"]))


def verify(ledger: Ledger) -> int:
    """Number of recorded changes, raising ``LedgerError`` if the chain was tampered with."""
    return ledger.verify()
