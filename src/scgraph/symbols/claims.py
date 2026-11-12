"""Inferred symbols as claims in the bitemporal ledger.

A claim is one edge, ``advisory -> symbol``. It is stored under the advisory id and under each
alias (GHSA, CVE), so a question by any of them finds it. It carries the confidence and a
source string that names the method, the evidence, the verifier result, and the model and
prompt hash when a model chose the symbol. The ledger is hash-chained, so a claim cannot change without
``verify()`` failing. A better inference later replaces a claim with ``retract_edge``. The old
claim stays visible to any view that was made before the retraction.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from ..core.graph import EdgeBatch, TypedGraph
from ..core.ledger import OPEN, Ledger, Receipt, to_ts
from ..scan.history import _head_time

__all__ = ["RELATION", "check_receipt", "claims_for", "open_claims", "record_claims"]

RELATION = "vulnerable_function"


def open_claims(path: str | Path, now: datetime | None = None) -> Ledger:
    """The claims ledger at ``path``. It is created empty on first use."""
    p = Path(path)
    if (p / "base").is_dir():
        return Ledger(p)
    base = TypedGraph.build(
        [], {RELATION: EdgeBatch([], [])}, meta={"kind": "scgraph-symbol-claims"}
    )
    p.mkdir(parents=True, exist_ok=True)
    return Ledger.create(p, base, now or datetime.now(UTC))


def _source(rec: dict) -> str:
    ev = rec.get("evidence") or {}
    parts = [
        f"method={rec.get('method', '')}",
        f"evidence={ev.get('fix') or 'code search'}",
        f"verified={rec.get('verified', '')}",
    ]
    llm = rec.get("llm") or {}
    if llm.get("model"):
        parts += [f"model={llm['model']}", f"prompt={llm.get('prompt_hash', '')}"]
    return "; ".join(parts)


def _node(ledger: Ledger, g: TypedGraph, made: set[str], key: str, kind: str, ts: int) -> None:
    if g.node(key) < 0 and key not in made:
        ledger.add_node(key, kind, recorded_at=ts)
        made.add(key)


def record_claims(
    ledger: Ledger, records: list[dict], now: datetime | None = None
) -> dict[str, int]:
    """Record one claim per dataset record. The call is idempotent: an unchanged claim is not
    written again. A record whose symbol changed retracts the old claim and adds the new one."""
    ts = max(to_ts(now or datetime.now(UTC)) or 0, _head_time(ledger) + 1)
    g, _ = ledger.view()
    rel = g.relations.get(RELATION)
    made: set[str] = set()
    counts = {"added": 0, "unchanged": 0, "superseded": 0}
    for rec in sorted(records, key=lambda r: r["id"]):
        sym = f"symbol:{rec['ecosystem']}:{rec['package']}:{rec['symbol']}"
        for adv_id in [rec["id"], *rec.get("aliases", [])]:  # people ask by CVE as well as GHSA
            adv = f"advisory:{adv_id}"
            open_dst: set[str] = set()
            src = g.node(adv)
            if src >= 0 and rel is not None:
                nbrs, eids = rel.out_edges(src)
                open_dst = {
                    g.keys[int(n)]
                    for n, e in zip(nbrs, eids, strict=True)
                    if rel.valid_to[int(e)] == OPEN
                }
            if sym in open_dst:
                counts["unchanged"] += 1
                continue
            for old in sorted(open_dst):
                ledger.retract_edge(
                    RELATION, adv, old, reason="superseded by a newer inference", recorded_at=ts
                )
                counts["superseded"] += 1
            _node(ledger, g, made, adv, "advisory", ts)
            _node(ledger, g, made, sym, "symbol", ts)
            ledger.add_edge(
                RELATION,
                adv,
                sym,
                valid_from=ts,
                confidence=float(rec.get("confidence", 1.0)),
                source=_source(rec),
                recorded_at=ts,
            )
            counts["added"] += 1
    return counts


def _query(advisory: str):
    key = f"advisory:{advisory}"

    def query(g: TypedGraph, _valid_at: int | None) -> list[dict]:
        node = g.node(key)
        rel = g.relations.get(RELATION)
        if node < 0 or rel is None:
            return []
        dsts, eids = rel.out_edges(node)
        return sorted(
            (
                {
                    "symbol": str(g.keys[int(d)]).split(":", 3)[3],
                    "confidence": round(float(rel.confidence[int(e)]), 4),
                    "source": str(g.sources[int(rel.source[int(e)])]),
                }
                for d, e in zip(dsts, eids, strict=True)
                if rel.valid_to[int(e)] == OPEN
            ),
            key=lambda d: d["symbol"],
        )

    return query


def claims_for(ledger: Ledger, advisory: str) -> tuple[list[dict], Receipt]:
    """The open claims for ``advisory``, with a receipt that anyone holding the ledger can check."""
    return ledger.answer({"op": "symbol_claims", "advisory": advisory}, _query(advisory))


def check_receipt(ledger: Ledger, receipt: Receipt) -> bool:
    q = receipt.query
    if q.get("op") != "symbol_claims" or not isinstance(q.get("advisory"), str):
        raise ValueError("not a symbol-claims receipt")
    return ledger.check(receipt, _query(q["advisory"]))
