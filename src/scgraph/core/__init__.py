"""scgraph.core: the domain-agnostic engine under scgraph.

    graph   TypedGraph   typed nodes, named relations, per-edge confidence, validity
                         window and provenance; CSR both directions; content fingerprint
    paths   find_paths   BFS whose output is evidence: every hop names its edge
    gates   Ladder       alert only with surviving evidence, else abstain with a reason
    ledger  Ledger       bitemporal, hash-chained change log over a base snapshot;
                         as-of views and verifiable answer receipts

Domain code lives in ``scgraph.adapters``; nothing here knows what a package is.
"""

from .gates import Gate, Ladder, Verdict, min_confidence_gate
from .graph import OPEN, EdgeBatch, Relation, TypedGraph
from .ledger import Delta, Ledger, LedgerError, Receipt, canonical, to_ts
from .paths import Path, find_paths, reachable

__all__ = [
    "OPEN",
    "Delta",
    "EdgeBatch",
    "Gate",
    "Ladder",
    "Ledger",
    "LedgerError",
    "Path",
    "Receipt",
    "Relation",
    "TypedGraph",
    "Verdict",
    "canonical",
    "find_paths",
    "min_confidence_gate",
    "reachable",
    "to_ts",
]
