"""The gate ladder, generalised: alert only with evidence, otherwise abstain with a reason.

The CVE pipeline's seven gates (``scgraph.ladder``) are one instance of a pattern that
holds in any domain: a claim is a set of evidence paths, and a sequence of predicates
narrows that set. If a gate empties it, the answer is an explicit abstention naming the
gate and the reason; nothing is silently dropped. If evidence survives every gate, the
answer is an alert carrying exactly the surviving evidence.

A gate is a name, a human-readable reason, and a filter ``(evidence, ctx) -> evidence``.
Gates are pure functions of their inputs, so a verdict is reproducible from the graph,
the query and the gate list (see ``scgraph.core.ledger.Receipt``).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar

E = TypeVar("E")


@dataclass(frozen=True)
class Gate(Generic[E]):
    name: str
    reason: str  # shown when this gate empties the evidence set
    keep: Callable[[E, dict], bool]  # per-item predicate

    def apply(self, evidence: Sequence[E], ctx: dict) -> list[E]:
        return [e for e in evidence if self.keep(e, ctx)]


@dataclass
class GateStep:
    gate: str
    n_in: int
    n_out: int


@dataclass
class Verdict(Generic[E]):
    alert: bool
    reason: str  # "alert", or the name of the gate that abstained
    detail: str
    evidence: list[E]  # surviving evidence on alert; the last non-empty set on abstain
    trail: list[GateStep] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        return {
            "alert": self.alert,
            "reason": self.reason,
            "detail": self.detail,
            "n_evidence": len(self.evidence),
            "trail": [(s.gate, s.n_in, s.n_out) for s in self.trail],
        }


class Ladder(Generic[E]):
    """Run gates in order; the first gate that empties the evidence decides the abstention."""

    def __init__(self, gates: Sequence[Gate[E]], no_evidence_reason: str = "no evidence path"):
        names = [g.name for g in gates]
        if len(set(names)) != len(names):
            raise ValueError("gate names must be unique")
        self.gates = list(gates)
        self.no_evidence_reason = no_evidence_reason

    def evaluate(self, evidence: Sequence[E], ctx: dict | None = None) -> Verdict[E]:
        ctx = ctx or {}
        cur = list(evidence)
        if not cur:
            return Verdict(False, "no_evidence", self.no_evidence_reason, [])
        trail: list[GateStep] = []
        for g in self.gates:
            nxt = g.apply(cur, ctx)
            trail.append(GateStep(g.name, len(cur), len(nxt)))
            if not nxt:
                return Verdict(False, g.name, g.reason, cur, trail)
            cur = nxt
        return Verdict(True, "alert", "", cur, trail)


def min_confidence_gate(threshold: float) -> Gate:
    """Drop evidence paths whose product confidence is below ``threshold``.

    This is what makes inferred edges safe to use: a weak path never becomes an alert,
    it becomes an abstention that says the evidence was too weak.
    """
    if not 0.0 <= threshold <= 1.0:
        raise ValueError("threshold must be in [0, 1]")
    return Gate(
        "below_confidence_floor",
        f"every evidence path has confidence below {threshold}",
        lambda p, ctx: getattr(p, "confidence", 1.0) >= threshold,
    )
