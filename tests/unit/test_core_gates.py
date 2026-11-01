from dataclasses import dataclass

import pytest

from scgraph.core import Gate, Ladder, min_confidence_gate


@dataclass
class Ev:
    sev: float
    confidence: float = 1.0


def test_alert_carries_only_surviving_evidence():
    lad = Ladder([Gate("sev", "too low", lambda e, c: e.sev >= c["floor"])])
    v = lad.evaluate([Ev(3), Ev(9)], {"floor": 5})
    assert v.alert and [e.sev for e in v.evidence] == [9]
    assert v.summary()["trail"] == [("sev", 2, 1)]


def test_first_emptying_gate_names_the_abstention():
    lad = Ladder([Gate("sev", "too low", lambda e, c: e.sev >= 5), min_confidence_gate(0.8)])
    v = lad.evaluate([Ev(9, 0.4)])
    assert not v.alert and v.reason == "below_confidence_floor"
    assert v.evidence  # the evidence that was rejected is kept for review


def test_no_evidence_and_validation():
    assert Ladder([]).evaluate([]).reason == "no_evidence"
    with pytest.raises(ValueError):
        Ladder([Gate("a", "", lambda e, c: True)] * 2)
    with pytest.raises(ValueError):
        min_confidence_gate(1.5)
