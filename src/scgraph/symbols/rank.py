"""Engine A, step 2: score candidates. A logistic regression over model-free features.

The features are language-agnostic on purpose (sizes, shares, flags, text overlap), so a model
trained on the Go vulnerability database's labelled symbols can score Python candidates. That
transfer is an assumption the evaluation reports, not a fact it hides.

Without a trained model, ``HEURISTIC`` weights are used: the largest change wins, functions
the fix introduced lose, names the advisory or the fix's tests mention gain.
"""

from __future__ import annotations

import json
import math
from collections.abc import Sequence
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

import numpy as np

from .candidates import Candidate

__all__ = [
    "FEATURES",
    "HEURISTIC",
    "Ranker",
    "features",
    "load_default",
    "rank",
]

FEATURES = (
    "log_changed",
    "share",
    "inv_size_rank",
    "only_changed",
    "public",
    "is_method",
    "dunder",
    "new_function",
    "via_caller",
    "via_caller_public",
    "log_test_refs",
    "name_in_advisory",
    "advisory_overlap",
    "adds_check",
    "removed_only",
)

HEURISTIC = {
    "log_changed": 0.6,
    "share": 1.5,
    "inv_size_rank": 1.0,
    "only_changed": 0.5,
    "public": 0.4,
    "dunder": -0.8,
    "new_function": -3.0,
    "via_caller": -0.8,
    "via_caller_public": 0.6,
    "log_test_refs": 0.5,
    "name_in_advisory": 1.5,
    "advisory_overlap": 1.0,
    "adds_check": 0.3,
}


def features(c: Candidate) -> list[float]:
    return [
        math.log1p(c.changed),
        c.share,
        1.0 / c.size_rank if c.size_rank and not c.via_caller else 0.0,
        float(c.n_changed == 1 and not c.via_caller),
        float(c.public),
        float(c.is_method),
        float(c.dunder),
        float(c.new_function),
        float(c.via_caller),
        float(c.via_caller and c.public),
        math.log1p(c.test_refs),
        float(c.name_in_advisory),
        c.advisory_overlap,
        float(c.adds_check),
        float(c.added == 0 and c.removed > 0),
    ]


@dataclass
class Ranker:
    weights: dict[str, float]
    bias: float = 0.0
    name: str = "heuristic"
    trained_on: str = ""

    def score(self, c: Candidate) -> float:
        x = features(c)
        z = self.bias + sum(self.weights.get(f, 0.0) * v for f, v in zip(FEATURES, x))
        return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))

    def to_json(self) -> str:
        return json.dumps(
            {
                "name": self.name,
                "trained_on": self.trained_on,
                "features": list(FEATURES),
                "weights": self.weights,
                "bias": self.bias,
            },
            indent=1,
            sort_keys=True,
        )

    @classmethod
    def from_json(cls, s: str) -> Ranker:
        d = json.loads(s)
        return cls(
            weights={k: float(v) for k, v in d["weights"].items()},
            bias=float(d.get("bias", 0.0)),
            name=d.get("name", "logreg"),
            trained_on=d.get("trained_on", ""),
        )

    @classmethod
    def fit(
        cls,
        groups: Sequence[Sequence[Candidate]],
        labels: Sequence[Sequence[bool]],
        C: float = 1.0,
        trained_on: str = "",
    ) -> Ranker:
        """Candidate-level logistic regression with balanced class weights."""
        from sklearn.linear_model import LogisticRegression

        X = np.array([features(c) for g in groups for c in g], dtype=float)
        y = np.array([bool(v) for lab in labels for v in lab], dtype=int)
        if X.size == 0 or y.min() == y.max():
            raise ValueError("training needs both positive and negative candidates")
        m = LogisticRegression(C=C, class_weight="balanced", max_iter=2000)
        m.fit(X, y)
        w = {f: float(v) for f, v in zip(FEATURES, m.coef_[0])}
        return cls(weights=w, bias=float(m.intercept_[0]), name="logreg", trained_on=trained_on)


def load_default() -> Ranker:
    """The packaged trained model when present, else the heuristic weights."""
    try:
        text = resources.files("scgraph.symbols").joinpath("ranker.json").read_text()
        return Ranker.from_json(text)
    except (FileNotFoundError, OSError, ValueError, KeyError):
        return Ranker(weights=dict(HEURISTIC))


def rank(cands: list[Candidate], ranker: Ranker | None = None) -> list[Candidate]:
    """Candidates sorted best first, each with ``score`` set."""
    r = ranker or load_default()
    for c in cands:
        c.score = r.score(c)
    return sorted(cands, key=lambda c: (-c.score, -c.changed, c.symbol))


def save(ranker: Ranker, path: Path) -> None:
    path.write_text(ranker.to_json() + "\n", encoding="utf-8")
