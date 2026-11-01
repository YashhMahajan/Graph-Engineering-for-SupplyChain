"""Software supply chain on the core engine.

Maps a built ``KGStore`` onto a ``TypedGraph``:

  nodes      ``ver:<ecosystem>/<name>@<version>``   type ``version``
             ``adv:<canonical id>|<osv id>``       type ``advisory``
  relations  ``resolves_to``  version -> version   source ``resolver``, confidence 1.0,
                                                   valid from the source version's
                                                   publish date when known
             ``affects``      version -> advisory  source ``osv``, confidence 1.0, valid
                                                   from the advisory's publish date

Putting the advisory publish date on the ``affects`` edge means "was this knowable on
date D" is not a special gate: it is ``as_of=D`` on the query, the same mechanism every
domain uses. Withdrawn advisories and severity are advisory attributes, applied as gates.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from ..core.gates import Gate, Ladder, Verdict, min_confidence_gate
from ..core.graph import EdgeBatch, TypedGraph
from ..core.ledger import to_ts
from ..core.paths import Path, find_paths

_MIN = np.iinfo(np.int64).min


@dataclass(frozen=True)
class Advisory:
    key: str
    canon: str
    osv_id: str
    severity: float
    withdrawn: bool
    published: int | None


@dataclass(frozen=True)
class Exposure:
    advisory: Advisory
    path: Path  # root ... affected version -> advisory

    @property
    def confidence(self) -> float:
        return self.path.confidence

    @property
    def depth(self) -> int:  # dependency hops, excluding the final ``affects`` hop
        return self.path.depth - 1


def _ts_or_min(s) -> int:
    try:
        t = to_ts(str(s)) if s is not None and str(s) not in ("", "None", "nan") else None
    except (ValueError, TypeError):
        t = None
    return _MIN if t is None else t


def version_key(store, vid: int) -> str:
    pid = int(store.ver_pkg[vid])
    return f"ver:{store.pkg_eco[pid]}/{store.pkg_name[pid]}@{store.ver_str[vid]}"


def from_kgstore(store) -> tuple[TypedGraph, dict[str, Advisory]]:
    """Project a ``KGStore`` onto the core graph. Returns ``(graph, advisories by key)``."""
    N, A = store.N, store.A
    vkeys = [version_key(store, v) for v in range(N)]
    akeys = [f"adv:{store.adv_canon[a]}|{store.adv_id[a]}" for a in range(A)]
    nodes = [(k, "version") for k in vkeys] + [(k, "advisory") for k in akeys]

    src = np.repeat(np.arange(N, dtype=np.int64), np.diff(np.asarray(store.res_indptr)))
    dst = np.asarray(store.res_indices, np.int64)
    if store.ver_published is not None:
        vpub = np.array([_ts_or_min(x) for x in store.ver_published], np.int64)
        rvf = vpub[src]
    else:
        rvf = None

    asrc = np.repeat(np.arange(N, dtype=np.int64), np.diff(np.asarray(store.aff_indptr)))
    aadv = np.asarray(store.aff_ids, np.int64)
    apub = np.array([_ts_or_min(x) for x in store.adv_published], np.int64)

    g = TypedGraph.build(
        nodes,
        {
            "resolves_to": EdgeBatch(src, dst, valid_from=rvf, source="resolver"),
            "affects": EdgeBatch(asrc, N + aadv, valid_from=apub[aadv], source="osv"),
        },
        meta={"adapter": "software", "versions": N, "advisories": A},
    )
    advs = {
        akeys[a]: Advisory(
            akeys[a],
            str(store.adv_canon[a]),
            str(store.adv_id[a]),
            float(store.adv_sev[a]),
            bool(store.adv_withdrawn[a]),
            None if apub[a] == _MIN else int(apub[a]),
        )
        for a in range(A)
    }
    return g, advs


def exposures(
    g: TypedGraph,
    advisories: dict[str, Advisory],
    root_key: str,
    *,
    as_of=None,
    max_depth: int = 12,
) -> tuple[list[Exposure], bool]:
    """Every (advisory, shortest path) reaching ``root_key``'s resolved tree.

    Returns ``(exposures, truncated)``. With ``as_of``, only dependency edges and
    advisories that existed on that date are visible.
    """
    root = g.node(root_key)
    if root < 0:
        raise KeyError(f"unknown root {root_key!r}")
    t = to_ts(as_of)
    aff = g.rel("affects")
    paths, truncated = find_paths(
        g,
        [root],
        ["resolves_to"],
        lambda v: len(aff.out_edges(v, as_of=t)[0]) > 0,
        as_of=t,
        max_depth=max_depth,
    )
    out = []
    for p in paths:
        nbrs, eids = aff.out_edges(p.terminal, as_of=t)
        for a, e in zip(nbrs.tolist(), eids.tolist()):
            hop = Path(
                (*p.nodes, a), (*p.edges, ("affects", e)), p.confidence * float(aff.confidence[e])
            )
            out.append(Exposure(advisories[str(g.keys[a])], hop))
    out.sort(key=lambda x: (x.depth, -x.advisory.severity, x.advisory.key))
    return out, truncated


def software_ladder(min_severity: float = 0.0, min_confidence: float = 0.0) -> Ladder[Exposure]:
    """The CVE gates as core gates. Ordering matches ``scgraph.ladder``."""
    return Ladder(
        [
            Gate(
                "only_withdrawn_advisories",
                "every affected path runs through a withdrawn advisory",
                lambda x, ctx: not x.advisory.withdrawn,
            ),
            Gate(
                "below_severity_floor",
                f"all matched advisories below CVSS {min_severity}",
                # severity 0.0 means "unscored", which is not "harmless"
                lambda x, ctx: x.advisory.severity >= min_severity or x.advisory.severity == 0.0,
            ),
            min_confidence_gate(min_confidence),
        ],
        no_evidence_reason="no resolved dependency path reaches an affected version",
    )


def audit(
    g: TypedGraph,
    advisories: dict[str, Advisory],
    root_key: str,
    *,
    as_of=None,
    min_severity: float = 0.0,
    min_confidence: float = 0.0,
) -> dict:
    """One root -> a deterministic, JSON-serialisable verdict per advisory."""
    ex, truncated = exposures(g, advisories, root_key, as_of=as_of)
    by: dict[str, list[Exposure]] = {}
    for x in ex:
        by.setdefault(x.advisory.canon, []).append(x)
    ladder = software_ladder(min_severity, min_confidence)
    rows: list[dict] = []
    for canon, xs in sorted(by.items()):
        v: Verdict[Exposure] = ladder.evaluate(xs)
        best = v.evidence[0]
        rows.append(
            {
                "advisory": canon,
                "alert": v.alert,
                "verdict": v.reason,
                "severity": max(x.advisory.severity for x in xs),
                "min_depth": min(x.depth for x in xs),
                "path": best.path.render(g),
                "evidence": best.path.evidence(g),
            }
        )
    rows.sort(key=lambda r: (not r["alert"], -float(r["severity"]), str(r["advisory"])))
    return {"root": root_key, "truncated": truncated, "findings": rows}
