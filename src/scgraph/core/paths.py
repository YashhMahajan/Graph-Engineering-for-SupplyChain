"""Path search over a ``TypedGraph``: the path is the evidence.

``find_paths`` walks one or more relations from a set of roots and returns every
shortest path that ends on a node satisfying ``is_target``. Each path carries its edge
ids, so it can be rendered with full provenance (source, confidence, validity) and its
strength is computed from its edges, not asserted.

Path strength is the product of edge confidences. A path made of published facts has
strength 1.0; one inferred hop at 0.7 makes the whole claim 0.7. Callers set
``min_path_confidence`` to drop paths that are not strong enough to alert on, and the
gate ladder (``scgraph.core.gates``) turns that into an explicit abstention.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

from .graph import TypedGraph


@dataclass(frozen=True)
class Path:
    nodes: tuple[int, ...]
    edges: tuple[tuple[str, int], ...]  # (relation, forward edge id) per hop
    confidence: float

    @property
    def depth(self) -> int:
        return len(self.edges)

    @property
    def terminal(self) -> int:
        return self.nodes[-1]

    def render(self, g: TypedGraph) -> str:
        parts = [str(g.keys[self.nodes[0]])]
        for (rel, _), n in zip(self.edges, self.nodes[1:]):
            parts.append(f"-[{rel}]-> {g.keys[n]}")
        return " ".join(parts) + f"  (confidence {self.confidence:.3f})"

    def evidence(self, g: TypedGraph) -> list[dict]:
        """One provenance record per hop, the auditable form of the path."""
        return [g.edge_record(rel, eid) for rel, eid in self.edges]


def find_paths(
    g: TypedGraph,
    roots: Iterable[int],
    relations: Sequence[str],
    is_target: Callable[[int], bool],
    *,
    as_of: int | None = None,
    min_edge_confidence: float = 0.0,
    min_path_confidence: float = 0.0,
    max_depth: int = 12,
    max_paths: int = 1000,
    node_budget: int = 1_000_000,
    reverse: bool = False,
) -> tuple[list[Path], bool]:
    """BFS from ``roots`` along ``relations``.

    Returns ``(paths, truncated)``. ``truncated`` is True when ``max_paths`` or
    ``node_budget`` cut the search short, so a caller can never mistake "we stopped
    looking" for "there is no path". Each node is expanded once (on its first, therefore
    shortest, arrival); among equal-depth arrivals the higher-confidence one wins because
    edges are relaxed per BFS layer.
    """
    rels = [g.rel(r) for r in relations]
    out: list[Path] = []
    best: dict[int, Path] = {}
    frontier: list[int] = []
    for r in dict.fromkeys(int(x) for x in roots):
        if not 0 <= r < g.n_nodes:
            raise IndexError(f"root {r} out of range")
        best[r] = Path((r,), (), 1.0)
        frontier.append(r)
    truncated = False
    depth = 0
    for r in frontier:
        if is_target(r):
            out.append(best[r])
    while frontier and depth < max_depth:
        depth += 1
        layer: dict[int, Path] = {}
        for u in frontier:
            pu = best[u]
            for rel, name in zip(rels, relations):
                fn = rel.in_edges if reverse else rel.out_edges
                nbrs, eids = fn(u, as_of=as_of, min_confidence=min_edge_confidence)
                for v, e in zip(nbrs.tolist(), eids.tolist()):
                    if v in best:
                        continue
                    c = pu.confidence * float(rel.confidence[e])
                    if c < min_path_confidence:
                        continue
                    cur = layer.get(v)
                    if cur is None or c > cur.confidence:
                        layer[v] = Path((*pu.nodes, v), (*pu.edges, (name, e)), c)
        best.update(layer)
        if len(best) > node_budget:
            truncated = True
        frontier = list(layer)
        for v in frontier:
            if is_target(v):
                out.append(layer[v])
                if len(out) >= max_paths:
                    return out, True
        if truncated:
            break
    if frontier and not truncated:
        # stopped at max_depth: truncated only if some visible edge leads somewhere new
        for u in frontier:
            for rel in rels:
                fn = rel.in_edges if reverse else rel.out_edges
                nbrs = fn(u, as_of=as_of, min_confidence=min_edge_confidence)[0]
                if any(v not in best for v in nbrs.tolist()):
                    return out, True
    return out, truncated


def reachable(
    g: TypedGraph,
    roots: Iterable[int],
    relations: Sequence[str],
    *,
    as_of: int | None = None,
    min_edge_confidence: float = 0.0,
    reverse: bool = False,
    max_depth: int | None = None,
) -> set[int]:
    """Every node reachable from ``roots`` (roots included). No path bookkeeping."""
    rels = [g.rel(r) for r in relations]
    seen = {int(r) for r in roots}
    q = deque((r, 0) for r in seen)
    while q:
        u, d = q.popleft()
        if max_depth is not None and d >= max_depth:
            continue
        for rel in rels:
            fn = rel.in_edges if reverse else rel.out_edges
            for v in fn(u, as_of=as_of, min_confidence=min_edge_confidence)[0].tolist():
                if v not in seen:
                    seen.add(v)
                    q.append((v, d + 1))
    return seen
