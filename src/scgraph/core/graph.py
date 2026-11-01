"""A domain-agnostic typed, temporal, provenanced graph on CSR arrays.

This is the engine under the software-supply-chain analysis, with the domain removed.
Every concept the CVE pipeline relies on is expressed here without reference to packages,
versions or advisories:

  nodes      int32 ids, each with a type (``node_type``) and a stable external ``key``.
  relations  named edge sets (``"resolves_to"``, ``"affects"``, ``"supplies"``, ...).
             Each relation is stored as a forward CSR and a reverse CSR, so both
             "what does X reach" and "what reaches X" are one O(degree) slice.
  edge attrs aligned with the forward CSR, per edge:
               confidence  float32 in [0, 1]. 1.0 for a published fact (a lockfile pin),
                           lower for an inferred edge. Paths carry the product.
               valid_from  int64 epoch seconds, inclusive. The edge exists from here on.
               valid_to    int64 epoch seconds, exclusive. ``OPEN`` means still valid.
               source      int32 index into ``sources``, the provenance of the edge
                           (``"lockfile"``, ``"deps.dev"``, ``"osv"``, ``"customs:2024-Q3"``).

Every query takes an optional ``as_of`` (valid time) and ``min_confidence``. Edges outside
the window or below the floor are invisible, so "what did the graph say on 2021-12-09" is
the same code path as "what does it say now".

The store is content-addressed: ``fingerprint()`` is a SHA-256 over every array, so an
answer can name the exact graph it was computed on (see ``scgraph.core.ledger``).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import numpy as np

from .strings import StrColumn

OPEN = np.iinfo(np.int64).max  # valid_to of an edge that has not been retired
_FORMAT = "scgraph.core.graph/2"


def csr(src: np.ndarray, dst: np.ndarray, n: int) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Sort edges by source and return ``(indptr, indices, order)``.

    ``order`` maps CSR position -> original edge position, so edge attributes can be
    permuted into CSR order with ``attr[order]``.
    """
    src = np.asarray(src, np.int64)
    dst = np.asarray(dst, np.int64)
    if src.shape != dst.shape:
        raise ValueError("src and dst must have the same length")
    if len(src) and (src.min() < 0 or dst.min() < 0 or src.max() >= n or dst.max() >= n):
        raise ValueError(f"edge endpoint out of range [0, {n})")
    order = np.argsort(src, kind="stable")
    indptr = np.zeros(n + 1, np.int64)
    np.cumsum(np.bincount(src, minlength=n), out=indptr[1:])
    return indptr, dst[order].astype(np.int32), order


@dataclass
class Relation:
    """One named edge set, forward CSR + reverse CSR + per-edge attributes.

    Edge ids are positions in the forward CSR. ``rev_eid`` maps a reverse-CSR position to
    the forward edge id, so attributes are shared, never duplicated.
    """

    name: str
    indptr: np.ndarray
    indices: np.ndarray
    rev_indptr: np.ndarray
    rev_indices: np.ndarray
    rev_eid: np.ndarray
    confidence: np.ndarray
    valid_from: np.ndarray
    valid_to: np.ndarray
    source: np.ndarray

    @property
    def n_edges(self) -> int:
        return len(self.indices)

    def src_of(self, eid: int) -> int:
        """Source node of forward edge ``eid`` (binary search over ``indptr``)."""
        return int(np.searchsorted(self.indptr, eid, side="right") - 1)

    def _mask(self, eids: np.ndarray, as_of: int | None, min_confidence: float) -> np.ndarray:
        keep = np.ones(len(eids), bool)
        if as_of is not None:
            keep &= (self.valid_from[eids] <= as_of) & (as_of < self.valid_to[eids])
        if min_confidence > 0.0:
            keep &= self.confidence[eids] >= min_confidence
        return keep

    def out_edges(
        self, node: int, as_of: int | None = None, min_confidence: float = 0.0
    ) -> tuple[np.ndarray, np.ndarray]:
        """``(neighbour ids, edge ids)`` of edges leaving ``node`` that are visible."""
        a, b = int(self.indptr[node]), int(self.indptr[node + 1])
        eids = np.arange(a, b, dtype=np.int64)
        nbr = np.asarray(self.indices[a:b])
        if as_of is None and min_confidence <= 0.0:
            return nbr, eids
        m = self._mask(eids, as_of, min_confidence)
        return nbr[m], eids[m]

    def in_edges(
        self, node: int, as_of: int | None = None, min_confidence: float = 0.0
    ) -> tuple[np.ndarray, np.ndarray]:
        """``(predecessor ids, forward edge ids)`` of edges entering ``node``."""
        a, b = int(self.rev_indptr[node]), int(self.rev_indptr[node + 1])
        eids = np.asarray(self.rev_eid[a:b], np.int64)
        nbr = np.asarray(self.rev_indices[a:b])
        if as_of is None and min_confidence <= 0.0:
            return nbr, eids
        m = self._mask(eids, as_of, min_confidence)
        return nbr[m], eids[m]


@dataclass
class EdgeBatch:
    """Edges for one relation, in any order, before CSR construction."""

    src: Sequence[int] | np.ndarray
    dst: Sequence[int] | np.ndarray
    confidence: Sequence[float] | np.ndarray | None = None
    valid_from: Sequence[int] | np.ndarray | None = None
    valid_to: Sequence[int] | np.ndarray | None = None
    source: str | Sequence[str] = "unspecified"


@dataclass
class TypedGraph:
    """Typed nodes + named relations. Immutable once built; see ``ledger`` for change."""

    node_type: np.ndarray  # int16 per node, index into type_names
    type_names: list[str]
    keys: StrColumn  # str per node: stable external id
    relations: dict[str, Relation]
    sources: list[str]
    meta: dict = field(default_factory=dict)
    _key_order: np.ndarray | None = field(default=None, repr=False)

    # ------------------------------------------------------------------ build
    @classmethod
    def build(
        cls,
        nodes: Iterable[tuple[str, str]],
        edges: dict[str, EdgeBatch],
        meta: dict | None = None,
    ) -> TypedGraph:
        """Build from ``(key, type)`` node pairs and per-relation ``EdgeBatch`` es.

        Node ids are assigned in iteration order. Keys must be unique.
        """
        keys: list[str] = []
        types: list[str] = []
        for k, t in nodes:
            keys.append(str(k))
            types.append(str(t))
        type_names = sorted(set(types))
        tix = {t: i for i, t in enumerate(type_names)}
        node_type = np.array([tix[t] for t in types], np.int16)
        return cls.from_arrays(keys, node_type, type_names, edges, meta)

    @classmethod
    def from_arrays(
        cls,
        keys,
        node_type: np.ndarray,
        type_names: list[str],
        edges: dict[str, EdgeBatch],
        meta: dict | None = None,
    ) -> TypedGraph:
        """Columnar constructor for large graphs: ``keys`` is a list, an Arrow string
        array or a ``StrColumn``; ``node_type`` holds indices into ``type_names``.
        No per-node Python work, so a 20M-node graph builds in seconds."""
        import pyarrow as pa
        import pyarrow.compute as pc

        if isinstance(keys, StrColumn):
            kcol = keys
        elif isinstance(keys, pa.Array | pa.ChunkedArray):
            kcol = StrColumn(*StrColumn.encode_arrow(keys))
        else:
            kcol = StrColumn(*StrColumn.encode(keys))
        n = len(kcol)
        node_type = np.asarray(node_type, np.int16)
        if node_type.shape != (n,):
            raise ValueError("node_type must have one entry per key")
        if n and (node_type.min() < 0 or node_type.max() >= len(type_names)):
            raise ValueError("node_type index out of range of type_names")
        if n and pc.count_distinct(kcol.to_arrow()).as_py() != n:
            raise ValueError("node keys must be unique")
        sources: list[str] = []
        six: dict[str, int] = {}
        rels: dict[str, Relation] = {}
        for name, eb in sorted(edges.items()):
            src = np.asarray(eb.src, np.int64)
            dst = np.asarray(eb.dst, np.int64)
            m = len(src)
            conf = _col(eb.confidence, m, 1.0, np.float32)
            if m and (np.isnan(conf).any() or conf.min() < 0.0 or conf.max() > 1.0):
                raise ValueError(f"{name}: confidence must be in [0, 1]")
            vf = _col(eb.valid_from, m, np.iinfo(np.int64).min, np.int64)
            vt = _col(eb.valid_to, m, OPEN, np.int64)
            if m and (vt <= vf).any():
                raise ValueError(f"{name}: valid_to must be > valid_from for every edge")
            if isinstance(eb.source, str):
                sid = np.full(m, six.setdefault(eb.source, len(six)), np.int32)
            else:
                # factorise in C: unique labels + inverse, then map labels to global ids
                raw = np.asarray(list(eb.source), dtype=object).astype(str)
                if len(raw) != m:
                    raise ValueError(f"{name}: source must be a str or one entry per edge")
                if m:
                    labels, inv = np.unique(raw, return_inverse=True)
                    gid = np.array([six.setdefault(str(x), len(six)) for x in labels], np.int32)
                    sid = gid[np.asarray(inv, np.int64)]
                else:
                    sid = np.zeros(0, np.int32)
            rels[name] = _relation(name, src, dst, n, conf, vf, vt, sid)
        sources = [None] * len(six)  # type: ignore[list-item]
        for s, i in six.items():
            sources[i] = s
        return cls(node_type, list(type_names), kcol, rels, sources, meta or {})

    # ------------------------------------------------------------------ lookup
    @property
    def n_nodes(self) -> int:
        return len(self.node_type)

    def rel(self, name: str) -> Relation:
        try:
            return self.relations[name]
        except KeyError:
            raise KeyError(f"unknown relation {name!r}; have {sorted(self.relations)}") from None

    def node(self, key: str) -> int:
        """External key -> node id, or -1."""
        return self.keys.find(key, self.key_order)

    @property
    def key_order(self) -> np.ndarray:
        """Node ids sorted by key: the lookup index. Computed in C once (and persisted by
        ``save``), so a lookup is a binary search with no per-node Python."""
        if self._key_order is None:
            self._key_order = self.keys.sort_order()
        return self._key_order

    def nodes(self, keys: list[str]) -> np.ndarray:
        """Many keys -> node ids (-1 where unknown) in one vectorised pass.

        Uses an Arrow hash join over the key column, so resolving a batch of keys never
        builds a Python dict over every node in the graph.
        """
        if not keys:
            return np.empty(0, np.int64)
        import pyarrow as pa
        import pyarrow.compute as pc

        ids = pc.index_in(pa.array(keys, pa.large_string()), value_set=self.keys.to_arrow())
        return ids.fill_null(-1).to_numpy(zero_copy_only=False).astype(np.int64)

    def type_of(self, node: int) -> str:
        return self.type_names[int(self.node_type[node])]

    def nodes_of_type(self, type_name: str) -> np.ndarray:
        if type_name not in self.type_names:
            return np.empty(0, np.int64)
        return np.flatnonzero(self.node_type == self.type_names.index(type_name))

    def edge_record(self, relation: str, eid: int) -> dict:
        """Everything known about one edge: the unit of provenance in an answer."""
        r = self.rel(relation)
        vt = int(r.valid_to[eid])
        return {
            "relation": relation,
            "src": str(self.keys[r.src_of(eid)]),
            "dst": str(self.keys[int(r.indices[eid])]),
            "confidence": float(r.confidence[eid]),
            "valid_from": int(r.valid_from[eid]),
            "valid_to": None if vt == OPEN else vt,
            "source": self.sources[int(r.source[eid])],
        }

    # ------------------------------------------------------------------ identity
    def fingerprint(self) -> str:
        """SHA-256 over every array and name. Equal graphs have equal fingerprints."""
        h = hashlib.sha256(_FORMAT.encode())
        h.update(json.dumps([self.type_names, self.sources], sort_keys=True).encode())
        _hash_arr(h, self.node_type)
        # keys as their canonical string-column encoding (offsets + UTF-8 blob): hashing
        # two flat buffers, with no per-key Python, whatever form the keys are in
        if isinstance(self.keys, StrColumn):
            blob, off = np.asarray(self.keys._blob), np.asarray(self.keys._off)
        else:
            blob, off = StrColumn.encode(self.keys)
        _hash_arr(h, off)
        _hash_arr(h, blob)
        _hash_arr(h, np.asarray(self.key_order, np.int64))  # the lookup index is covered too
        for name in sorted(self.relations):
            r = self.relations[name]
            h.update(name.encode())
            for a in (r.indptr, r.indices, r.confidence, r.valid_from, r.valid_to, r.source):
                _hash_arr(h, a)
        return h.hexdigest()

    # ------------------------------------------------------------------ persistence
    def save(self, path: str | Path) -> str:
        """Write to a directory of ``.npy`` files; returns the fingerprint."""
        d = Path(path)
        d.mkdir(parents=True, exist_ok=True)
        np.save(d / "node_type.npy", self.node_type)
        StrColumn.save(d / "keys", self.keys)
        np.save(d / "keys.order.npy", self.key_order)
        for name, r in self.relations.items():
            _check_name(name)
            for f in _REL_FIELDS:
                np.save(d / f"rel.{name}.{f}.npy", getattr(r, f))
        fp = self.fingerprint()
        manifest = {
            "format": _FORMAT,
            "type_names": self.type_names,
            "sources": self.sources,
            "relations": sorted(self.relations),
            "meta": self.meta,
            "fingerprint": fp,
        }
        (d / "graph.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
        return fp

    @classmethod
    def load(cls, path: str | Path, mmap: bool = True, verify: bool = True) -> TypedGraph:
        """Open a saved graph. Arrays are memory-mapped; no pickle is ever loaded."""
        d = Path(path)
        man = json.loads((d / "graph.json").read_text())
        if man.get("format") != _FORMAT:
            raise ValueError(f"unsupported graph format {man.get('format')!r}")
        mode: Literal["r"] | None = "r" if mmap else None
        load = lambda f: np.load(d / f, mmap_mode=mode, allow_pickle=False)  # noqa: E731
        rels = {}
        for name in man["relations"]:
            _check_name(name)
            rels[name] = Relation(name, *(load(f"rel.{name}.{f}.npy") for f in _REL_FIELDS))
        keys = StrColumn.load(d / "keys")
        order = load("keys.order.npy")
        g = cls(load("node_type.npy"), man["type_names"], keys, rels, man["sources"], man["meta"])
        g._key_order = order
        if verify and g.fingerprint() != man["fingerprint"]:
            raise ValueError(f"fingerprint mismatch for {d}: the graph on disk was modified")
        return g


_REL_FIELDS = (
    "indptr",
    "indices",
    "rev_indptr",
    "rev_indices",
    "rev_eid",
    "confidence",
    "valid_from",
    "valid_to",
    "source",
)


def _relation(name, src, dst, n, conf, vf, vt, sid) -> Relation:
    indptr, indices, order = csr(src, dst, n)
    fwd_src = src[order]
    rev_indptr, rev_indices, rorder = csr(indices.astype(np.int64), fwd_src, n)
    return Relation(
        name,
        indptr,
        indices,
        rev_indptr,
        rev_indices,
        rorder.astype(np.int64),  # reverse position -> forward edge id
        conf[order],
        vf[order],
        vt[order],
        sid[order],
    )


def _col(v, m: int, default, dtype) -> np.ndarray:
    if v is None:
        return np.full(m, default, dtype)
    a = np.asarray(v, dtype)
    if a.shape != (m,):
        raise ValueError(f"edge attribute has length {len(a)}, expected {m}")
    return a


def _hash_arr(h, a: np.ndarray) -> None:
    a = np.ascontiguousarray(a)
    h.update(str(a.dtype).encode())
    h.update(str(a.shape).encode())
    h.update(a.tobytes())


def _check_name(name: str) -> None:
    if not name or not all(c.isalnum() or c in "_-" for c in name):
        raise ValueError(f"relation name {name!r} must be alphanumeric, '_' or '-'")
