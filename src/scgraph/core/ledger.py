"""A bitemporal, append-only, hash-chained ledger over a ``TypedGraph``.

Two problems with a batch snapshot, both fatal in production:

1. **Change.** New advisories land every hour. Rebuilding an 82.8M-edge CSR store for
   each one takes minutes. The ledger records changes as deltas against a base snapshot
   and materialises a view on demand; ``compact()`` folds deltas into a new base.

2. **Accountability.** "Were we exposed on 2021-12-09?" and "what did we *know* on
   2021-12-09?" are different questions. An auditor asks the second. The ledger keeps
   two clocks per change:

     valid time     when the fact is true in the world (``valid_from`` / ``valid_to``)
     recorded time  when the ledger learned it (``recorded_at``)

   ``view(valid_at=t1, known_at=t2)`` is the graph as it stood at ``t1`` using only what
   had been recorded by ``t2``. A late correction (``retract``) changes the answer for
   ``known_at`` after it was recorded and leaves every earlier answer intact.

Every delta carries ``prev`` and ``hash`` (SHA-256 over the canonical record and the
previous hash), so the log is tamper-evident: editing or deleting any past line breaks
``verify()``. A ``Receipt`` binds an answer to the base fingerprint, the log head it was
computed from, both clocks, the canonical query and a hash of the result, so anyone with
the ledger can recompute it and prove the answer was what it claims.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import numpy as np

from .graph import OPEN, Relation, TypedGraph, _check_name, _relation
from .strings import StrColumn

GENESIS = "0" * 64

try:  # POSIX
    import fcntl

    def _lock(f) -> None:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)

    def _unlock(f) -> None:
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)

except ImportError:  # Windows
    import msvcrt

    def _lock(f) -> None:
        f.seek(0)
        msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)  # type: ignore[attr-defined]

    def _unlock(f) -> None:
        f.seek(0)
        msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]


_OPS = {"add_node", "add_edge", "retire_edge", "retract_edge"}
_MIN = np.iinfo(np.int64).min


def to_ts(t: int | float | str | datetime | date | None) -> int | None:
    """Epoch seconds from an int, an ISO-8601 string, a date or a datetime (UTC assumed)."""
    if t is None:
        return None
    if isinstance(t, bool):
        raise TypeError("bool is not a timestamp")
    if isinstance(t, int | float | np.integer):
        return int(t)
    if isinstance(t, str):
        t = datetime.fromisoformat(t.replace("Z", "+00:00"))
    if isinstance(t, datetime):
        if t.tzinfo is None:
            t = t.replace(tzinfo=UTC)
        return int(t.timestamp())
    if isinstance(t, date):
        return int(datetime(t.year, t.month, t.day, tzinfo=UTC).timestamp())
    raise TypeError(f"cannot convert {type(t).__name__} to a timestamp")


def canonical(obj: Any) -> str:
    """Canonical JSON: sorted keys, no whitespace, so equal objects hash equally."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=_jsonable)


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _jsonable(o: Any) -> Any:
    if isinstance(o, np.integer):
        return int(o)
    if isinstance(o, np.floating):
        return float(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    if isinstance(o, set | frozenset):
        return sorted(o)
    if hasattr(o, "__dataclass_fields__"):
        return asdict(o)
    raise TypeError(f"not JSON-serialisable: {type(o).__name__}")


@dataclass(frozen=True)
class Delta:
    seq: int
    op: str
    recorded_at: int
    body: dict
    prev: str
    hash: str

    @staticmethod
    def digest(seq: int, op: str, recorded_at: int, body: dict, prev: str) -> str:
        return sha256(canonical([seq, op, recorded_at, body, prev]))


@dataclass(frozen=True)
class Receipt:
    """Everything needed to recompute and verify one answer."""

    base_fingerprint: str  # genesis snapshot
    log_seq: int  # last delta included (-1: base only)
    log_hash: str  # hash of that delta (GENESIS: base only)
    valid_at: int | None
    known_at: int
    query: dict
    result_hash: str

    def to_json(self) -> str:
        return canonical(asdict(self))

    @classmethod
    def from_json(cls, s: str) -> Receipt:
        return cls(**json.loads(s))


class LedgerError(ValueError):
    pass


class Ledger:
    """Directory layout::

    base/<seq>/      TypedGraph snapshots; <seq> is the last delta folded in (-1 = initial)
    log.jsonl        append-only, hash-chained deltas
    """

    def __init__(self, path: str | Path):
        self.dir = Path(path)
        if not (self.dir / "base").is_dir():
            raise LedgerError(f"{self.dir} is not a ledger (no base/); use Ledger.create")
        self._log_path = self.dir / "log.jsonl"
        self._deltas: list[Delta] = self._read_log()
        self._log_size = self._log_path.stat().st_size if self._log_path.exists() else 0
        self._bases = self._scan_bases()
        self._cache: dict[tuple[int, int], TypedGraph] = {}

    # ------------------------------------------------------------------ create / open
    @classmethod
    def create(
        cls, path: str | Path, base: TypedGraph, recorded_at: int | str | datetime
    ) -> Ledger:
        d = Path(path)
        if (d / "base").exists():
            raise LedgerError(f"{d} already holds a ledger")
        meta = dict(base.meta)
        meta["recorded_at"] = to_ts(recorded_at)
        meta["base_seq"] = -1
        g = TypedGraph(
            base.node_type, base.type_names, base.keys, base.relations, base.sources, meta
        )
        for name in g.relations:
            _check_name(name)
        tmp = d / f".create-{os.getpid()}"
        g.save(tmp / "base" / "-1")
        (tmp / "log.jsonl").touch()
        (tmp / "base").rename(d / "base")  # publishing base/ is what makes it a ledger
        (tmp / "log.jsonl").rename(d / "log.jsonl")
        tmp.rmdir()
        return cls(d)

    def _read_log(self, f=None) -> list[Delta]:
        """Parse the log. Pass an open handle to read through it (needed while holding the
        write lock: Windows byte-range locks are mandatory for other handles)."""
        if f is None:
            if not self._log_path.exists():
                return []
            with self._log_path.open() as g:
                return self._read_log(g)
        f.seek(0)
        out: list[Delta] = []
        for i, line in enumerate(f.read().splitlines()):
            if not line.strip():
                continue
            try:
                out.append(Delta(**json.loads(line)))
            except (json.JSONDecodeError, TypeError) as exc:
                raise LedgerError(f"log line {i + 1} is corrupt: {exc}") from exc
        return out

    def refresh(self) -> None:
        """Pick up deltas and snapshots written by other handles or processes."""
        size = self._log_path.stat().st_size if self._log_path.exists() else 0
        if size != self._log_size:
            self._deltas = self._read_log()
            self._log_size = size
        self._bases = self._scan_bases()

    def _scan_bases(self) -> list[tuple[int, int]]:
        """Sorted ``(base_seq, recorded_at)`` of every snapshot on disk."""
        out = []
        for p in (self.dir / "base").iterdir():
            if p.name.startswith("."):  # an interrupted compaction; never a published base
                continue
            meta = json.loads((p / "graph.json").read_text())["meta"]
            out.append((int(meta["base_seq"]), int(meta["recorded_at"])))
        return sorted(out)

    # ------------------------------------------------------------------ integrity
    @property
    def head(self) -> tuple[int, str]:
        if not self._deltas:
            return -1, GENESIS
        d = self._deltas[-1]
        return d.seq, d.hash

    def verify(self, snapshots: bool = True) -> int:
        """Check the hash chain and clock monotonicity, and (``snapshots=True``) re-hash
        every base snapshot. Returns the number of deltas."""
        self.refresh()
        prev = GENESIS
        last_t = self._bases[0][1]
        for i, d in enumerate(self._deltas):
            if d.seq != i:
                raise LedgerError(f"delta {i}: seq {d.seq} out of order")
            if d.prev != prev:
                raise LedgerError(f"delta {i}: chain broken (prev does not match)")
            if Delta.digest(d.seq, d.op, d.recorded_at, d.body, d.prev) != d.hash:
                raise LedgerError(f"delta {i}: hash mismatch, record was altered")
            if d.recorded_at < last_t:
                raise LedgerError(f"delta {i}: recorded_at goes backwards")
            prev, last_t = d.hash, d.recorded_at
        if snapshots:
            for seq, _ in self._bases:
                TypedGraph.load(self.dir / "base" / str(seq), verify=True)
        return len(self._deltas)

    # ------------------------------------------------------------------ write
    def _append(self, op: str, body: dict, recorded_at: Any) -> Delta:
        if op not in _OPS:
            raise LedgerError(f"unknown op {op!r}")
        t = to_ts(recorded_at) if recorded_at is not None else int(time.time())
        assert t is not None
        with self._log_path.open("a+") as f:
            # one writer at a time; re-read the log under the lock so a concurrent
            # writer's deltas are chained onto, never forked from
            _lock(f)
            try:
                self._deltas = self._read_log(f)
                floor = self._deltas[-1].recorded_at if self._deltas else self._bases[0][1]
                if t < floor:
                    raise LedgerError(f"recorded_at {t} is earlier than the ledger head ({floor})")
                seq, prev = self.head
                seq += 1
                d = Delta(seq, op, t, body, prev, Delta.digest(seq, op, t, body, prev))
                f.write(canonical(asdict(d)) + "\n")
                f.flush()
                os.fsync(f.fileno())
                self._log_size = f.tell()
            finally:
                _unlock(f)
        self._deltas.append(d)
        return d

    def add_node(self, key: str, type_name: str, recorded_at: Any = None) -> Delta:
        return self._append("add_node", {"key": str(key), "type": str(type_name)}, recorded_at)

    def add_edge(
        self,
        relation: str,
        src: str,
        dst: str,
        *,
        valid_from: Any = None,
        valid_to: Any = None,
        confidence: float = 1.0,
        source: str = "unspecified",
        recorded_at: Any = None,
    ) -> Delta:
        if not 0.0 <= confidence <= 1.0:
            raise LedgerError("confidence must be in [0, 1]")
        vf, vt = to_ts(valid_from), to_ts(valid_to)
        if vf is not None and vt is not None and vt <= vf:
            raise LedgerError("valid_to must be after valid_from")
        body = {
            "relation": relation,
            "src": str(src),
            "dst": str(dst),
            "valid_from": vf,
            "valid_to": vt,
            "confidence": float(confidence),
            "source": source,
        }
        return self._append("add_edge", body, recorded_at)

    def retire_edge(
        self, relation: str, src: str, dst: str, *, valid_to: Any, recorded_at: Any = None
    ) -> Delta:
        """The edge stopped being true at ``valid_to`` (e.g. a dependency was dropped)."""
        if valid_to is None:
            raise LedgerError("retire_edge needs valid_to")
        body = {"relation": relation, "src": str(src), "dst": str(dst), "valid_to": to_ts(valid_to)}
        return self._append("retire_edge", body, recorded_at)

    def retract_edge(
        self, relation: str, src: str, dst: str, *, reason: str, recorded_at: Any = None
    ) -> Delta:
        """The edge was never true; it was recorded in error. Earlier ``known_at`` views
        still show it, because that is what was known then."""
        body = {"relation": relation, "src": str(src), "dst": str(dst), "reason": reason}
        return self._append("retract_edge", body, recorded_at)

    # ------------------------------------------------------------------ read
    def _upto(self, known_at: int) -> int:
        """Index of the last delta recorded at or before ``known_at`` (-1 if none)."""
        last = -1
        for d in self._deltas:
            if d.recorded_at > known_at:
                break
            last = d.seq
        return last

    def view(self, known_at: Any = None) -> tuple[TypedGraph, int]:
        """The graph using only what was recorded by ``known_at`` (default: everything).

        Returns ``(graph, last_seq)``. Valid-time filtering is a query parameter
        (``as_of=``) on the returned graph, so one view answers every ``valid_at``.
        """
        self.refresh()
        kt = to_ts(known_at)
        if kt is None:
            kt = self._deltas[-1].recorded_at if self._deltas else self._bases[-1][1]
        if kt < self._bases[0][1]:
            raise LedgerError("known_at is before the ledger's first snapshot: nothing was known")
        upto = self._upto(kt)
        base_seq = max(s for s, t in self._bases if s <= upto and t <= kt)
        key = (base_seq, upto)
        if key not in self._cache:
            base = TypedGraph.load(self.dir / "base" / str(base_seq))
            todo = self._deltas[base_seq + 1 : upto + 1]
            self._cache[key] = _apply(base, todo) if todo else base
            if len(self._cache) > 8:
                self._cache.pop(next(iter(self._cache)))
        return self._cache[key], upto

    def answer(
        self,
        query: dict,
        fn: Callable[[TypedGraph, int | None], Any],
        *,
        valid_at: Any = None,
        known_at: Any = None,
    ) -> tuple[Any, Receipt]:
        """Run ``fn(graph, valid_at)`` on the right view and return ``(result, receipt)``.

        ``query`` must fully describe what ``fn`` computes (the same query on the same
        view must give the same result); it is stored verbatim in the receipt.
        """
        g, upto = self.view(known_at)
        kt = to_ts(known_at)
        if kt is None:
            kt = self._deltas[upto].recorded_at if upto >= 0 else self._bases[0][1]
        va = to_ts(valid_at)
        result = fn(g, va)
        r = Receipt(
            # the genesis snapshot, not the compacted base: compaction is an optimisation
            # and must not change the identity of any answer
            base_fingerprint=json.loads((self.dir / "base" / "-1" / "graph.json").read_text())[
                "fingerprint"
            ],
            log_seq=upto,
            log_hash=self._deltas[upto].hash if upto >= 0 else GENESIS,
            valid_at=va,
            known_at=kt,
            query=json.loads(canonical(query)),
            result_hash=sha256(canonical(result)),
        )
        return result, r

    def check(self, receipt: Receipt, fn: Callable[[TypedGraph, int | None], Any]) -> bool:
        """Recompute an answer from its receipt. True iff the result hash matches and the
        receipt's log head is part of this ledger's verified chain. The snapshot the
        answer is recomputed on is fingerprint-checked when it is loaded."""
        self.verify(snapshots=False)
        if receipt.log_seq >= len(self._deltas):
            raise LedgerError("receipt refers to deltas this ledger does not have")
        expect = self._deltas[receipt.log_seq].hash if receipt.log_seq >= 0 else GENESIS
        if expect != receipt.log_hash:
            raise LedgerError("receipt's log head is not in this ledger's history")
        if self._upto(receipt.known_at) != receipt.log_seq:
            raise LedgerError("receipt's known_at does not match its log head")
        _, r = self.answer(receipt.query, fn, valid_at=receipt.valid_at, known_at=receipt.known_at)
        return r == receipt

    # ------------------------------------------------------------------ compaction
    def compact(self) -> int:
        """Fold every delta into a new base snapshot. The log is kept, so history and old
        receipts stay verifiable; future views start from the new base."""
        upto = len(self._deltas) - 1
        if upto < 0 or any(s == upto for s, _ in self._bases):
            return upto
        g, _ = self.view()
        meta = dict(g.meta)
        meta["base_seq"] = upto
        meta["recorded_at"] = self._deltas[upto].recorded_at
        snap = TypedGraph(g.node_type, g.type_names, g.keys, g.relations, g.sources, meta)
        tmp = self.dir / "base" / f".tmp-{upto}"
        snap.save(tmp)
        tmp.rename(self.dir / "base" / str(upto))  # atomic publish
        self._bases = self._scan_bases()
        return upto


# ---------------------------------------------------------------------- materialise
def _apply(base: TypedGraph, deltas: list[Delta]) -> TypedGraph:
    """Replay deltas over a base snapshot into a fresh TypedGraph.

    Cost is proportional to what changed: relations no delta touches are reused as-is
    (their CSR is only padded if nodes were added), and touched relations are rebuilt
    from arrays with retirements / retractions matched by vectorised pair codes.
    """
    nb = base.n_nodes
    new_keys: list[str] = []
    new_types: list[str] = []
    new_index: dict[str, int] = {}

    wanted = sorted(
        {d.body[f] for d in deltas if d.op != "add_node" for f in ("src", "dst")}
        | {d.body["key"] for d in deltas if d.op == "add_node"}
    )
    known = dict(zip(wanted, base.nodes(wanted).tolist()))

    def nid(key: str, where: str) -> int:
        i = known.get(key, -1)
        if i < 0:
            i = new_index.get(key, -1)
        if i < 0:
            raise LedgerError(f"{where}: unknown node {key!r}")
        return i

    sources = list(base.sources)
    six = {x: i for i, x in enumerate(sources)}
    rels: dict[str, dict[str, list]] = {}
    retire: dict[str, list[tuple[tuple[int, int], int]]] = {}
    retract: dict[str, set[tuple[int, int]]] = {}
    for d in deltas:
        b = d.body
        if d.op == "add_node":
            if known.get(b["key"], -1) >= 0 or b["key"] in new_index:
                raise LedgerError(f"delta {d.seq}: node {b['key']!r} already exists")
            new_index[b["key"]] = nb + len(new_keys)
            new_keys.append(b["key"])
            new_types.append(b["type"])
            continue
        rel = b["relation"]
        pair = (nid(b["src"], f"delta {d.seq}"), nid(b["dst"], f"delta {d.seq}"))
        if d.op == "add_edge":
            r = rels.setdefault(rel, {k: [] for k in ("s", "d", "c", "f", "t", "o")})
            r["s"].append(pair[0])
            r["d"].append(pair[1])
            r["c"].append(b["confidence"])
            r["f"].append(_MIN if b["valid_from"] is None else b["valid_from"])
            r["t"].append(OPEN if b["valid_to"] is None else b["valid_to"])
            r["o"].append(six.setdefault(b["source"], len(six)))
        elif d.op == "retire_edge":
            # applies to every open edge of that pair recorded so far, base or delta
            retire.setdefault(rel, []).append((pair, b["valid_to"]))
            pend = rels.get(rel)
            if pend:
                gone = []
                for i in range(len(pend["s"])):
                    if (pend["s"][i], pend["d"][i]) == pair and pend["t"][i] == OPEN:
                        if b["valid_to"] <= pend["f"][i]:
                            gone.append(i)  # retired before it began: never valid
                        else:
                            pend["t"][i] = b["valid_to"]
                if gone:
                    for k in pend:
                        pend[k] = [x for i, x in enumerate(pend[k]) if i not in gone]
        elif d.op == "retract_edge":
            retract.setdefault(rel, set()).add(pair)
            pend = rels.get(rel)
            if pend:
                kept = [i for i in range(len(pend["s"])) if (pend["s"][i], pend["d"][i]) != pair]
                for k in pend:
                    pend[k] = [pend[k][i] for i in kept]
    for x in sorted(six, key=six.__getitem__)[len(sources) :]:
        sources.append(x)

    # node table
    type_names = sorted(set(base.type_names) | set(new_types))
    if new_keys:
        remap = np.array([type_names.index(t) for t in base.type_names], np.int16)
        node_type = np.concatenate(
            [remap[np.asarray(base.node_type)], [type_names.index(t) for t in new_types]]
        ).astype(np.int16)
        keys = StrColumn.concat(base.keys, new_keys)
    else:
        node_type, keys = base.node_type, base.keys
    n = nb + len(new_keys)

    out: dict[str, Relation] = {}
    touched = set(rels) | set(retire) | set(retract)
    for name in sorted(set(base.relations) | touched):
        if name not in touched:
            out[name] = _pad(base.relations[name], n)
            continue
        ps: list[np.ndarray] = []
        pd_: list[np.ndarray] = []
        pc: list[np.ndarray] = []
        pf: list[np.ndarray] = []
        pt: list[np.ndarray] = []
        po: list[np.ndarray] = []
        if name in base.relations:
            R = base.relations[name]
            src = np.repeat(np.arange(nb, dtype=np.int64), np.diff(np.asarray(R.indptr)))
            dst = np.asarray(R.indices, np.int64)
            vt = np.array(R.valid_to, np.int64)
            vf = np.asarray(R.valid_from, np.int64)
            code = src * n + dst
            keep = np.ones(len(src), bool)
            if name in retract:
                codes = np.array([s * n + t for s, t in retract[name]], np.int64)
                keep &= ~np.isin(code, codes)
            if name in retire:
                # first retirement of a pair wins (later ones find the edge closed)
                first: dict[int, int] = {}
                for (s, t), when in retire[name]:
                    first.setdefault(s * n + t, when)
                rc = np.array(sorted(first), np.int64)
                rw = np.array([first[c] for c in rc.tolist()], np.int64)
                pos = np.searchsorted(rc, code)
                pos[pos == len(rc)] = 0
                hit = (rc[pos] == code) & (vt == OPEN)
                wv = rw[pos]
                keep &= ~(hit & (wv <= vf))  # retired before it began: never valid
                vt = np.where(hit, wv, vt)
            ps.append(src[keep])
            pd_.append(dst[keep])
            pc.append(np.asarray(R.confidence)[keep])
            pf.append(vf[keep])
            pt.append(vt[keep])
            po.append(np.asarray(R.source)[keep])
        if name in rels:
            r = rels[name]
            ps.append(np.array(r["s"], np.int64))
            pd_.append(np.array(r["d"], np.int64))
            pc.append(np.array(r["c"], np.float32))
            pf.append(np.array(r["f"], np.int64))
            pt.append(np.array(r["t"], np.int64))
            po.append(np.array(r["o"], np.int32))
        out[name] = _relation(
            name,
            np.concatenate(ps),
            np.concatenate(pd_),
            n,
            np.concatenate(pc).astype(np.float32),
            np.concatenate(pf),
            np.concatenate(pt),
            np.concatenate(po).astype(np.int32),
        )
    return TypedGraph(node_type, type_names, keys, out, sources, dict(base.meta))


def _pad(r: Relation, n: int) -> Relation:
    """Extend a relation's CSR to ``n`` nodes (new nodes have no edges)."""
    extra = n + 1 - len(r.indptr)
    if extra == 0:
        return r
    pad = lambda ip: np.concatenate([ip, np.full(extra, ip[-1], ip.dtype)])  # noqa: E731
    return Relation(
        r.name,
        pad(np.asarray(r.indptr)),
        r.indices,
        pad(np.asarray(r.rev_indptr)),
        r.rev_indices,
        r.rev_eid,
        r.confidence,
        r.valid_from,
        r.valid_to,
        r.source,
    )
