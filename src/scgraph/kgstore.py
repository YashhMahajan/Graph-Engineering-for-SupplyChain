"""CSR memmap graph store — the notebook §5/§6 argument, transplanted.

Neo4j has no bulk edge loader; billions of `CREATE` at 1-5 ms each is days before a
query runs, and a server cannot answer a k-hop expansion in the microseconds an agent
loop needs. Compressed Sparse Row: edges sorted by source give
`indptr[i]..indptr[i+1]` -> a slice of `indices` = i's neighbours. O(degree), no
allocation, no IPC. Both directions are stored so "what breaks if I bump X" is also
one slice.

Arrays (saved as .npy, opened mmap_mode='r', allow_pickle=False; nothing executes on load):
  res_indptr, res_indices        Version --RESOLVES_TO--> Version   (forward)
  rdep_indptr, rdep_indices      Version <--RESOLVES_TO-- Version   (reverse / dependents)
  aff_adv_indptr, aff_adv_ids    Version --is affected by--> Advisory
  pkgver_indptr, pkgver_indices  Package -> its versions
  ver_pkg                        ver_id -> pkg_id
  adv_sev (float32), adv_withdrawn (bool)
String columns (StrColumn: <name>.utf8.npy blob + <name>.off.npy offsets):
  ver_str, ver_published, pkg_eco, pkg_name, adv_id_str, adv_canon, adv_published,
  adv_summary
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import numpy as np
import pyarrow.parquet as pq

from .core.strings import StrColumn


def _csr(src, dst, n):
    """Build (indptr, indices) for edges src->dst over n source nodes, sorted by source.

    Stable, so edges keep their input order within a source. ``bincount`` + ``cumsum``
    builds indptr in one pass (``np.add.at`` is an unbuffered scatter, ~10x slower).
    """
    src = np.asarray(src, np.int64)
    dst = np.asarray(dst, np.int64)
    order = np.argsort(src, kind="stable")
    indptr = np.zeros(n + 1, np.int64)
    np.cumsum(np.bincount(src, minlength=n), out=indptr[1:])
    return indptr, dst[order].astype(np.int32)


_STR_COLUMNS = (
    "ver_str",
    "ver_published",
    "pkg_eco",
    "pkg_name",
    "adv_id_str",
    "adv_canon",
    "adv_published",
    "adv_summary",
)


class LegacyFormatError(RuntimeError):
    pass


def _col(table, name, dtype=None):
    """One parquet column as a numpy array, without a trip through Python lists."""
    a = table.column(name).to_numpy(zero_copy_only=False)
    return a if dtype is None else a.astype(dtype, copy=False)


def build(pq_dir: str, graph_dir: str) -> dict:
    PQ, G = Path(pq_dir), Path(graph_dir)
    G.mkdir(parents=True, exist_ok=True)

    pkgs = pq.read_table(PQ / "packages.parquet")
    vers = pq.read_table(PQ / "versions.parquet")
    res = pq.read_table(PQ / "resolved.parquet")
    advs = pq.read_table(PQ / "advisories.parquet")
    affv = pq.read_table(PQ / "affected_versions.parquet")
    meta = json.loads((PQ / "_osv_meta.json").read_text())

    N = vers.num_rows
    A = advs.num_rows
    P = pkgs.num_rows
    r_src = _col(res, "ver_id", np.int64)
    r_dst = _col(res, "res_ver_id", np.int64)

    ri, rx = _csr(r_src, r_dst, N)
    di, dx = _csr(r_dst, r_src, N)  # reverse
    ai, ax = _csr(_col(affv, "ver_id", np.int64), _col(affv, "adv_id", np.int64), N)

    np.save(G / "res_indptr.npy", ri)
    np.save(G / "res_indices.npy", rx)
    np.save(G / "rdep_indptr.npy", di)
    np.save(G / "rdep_indices.npy", dx)
    np.save(G / "aff_adv_indptr.npy", ai)
    np.save(G / "aff_adv_ids.npy", ax)
    ver_pkg = _col(vers, "pkg_id", np.int32)
    np.save(G / "ver_pkg.npy", ver_pkg)
    # package -> its versions, as CSR, so KGStore() needs no per-version Python loop
    pvi, pvx = _csr(ver_pkg.astype(np.int64), np.arange(N, dtype=np.int64), P)
    np.save(G / "pkgver_indptr.npy", pvi)
    np.save(G / "pkgver_indices.npy", pvx)

    # ---- package-level resolved graph: pkg A -> pkg B if any A-version resolves to
    #      any B-version. This is the graph for centrality / k-core / systemic risk.
    #      Dedup on one int64 code per pair: 1-D unique is a plain sort, where
    #      unique(axis=0) sorts structured rows and was most of the build time.
    pe = ver_pkg[r_src].astype(np.int64)
    pd = ver_pkg[r_dst].astype(np.int64)
    m = pe != pd
    code = np.sort(pe[m] * P + pd[m])
    if len(code):
        code = code[np.concatenate(([True], code[1:] != code[:-1]))]
    ps, pt = code // P, code % P
    pi = np.zeros(P + 1, np.int64)  # codes are sorted by source: no argsort needed
    np.cumsum(np.bincount(ps, minlength=P), out=pi[1:])
    px = pt.astype(np.int32)
    ppi, ppx = _csr(pt, ps, P)  # reverse (dependents)
    np.save(G / "pkgdep_indptr.npy", pi)
    np.save(G / "pkgdep_indices.npy", px)
    np.save(G / "pkgrev_indptr.npy", ppi)
    np.save(G / "pkgrev_indices.npy", ppx)
    StrColumn.save(G / "ver_str", vers.column("version"))
    np.save(G / "ver_default.npy", _col(vers, "is_default", bool))
    if "published" in vers.column_names:  # FULL loader carries version dates
        StrColumn.save(G / "ver_published", vers.column("published"))
    StrColumn.save(G / "pkg_eco", pkgs.column("ecosystem"))
    StrColumn.save(G / "pkg_name", pkgs.column("name"))

    osv_ids = advs.column("osv_id").to_pylist()
    canon = meta["canon"]
    wd = set(meta["withdrawn"])
    al = pq.read_table(PQ / "aliases.parquet").to_pydict()
    alias_map: dict[str, list[str]] = {}
    for oid, a in zip(al["osv_id"], al["alias"]):
        alias_map.setdefault(oid, []).append(a)
    StrColumn.save(G / "adv_id_str", osv_ids)
    StrColumn.save(G / "adv_canon", [canon.get(o, o) for o in osv_ids])
    (G / "adv_aliases.json").write_text(
        json.dumps({o: alias_map[o] for o in osv_ids if alias_map.get(o)})
    )
    np.save(G / "adv_sev.npy", _col(advs, "severity", np.float32))
    np.save(G / "adv_withdrawn.npy", np.array([o in wd for o in osv_ids], bool))
    StrColumn.save(G / "adv_published", advs.column("published"))
    StrColumn.save(G / "adv_summary", advs.column("summary"))

    stats = {"versions": N, "advisories": A, "resolves_edges": len(rx), "affected_edges": len(ax)}
    (G / "_csr_stats.json").write_text(json.dumps(stats, indent=2))
    return stats


def migrate_legacy(graph_dir: str) -> list[str]:
    """Convert a graph directory written by scgraph <= 1.0 (pickled object arrays) to
    the pickle-free format, in place. Returns the converted column names.

    This *does* unpickle the old files, so run it only on a directory you built yourself
    or verified by checksum. That is the point: the trust decision is made once, here,
    explicitly, instead of on every load.
    """
    G = Path(graph_dir)
    done = []
    for name in _STR_COLUMNS:
        old = G / f"{name}.npy"
        if old.exists() and not StrColumn.exists(G / name):
            StrColumn.save(G / name, np.load(old, allow_pickle=True).tolist())
            old.unlink()
            done.append(name)
    if not (G / "pkgver_indptr.npy").exists():
        ver_pkg = np.load(G / "ver_pkg.npy")
        P = len(StrColumn.load(G / "pkg_name"))
        pvi, pvx = _csr(ver_pkg.astype(np.int64), np.arange(len(ver_pkg)), P)
        np.save(G / "pkgver_indptr.npy", pvi)
        np.save(G / "pkgver_indices.npy", pvx)
        done.append("pkgver")
    return done


class KGStore:
    def __init__(self, graph_dir: str):
        t0 = time.time()
        G = Path(graph_dir)
        legacy = [n for n in _STR_COLUMNS if (G / f"{n}.npy").exists()]
        if legacy:
            raise LegacyFormatError(
                f"{G} uses the pickled format of scgraph <= 1.0 ({', '.join(legacy)}). "
                "Loading it would unpickle file contents, which can execute code. If you "
                "built or checksum-verified this directory, convert it once with "
                f"`python -m scgraph.kgstore --migrate {G}`, or rebuild it."
            )
        L = lambda n: np.load(G / f"{n}.npy", mmap_mode="r", allow_pickle=False)  # noqa: E731
        LS = lambda n: StrColumn.load(G / n)  # noqa: E731
        self.res_indptr, self.res_indices = L("res_indptr"), L("res_indices")
        self.rdep_indptr, self.rdep_indices = L("rdep_indptr"), L("rdep_indices")
        self.aff_indptr, self.aff_ids = L("aff_adv_indptr"), L("aff_adv_ids")
        self.pkgdep_indptr, self.pkgdep_indices = L("pkgdep_indptr"), L("pkgdep_indices")
        self.pkgrev_indptr, self.pkgrev_indices = L("pkgrev_indptr"), L("pkgrev_indices")
        self.pkgver_indptr, self.pkgver_indices = L("pkgver_indptr"), L("pkgver_indices")
        self.ver_pkg = L("ver_pkg")
        self.ver_str = LS("ver_str")
        self.ver_default = L("ver_default")
        self.ver_published = LS("ver_published") if StrColumn.exists(G / "ver_published") else None
        self.pkg_eco = LS("pkg_eco")
        self.pkg_name = LS("pkg_name")
        self.adv_id = LS("adv_id_str")
        self.adv_canon = LS("adv_canon")
        try:
            self.adv_aliases = json.loads((G / "adv_aliases.json").read_text())
        except FileNotFoundError:
            self.adv_aliases = {}
        self.adv_sev = L("adv_sev")
        self.adv_withdrawn = L("adv_withdrawn")
        self.adv_published = LS("adv_published")
        self.adv_summary = LS("adv_summary")
        self.N, self.A = len(self.ver_pkg), len(self.adv_id)
        self.canon_to_idx: dict[str, int] = {}
        for i, c in enumerate(self.adv_canon):
            self.canon_to_idx.setdefault(c, i)
        self._pkg_index: dict[tuple[str, str], int] | None = None
        self.load_secs = time.time() - t0

    @property
    def pkg_index(self) -> dict[tuple[str, str], int]:
        """(ecosystem, name) -> pkg_id. Built on first use, not at load: most queries
        start from a version id and never need it."""
        if self._pkg_index is None:
            self._pkg_index = {
                (e, n): i for i, (e, n) in enumerate(zip(self.pkg_eco, self.pkg_name))
            }
        return self._pkg_index

    # --- traversal ---
    def resolves_to(self, vid):
        return self.res_indices[self.res_indptr[vid] : self.res_indptr[vid + 1]]

    def dependents(self, vid):
        return self.rdep_indices[self.rdep_indptr[vid] : self.rdep_indptr[vid + 1]]

    def advisories_of(self, vid):
        return self.aff_ids[self.aff_indptr[vid] : self.aff_indptr[vid + 1]]

    def pkg_deps(self, pid):
        return self.pkgdep_indices[self.pkgdep_indptr[pid] : self.pkgdep_indptr[pid + 1]]

    def pkg_dependents(self, pid):
        return self.pkgrev_indices[self.pkgrev_indptr[pid] : self.pkgrev_indptr[pid + 1]]

    # --- lookup ---
    def pkg_id(self, ecosystem, name):
        return self.pkg_index.get((ecosystem, name), -1)

    def versions_of(self, pid) -> list[int]:
        pid = int(pid)
        if not 0 <= pid < len(self.pkgver_indptr) - 1:
            return []
        a, b = int(self.pkgver_indptr[pid]), int(self.pkgver_indptr[pid + 1])
        return np.asarray(self.pkgver_indices[a:b]).tolist()

    def default_version(self, pid):
        vs = self.versions_of(pid)
        for vid in vs:
            if self.ver_default[vid]:
                return vid
        return vs[-1] if vs else -1


if __name__ == "__main__":
    import sys

    if len(sys.argv) == 3 and sys.argv[1] == "--migrate":
        print("converted:", migrate_legacy(sys.argv[2]) or "nothing (already current)")
        raise SystemExit(0)
    base = Path(__file__).resolve().parent.parent
    print(json.dumps(build(str(base / "data" / "parquet"), str(base / "data" / "graph")), indent=2))
    S = KGStore(str(base / "data" / "graph"))
    print(f"load {S.load_secs * 1000:.1f} ms  versions={S.N:,}  advisories={S.A:,}")
