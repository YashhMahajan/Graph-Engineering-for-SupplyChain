"""Benchmark the CSR store end to end on a synthetic corpus of configurable size.

    python scripts/bench/bench_kgstore.py --versions 2000000 --out /tmp/bench

Measures build (parquet -> CSR), load (KGStore()), and single-manifest audit latency
(exposure_paths + ladder) at p50 / p99. The synthetic graph is heavy-tailed (Zipf
in-degree) like the real one, so hub fan-out is exercised. Numbers go to stdout as JSON.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq


def synth(pq_dir: Path, n_ver: int, seed: int = 0) -> None:
    rng = np.random.default_rng(seed)
    n_pkg = max(1, n_ver // 5)
    pkg_of = np.sort(rng.integers(0, n_pkg, n_ver)).astype(np.int32)
    eco = np.array(["npm", "pypi", "maven", "cargo"])[rng.integers(0, 4, n_pkg)]
    pq_dir.mkdir(parents=True, exist_ok=True)
    pq.write_table(
        pa.table(
            {
                "pkg_id": np.arange(n_pkg, dtype=np.int32),
                "ecosystem": eco,
                "name": [f"pkg-{i}" for i in range(n_pkg)],
            }
        ),
        pq_dir / "packages.parquet",
    )
    pq.write_table(
        pa.table(
            {
                "ver_id": np.arange(n_ver, dtype=np.int32),
                "pkg_id": pkg_of,
                "version": [f"1.{i % 50}.{i % 7}" for i in range(n_ver)],
                "is_default": rng.random(n_ver) < 0.2,
            }
        ),
        pq_dir / "versions.parquet",
    )
    m = n_ver * 4
    src = rng.integers(0, n_ver, m)
    dst = (rng.zipf(1.6, m) - 1) % n_ver  # heavy-tailed in-degree
    pq.write_table(
        pa.table({"ver_id": src.astype(np.int32), "res_ver_id": dst.astype(np.int32)}),
        pq_dir / "resolved.parquet",
    )
    n_adv = max(1, n_ver // 100)
    ids = [f"GHSA-{i}" for i in range(n_adv)]
    pq.write_table(
        pa.table(
            {
                "adv_id": np.arange(n_adv, dtype=np.int32),
                "osv_id": ids,
                "canon_id": [f"CVE-{i}" for i in range(n_adv)],
                "summary": ["synthetic advisory text " * 4] * n_adv,
                "severity": rng.uniform(0, 10, n_adv).astype(np.float32),
                "withdrawn": rng.random(n_adv) < 0.01,
                "published": ["2021-01-01"] * n_adv,
            }
        ),
        pq_dir / "advisories.parquet",
    )
    k = n_ver // 20
    pq.write_table(
        pa.table(
            {
                "adv_id": rng.integers(0, n_adv, k).astype(np.int32),
                "ver_id": rng.integers(0, n_ver, k).astype(np.int32),
            }
        ),
        pq_dir / "affected_versions.parquet",
    )
    pq.write_table(
        pa.table({"osv_id": ids, "alias": [f"CVE-{i}" for i in range(n_adv)]}),
        pq_dir / "aliases.parquet",
    )
    (pq_dir / "_osv_meta.json").write_text(
        json.dumps({"canon": {o: f"CVE-{i}" for i, o in enumerate(ids)}, "withdrawn": []})
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--versions", type=int, default=1_000_000)
    ap.add_argument("--audits", type=int, default=2000)
    ap.add_argument("--out", default="/tmp/scgraph-bench")
    a = ap.parse_args()
    from scgraph.kgstore import KGStore, build
    from scgraph.paths import exposure_paths

    out = Path(a.out)
    t = time.perf_counter()
    synth(out / "pq", a.versions)
    t_synth = time.perf_counter() - t
    t = time.perf_counter()
    build(str(out / "pq"), str(out / "graph"))
    t_build = time.perf_counter() - t
    t = time.perf_counter()
    S = KGStore(str(out / "graph"))
    t_load = time.perf_counter() - t
    rng = np.random.default_rng(1)
    roots = rng.integers(0, S.N, a.audits)
    lat = []
    for r in roots:
        t = time.perf_counter()
        exposure_paths(S, int(r), max_depth=6, max_paths=50)
        lat.append(time.perf_counter() - t)
    lat_ms = np.array(lat) * 1e3
    print(
        json.dumps(
            {
                "versions": int(S.N),
                "edges": len(S.res_indices),
                "synth_s": round(t_synth, 2),
                "build_s": round(t_build, 2),
                "load_s": round(t_load, 3),
                "audit_p50_ms": round(float(np.percentile(lat_ms, 50)), 3),
                "audit_p99_ms": round(float(np.percentile(lat_ms, 99)), 3),
                "audits_per_s": round(a.audits / (lat_ms.sum() / 1e3), 1),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
