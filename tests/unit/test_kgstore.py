"""The CSR graph store: build determinism, adjacency, and lookups."""

from __future__ import annotations

import shutil

import numpy as np
import pyarrow as pa
import pytest

from scgraph import build_graph
from scgraph.kgstore import KGStore, LegacyFormatError, StrColumn, migrate_legacy


def test_dimensions(tiny_graph: KGStore) -> None:
    assert tiny_graph.N == 9  # versions
    assert len(tiny_graph.pkg_name) == 6
    assert len(tiny_graph.res_indices) == 3
    assert len(tiny_graph.aff_ids) == 2


def test_forward_and_reverse_adjacency_agree(tiny_graph: KGStore) -> None:
    # app@1.0.0 (ver 0) resolves to web-framework@2.1.0 (ver 1)
    assert 1 in list(tiny_graph.resolves_to(0))
    # and web-framework@2.1.0 has app@1.0.0 as a dependent
    assert 0 in list(tiny_graph.dependents(1))


def test_package_level_graph(tiny_graph: KGStore) -> None:
    log4j = tiny_graph.pkg_id("maven", "org.apache.logging.log4j:log4j-core")
    framework = tiny_graph.pkg_id("maven", "com.example:web-framework")
    assert log4j >= 0 and framework >= 0
    assert log4j in list(tiny_graph.pkg_deps(framework))
    assert framework in list(tiny_graph.pkg_dependents(log4j))


def test_pkg_id_missing_returns_negative(tiny_graph: KGStore) -> None:
    assert tiny_graph.pkg_id("npm", "does-not-exist") < 0


def test_advisories_of_the_vulnerable_version(tiny_graph: KGStore) -> None:
    # log4j-core@2.12.1 is ver 3, affected by SEC-1
    assert len(list(tiny_graph.advisories_of(3))) == 1
    # log4j-core@2.17.0 is ver 4, patched
    assert len(list(tiny_graph.advisories_of(4))) == 0


def test_build_is_deterministic(tiny_corpus, tmp_path) -> None:
    a = tmp_path / "a"
    b = tmp_path / "b"
    stats_a = build_graph(str(tiny_corpus), str(a))
    stats_b = build_graph(str(tiny_corpus), str(b))
    assert stats_a == stats_b
    for name in ("res_indptr", "res_indices", "aff_adv_ids", "ver_pkg"):
        assert (a / f"{name}.npy").read_bytes() == (b / f"{name}.npy").read_bytes()


# ---- pickle-free string columns -------------------------------------------------


@pytest.mark.parametrize("vals", [[], ["a"], ["", "héllo", "日本", "x" * 1000], [None, "b"]])
def test_strcolumn_roundtrip_python_and_arrow(tmp_path, vals):
    StrColumn.save(tmp_path / "p", vals)
    StrColumn.save(tmp_path / "a", pa.chunked_array([pa.array(vals, pa.string())]))
    want = ["" if v is None else v for v in vals]
    for name in ("p", "a"):
        c = StrColumn.load(tmp_path / name)
        assert list(c) == want and len(c) == len(want)
        if want:
            assert c[-1] == want[-1] and list(c[[0]]) == [want[0]]
            assert list(np.asarray(c)) == want


def test_strcolumn_sliced_arrow_and_bounds(tmp_path):
    arr = pa.array(["skip", "keep", "me"]).slice(1)
    StrColumn.save(tmp_path / "s", arr)
    c = StrColumn.load(tmp_path / "s")
    assert list(c) == ["keep", "me"]
    with pytest.raises(IndexError):
        c[2]


def test_store_files_contain_no_pickle(tiny_graph, tiny_corpus):
    for f in (tiny_corpus.parent / "graph").glob("*.npy"):
        np.load(f, allow_pickle=False)  # raises if any file needs pickle


def test_legacy_pickled_store_is_refused_then_migrated(tiny_corpus, tmp_path):
    g = tmp_path / "g"
    shutil.copytree(tiny_corpus.parent / "graph", g)
    for n in ("pkg_name", "ver_str"):
        vals = StrColumn.load(g / n).tolist()
        for suf in (".utf8.npy", ".off.npy"):
            (g / f"{n}{suf}").unlink()
        np.save(g / f"{n}.npy", np.array(vals, dtype=object), allow_pickle=True)
    (g / "pkgver_indptr.npy").unlink()
    with pytest.raises(LegacyFormatError, match="migrate"):
        KGStore(str(g))
    assert set(migrate_legacy(str(g))) == {"pkg_name", "ver_str", "pkgver"}
    s = KGStore(str(g))
    assert s.pkg_name[2] == "org.apache.logging.log4j:log4j-core"
    assert s.versions_of(2) == [3, 4]


def test_pkg_id_binary_search_matches_names(tiny_graph: KGStore) -> None:
    for pid, (e, n) in enumerate(zip(tiny_graph.pkg_eco, tiny_graph.pkg_name)):
        assert tiny_graph.pkg_id(e, n) == pid
    assert tiny_graph.pkg_id("npm", "nope") == -1
    assert tiny_graph.pkg_id("maven", "lib-safe") == -1  # right name, wrong ecosystem


def test_build_with_no_packages(tmp_path, tiny_corpus) -> None:
    import pyarrow.parquet as pq

    pqd = tmp_path / "pq"
    shutil.copytree(tiny_corpus, pqd)
    for t in ("packages", "versions", "resolved", "affected_versions"):
        tab = pq.read_table(pqd / f"{t}.parquet")
        pq.write_table(tab.slice(0, 0), pqd / f"{t}.parquet")
    stats = build_graph(str(pqd), str(tmp_path / "g"))
    assert stats["versions"] == 0 and stats["resolves_edges"] == 0
