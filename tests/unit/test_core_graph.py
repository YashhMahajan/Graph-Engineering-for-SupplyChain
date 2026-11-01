import gc

import numpy as np
import pytest

from scgraph.core import OPEN, EdgeBatch, TypedGraph, find_paths, reachable

T0, T1, T2 = 1_000, 2_000, 3_000


def _g():
    # a -> b -> c -> d ; a -> e (inferred, 0.5) -> d ; b -> c only valid in [T0, T2)
    nodes = [(k, "n") for k in "abcde"]
    edges = {
        "x": EdgeBatch(
            [0, 1, 2, 0, 4],
            [1, 2, 3, 4, 3],
            confidence=[1, 1, 1, 0.5, 1],
            valid_from=[0, T0, 0, 0, 0],
            valid_to=[OPEN, T2, OPEN, OPEN, OPEN],
            source=["lock", "lock", "lock", "inferred", "lock"],
        )
    }
    return TypedGraph.build(nodes, edges)


def test_csr_both_directions_share_edge_attrs():
    g = _g()
    r = g.rel("x")
    nbr, eids = r.in_edges(g.node("d"))
    assert sorted(g.keys[n] for n in nbr) == ["c", "e"]
    for n, e in zip(nbr, eids):
        assert r.indices[e] == g.node("d") and r.src_of(int(e)) == n


def test_validity_and_confidence_filters():
    g = _g()
    r = g.rel("x")
    b = g.node("b")
    assert len(r.out_edges(b, as_of=T1)[0]) == 1
    assert len(r.out_edges(b, as_of=T2)[0]) == 0  # valid_to is exclusive
    assert len(r.out_edges(b, as_of=T0 - 1)[0]) == 0
    assert len(r.out_edges(g.node("a"), min_confidence=0.6)[0]) == 1


def test_find_paths_prefers_stronger_and_respects_time():
    g = _g()
    d = g.node("d")
    paths, trunc = find_paths(g, [g.node("a")], ["x"], lambda v: v == d)
    assert not trunc and len(paths) == 1
    # shortest path is a->e->d (depth 2, conf 0.5)
    assert paths[0].depth == 2 and paths[0].confidence == pytest.approx(0.5)
    paths, _ = find_paths(g, [0], ["x"], lambda v: v == d, min_path_confidence=0.9)
    assert [g.keys[n] for n in paths[0].nodes] == ["a", "b", "c", "d"]
    paths, _ = find_paths(g, [0], ["x"], lambda v: v == d, min_path_confidence=0.9, as_of=T2)
    assert paths == []
    ev = find_paths(g, [0], ["x"], lambda v: v == d)[0][0].evidence(g)
    assert ev[0]["source"] == "inferred" and ev[0]["confidence"] == 0.5


def test_truncation_is_reported_not_hidden():
    g = _g()
    d = g.node("d")
    paths, trunc = find_paths(g, [0], ["x"], lambda v: v == d, max_depth=1)
    assert paths == [] and trunc
    _, trunc = find_paths(g, [0], ["x"], lambda v: False, max_depth=10)
    assert not trunc


def test_reverse_reachability():
    g = _g()
    assert {g.keys[n] for n in reachable(g, [g.node("d")], ["x"], reverse=True)} == set("abcde")


def test_save_load_roundtrip_and_tamper_detection(tmp_path):
    g = _g()
    fp = g.save(tmp_path / "g")
    h = TypedGraph.load(tmp_path / "g")
    assert h.fingerprint() == fp
    assert h.edge_record("x", 0) == g.edge_record("x", 0)
    del h  # release the memory maps: Windows cannot overwrite a mapped file
    gc.collect()
    arr = np.load(tmp_path / "g" / "rel.x.confidence.npy")
    arr[0] = 0.1
    np.save(tmp_path / "g" / "rel.x.confidence.npy", arr)
    with pytest.raises(ValueError, match="fingerprint"):
        TypedGraph.load(tmp_path / "g")


@pytest.mark.parametrize(
    "kw,msg",
    [
        ({"confidence": [1.5]}, "confidence"),
        ({"valid_from": [5], "valid_to": [5]}, "valid_to"),
        ({"source": ["a", "b"]}, "source"),
    ],
)
def test_build_rejects_bad_edges(kw, msg):
    with pytest.raises(ValueError, match=msg):
        TypedGraph.build([("a", "n"), ("b", "n")], {"x": EdgeBatch([0], [1], **kw)})


def test_build_rejects_out_of_range_and_duplicate_keys():
    with pytest.raises(ValueError, match="range"):
        TypedGraph.build([("a", "n")], {"x": EdgeBatch([0], [3])})
    with pytest.raises(ValueError, match="unique"):
        TypedGraph.build([("a", "n"), ("a", "n")], {})


def test_relation_name_is_path_safe(tmp_path):
    g = TypedGraph.build([("a", "n")], {"../evil": EdgeBatch([], [])})
    with pytest.raises(ValueError, match="relation name"):
        g.save(tmp_path / "g")


def test_exact_max_paths_is_not_truncated():
    g = _g()
    paths, trunc = find_paths(g, [0], ["x"], lambda v: v == g.node("d"), max_paths=1)
    assert len(paths) == 1 and not trunc
    paths, trunc = find_paths(g, [0], ["x"], lambda v: v != 0, max_paths=1)
    assert len(paths) == 1 and trunc


def test_keys_are_pickle_free_and_fingerprint_stable(tmp_path):
    g = TypedGraph.build([("ä/1", "n"), ("", "n"), ("b", "m")], {"x": EdgeBatch([0], [2])})
    fp = g.save(tmp_path / "g")
    h = TypedGraph.load(tmp_path / "g")
    assert list(h.keys) == ["ä/1", "", "b"] and h.node("b") == 2
    assert h.fingerprint() == fp == g.fingerprint()
    assert h.save(tmp_path / "h") == fp  # re-saving a loaded graph keeps identity
    for f in (tmp_path / "g").glob("*.npy"):
        np.load(f, allow_pickle=False)


def test_binary_search_lookup_and_order_is_fingerprinted(tmp_path):
    keys = ["b", "a", "ä", "aa", "", "日本", "Z"]
    g = TypedGraph.build([(k, "n") for k in keys], {})
    for i, k in enumerate(keys):
        assert g.node(k) == i
    assert g.node("missing") == -1 and g.node("ab") == -1
    assert list(g.nodes(["Z", "nope", "a"])) == [6, -1, 1]
    g.save(tmp_path / "g")
    order = np.load(tmp_path / "g" / "keys.order.npy")
    np.save(tmp_path / "g" / "keys.order.npy", order[::-1].copy())
    with pytest.raises(ValueError, match="fingerprint"):
        TypedGraph.load(tmp_path / "g")


def test_from_arrays_validates():
    with pytest.raises(ValueError, match="unique"):
        TypedGraph.from_arrays(["a", "a"], np.zeros(2), ["n"], {})
    with pytest.raises(ValueError, match="type"):
        TypedGraph.from_arrays(["a"], np.array([3]), ["n"], {})


def test_reads_v1_graphs_written_before_the_format_change(tmp_path):
    import json

    from scgraph.core.graph import _fingerprint_v1

    g = _g()
    g.save(tmp_path / "g")
    d = tmp_path / "g"
    raw = list(g.keys)
    (d / "keys.json").write_text(json.dumps(raw))
    for f in ("keys.utf8.npy", "keys.off.npy", "keys.order.npy"):
        (d / f).unlink()
    man = json.loads((d / "graph.json").read_text())
    man["format"] = "scgraph.core.graph/1"
    man["fingerprint"] = _fingerprint_v1(g, raw)
    (d / "graph.json").write_text(json.dumps(man))
    h = TypedGraph.load(d)
    assert list(h.keys) == raw and h.node("d") == g.node("d")
    man["fingerprint"] = "0" * 64
    (d / "graph.json").write_text(json.dumps(man))
    with pytest.raises(ValueError, match="fingerprint"):
        TypedGraph.load(d)


def test_corrupt_key_order_fails_even_unverified(tmp_path):
    g = _g()
    g.save(tmp_path / "g")
    np.save(tmp_path / "g" / "keys.order.npy", np.zeros(g.n_nodes, np.int64))
    with pytest.raises(ValueError, match="permutation"):
        TypedGraph.load(tmp_path / "g", verify=False)
