import json

import pytest

from scgraph.core import EdgeBatch, Ledger, LedgerError, Receipt, TypedGraph, find_paths

D = "2021-12-01"


def _base():
    nodes = [("app", "v"), ("lib", "v"), ("log", "v")]
    return TypedGraph.build(nodes, {"dep": EdgeBatch([0], [1], source="lock")})


def _reach(src, dst):
    def fn(g, as_of):
        paths, _ = find_paths(g, [g.node(src)], ["dep"], lambda v: v == g.node(dst), as_of=as_of)
        return [p.render(g) for p in paths]

    return fn


@pytest.fixture
def led(tmp_path):
    L = Ledger.create(tmp_path / "L", _base(), recorded_at=D)
    L.add_edge(
        "dep", "lib", "log", valid_from="2021-12-05", source="lock", recorded_at="2021-12-06"
    )
    return L


def test_bitemporal_views(led):
    q = _reach("app", "log")
    # known only the base: no path, whatever the valid time
    assert q(led.view(known_at="2021-12-02")[0], None) == []
    g, seq = led.view(known_at="2021-12-07")
    assert seq == 0
    assert q(g, None) and q(g, 1638662400)  # 2021-12-05 00:00 UTC, inclusive
    assert q(g, 1638662399) == []  # one second before it became true


def test_retire_and_retract_keep_history(led):
    q = _reach("app", "log")
    led.retire_edge("dep", "lib", "log", valid_to="2021-12-10", recorded_at="2021-12-11")
    g, _ = led.view()
    assert q(g, 1638748800) and q(g, 1639180800) == []  # 12-06 yes, 12-11 no
    led.retract_edge("dep", "app", "lib", reason="bad lockfile parse", recorded_at="2021-12-12")
    assert q(led.view()[0], 1638748800) == []
    # what we knew on 12-11 is unchanged by the 12-12 correction
    assert q(led.view(known_at="2021-12-11")[0], 1638748800)


def test_receipts_verify_and_detect_divergence(led, tmp_path):
    fn = _reach("app", "log")
    res, rec = led.answer({"q": "reach", "src": "app", "dst": "log"}, fn, known_at="2021-12-07")
    assert res and led.check(Receipt.from_json(rec.to_json()), fn)
    # same answer after more history is appended and the ledger reopened
    led.add_node("new", "v", recorded_at="2022-01-01")
    assert Ledger(led.dir).check(rec, fn)
    forged = Receipt(**{**json.loads(rec.to_json()), "result_hash": "0" * 64})
    assert not led.check(forged, fn)


def test_tamper_evident_log(led):
    led.add_node("x", "v", recorded_at="2021-12-08")
    lines = (led.dir / "log.jsonl").read_text().splitlines()
    rec = json.loads(lines[0])
    rec["body"]["dst"] = "app"
    lines[0] = json.dumps(rec)
    (led.dir / "log.jsonl").write_text("\n".join(lines) + "\n")
    with pytest.raises(LedgerError, match="hash mismatch"):
        Ledger(led.dir).verify()
    lines.pop(0)
    (led.dir / "log.jsonl").write_text("\n".join(lines) + "\n")
    with pytest.raises(LedgerError):
        Ledger(led.dir).verify()


def test_compaction_preserves_every_answer(led):
    fn = _reach("app", "log")
    _, before = led.answer({"q": 1}, fn)
    _, early = led.answer({"q": 1}, fn, known_at="2021-12-02")
    assert led.compact() == 0
    L2 = Ledger(led.dir)
    assert L2.verify() == 1
    assert L2.check(before, fn)  # compaction does not change any answer's identity
    res_now, _ = L2.answer({"q": 1}, fn)
    assert res_now and L2.answer({"q": 1}, fn, known_at="2021-12-02")[0] == []
    assert L2.check(early, fn)


def test_write_validation(led):
    with pytest.raises(LedgerError, match="earlier"):
        led.add_node("y", "v", recorded_at="2020-01-01")
    with pytest.raises(LedgerError, match="confidence"):
        led.add_edge("dep", "app", "log", confidence=2.0)
    with pytest.raises(LedgerError, match="before"):
        led.view(known_at="2000-01-01")
    led.add_edge("dep", "app", "ghost", recorded_at="2022-01-01")
    with pytest.raises(LedgerError, match="unknown node"):
        led.view()
    with pytest.raises(LedgerError, match="already"):
        Ledger.create(led.dir, _base(), recorded_at=D)


def test_compacted_and_replayed_views_are_identical(tmp_path):
    base = TypedGraph.build(
        [("a", "v"), ("b", "v")],
        {"dep": EdgeBatch([0], [1], source="lock"), "other": EdgeBatch([1], [0])},
    )
    A = Ledger.create(tmp_path / "A", base, recorded_at=0)
    B = Ledger.create(tmp_path / "B", base, recorded_at=0)
    ops = [
        ("add_node", ("c", "w"), {"recorded_at": 1}),
        (
            "add_edge",
            ("dep", "b", "c"),
            {"source": "inferred", "confidence": 0.6, "recorded_at": 2},
        ),
        ("retire_edge", ("dep", "a", "b"), {"valid_to": 50, "recorded_at": 3}),
        ("add_edge", ("dep", "c", "a"), {"recorded_at": 4}),
        ("retract_edge", ("dep", "b", "c"), {"reason": "dup", "recorded_at": 5}),
    ]
    for i, (op, args, kw) in enumerate(ops):
        for L in (A, B):
            getattr(L, op)(*args, **kw)
        if i == 1:
            B.compact()
    ga, gb = A.view()[0], B.view()[0]
    assert ga.fingerprint() == gb.fingerprint()
    assert ga.type_of(ga.node("c")) == "w"
    assert len(ga.rel("other").out_edges(ga.node("c"))[0]) == 0  # padded, untouched relation
    assert [ga.edge_record("dep", e)["valid_to"] for e in range(ga.rel("dep").n_edges)] == [
        50,
        None,
    ]


def test_concurrent_writers_never_fork_the_chain(led):
    other = Ledger(led.dir)  # a second process's handle, with a stale in-memory head
    led.add_node("p", "v", recorded_at="2022-01-01")
    other.add_node("q", "v", recorded_at="2022-01-02")
    assert Ledger(led.dir).verify() == 3


def test_interrupted_compaction_is_ignored(led):
    import shutil

    shutil.copytree(led.dir / "base" / "-1", led.dir / "base" / ".tmp-9")
    assert Ledger(led.dir).verify() == 1


def test_retire_before_valid_from_means_never_valid(led):
    led.retire_edge("dep", "lib", "log", valid_to="2021-12-01", recorded_at="2021-12-07")
    g = led.view()[0]
    assert g.rel("dep").n_edges == 1  # only app->lib remains; no 1-second ghost window


def test_retire_base_edge_vectorised(tmp_path):
    base = TypedGraph.build(
        [(k, "v") for k in "abc"],
        {"dep": EdgeBatch([0, 1, 0], [1, 2, 2], valid_from=[0, 100, 0])},
    )
    L = Ledger.create(tmp_path / "L", base, recorded_at=0)
    L.retire_edge("dep", "a", "b", valid_to=50, recorded_at=1)
    L.retire_edge("dep", "a", "b", valid_to=70, recorded_at=2)  # already closed: no effect
    L.retire_edge("dep", "b", "c", valid_to=60, recorded_at=3)  # before it began: dropped
    g = L.view()[0]
    recs = sorted(
        (r["src"], r["dst"], r["valid_to"])
        for r in (g.edge_record("dep", e) for e in range(g.rel("dep").n_edges))
    )
    assert recs == [("a", "b", 50), ("a", "c", None)]


def test_readers_see_other_writers(led):
    reader = Ledger(led.dir)
    led.retract_edge("dep", "lib", "log", reason="x", recorded_at="2022-01-01")
    assert reader.view()[1] == 1


def test_failed_create_leaves_no_ledger(tmp_path):
    bad = TypedGraph.build([("a", "v")], {"a/b": EdgeBatch([], [])})
    with pytest.raises(ValueError):
        Ledger.create(tmp_path / "L", bad, recorded_at=0)
    Ledger.create(tmp_path / "L", _base(), recorded_at=0)  # retry succeeds
