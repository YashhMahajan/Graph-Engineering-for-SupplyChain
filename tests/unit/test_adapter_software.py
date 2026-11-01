from scgraph.adapters import software
from scgraph.paths import exposure_paths

APP = "ver:maven/com.example:app@1.0.0"


def test_core_matches_legacy_exposure_paths(tiny_graph):
    g, advs = software.from_kgstore(tiny_graph)
    ex, trunc = software.exposures(g, advs, APP)
    legacy = exposure_paths(tiny_graph, 0)
    assert not trunc
    assert {(x.advisory.canon, x.depth) for x in ex} == {(p.advisory, p.depth) for p in legacy}


def test_as_of_hides_unpublished_advisory(tiny_graph):
    g, advs = software.from_kgstore(tiny_graph)
    assert software.audit(g, advs, APP, as_of="2021-12-09")["findings"] == []
    r = software.audit(g, advs, APP, as_of="2021-12-10")
    assert [f["advisory"] for f in r["findings"] if f["alert"]] == ["CVE-2021-44228"]
    hops = r["findings"][0]["evidence"]
    assert [h["source"] for h in hops] == ["resolver", "resolver", "osv"]


def test_severity_gate_abstains_with_reason(tiny_graph):
    g, advs = software.from_kgstore(tiny_graph)
    f = software.audit(g, advs, APP, min_severity=10.5)["findings"][0]
    assert not f["alert"] and f["verdict"] == "below_severity_floor"


def test_patched_tree_is_clean(tiny_graph):
    g, advs = software.from_kgstore(tiny_graph)
    assert software.audit(g, advs, "ver:maven/com.example:cli-tool@3.0.0")["findings"] == []
