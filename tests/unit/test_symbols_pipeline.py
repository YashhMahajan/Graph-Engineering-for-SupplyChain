"""Verifier, Engine B search, finalize and the dataset manifest (in-memory releases)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scgraph.symbols.candidates import build_candidates
from scgraph.symbols.dataset import DatasetError, load, write
from scgraph.symbols.diff import parse_unified
from scgraph.symbols.fetch import Fix, FixRef
from scgraph.symbols.pipeline import Prepared, finalize, task_for
from scgraph.symbols.rank import HEURISTIC, Ranker, rank
from scgraph.symbols.retrieve import search
from scgraph.symbols.select import Choice
from scgraph.symbols.source import Release
from scgraph.symbols.verify import release_diff, verify

AFF = {
    "yaml/__init__.py": (
        "from .loader import load\ndef safe_load(stream):\n    return load(stream, SafeLoader)\n"
    ),
    "yaml/loader.py": (
        "def load(stream, Loader=None):\n    '''Parse the first YAML document in a stream.'''\n"
        "    return construct_python_object(stream)\n\n"
        "def construct_python_object(node):\n    return eval_object(node)\n\n"
        "def dump(data):\n    return str(data)\n"
    ),
}
FIX = {
    "yaml/__init__.py": AFF["yaml/__init__.py"],
    "yaml/loader.py": AFF["yaml/loader.py"].replace(
        "    return eval_object(node)",
        "    if unsafe(node):\n        raise Error\n    return eval_object(node)",
    ),
}


def releases() -> tuple[Release, Release]:
    return Release("PyPI", "pyyaml", "5.3", dict(AFF)), Release("PyPI", "pyyaml", "5.4", dict(FIX))


def test_verifier_statuses() -> None:
    aff, fix = releases()
    assert verify(aff, fix, "yaml.loader", "construct_python_object").status == "verified"
    v = verify(aff, fix, "yaml.loader", "load")
    assert v.status == "verified" and "construct_python_object" in v.detail  # calls a changed fn
    assert verify(aff, fix, "yaml.loader", "dump").status == "unchanged_in_fix"
    assert verify(aff, fix, "yaml.loader", "nope").status == "not_in_affected"
    assert verify(aff, None, "yaml.loader", "load").status == "present_only"
    assert verify(None, fix, "yaml.loader", "load").status == "source_unavailable"
    assert release_diff(aff, fix) == {("yaml.loader", "construct_python_object")}


def test_engine_b_search_uses_text_and_the_release_diff() -> None:
    aff, fix = releases()
    text = "Arbitrary code execution when constructing python objects in the full loader"
    hits, info = search(text, aff, fix, k=3)
    assert hits[0].func.qualname == "construct_python_object" and hits[0].changed
    assert info["release_diff"] == 1 and info["functions"] == 4
    hits_no_diff, _ = search(text, aff, None, k=3)
    assert hits_no_diff[0].func.qualname == "construct_python_object"  # text alone still finds it
    assert "eval_object" in hits[0].excerpt(aff)


DIFF = (
    "--- a/yaml/loader.py\n+++ b/yaml/loader.py\n@@ -6,2 +6,4 @@\n def construct_python_object(node):\n"
    "+    if unsafe(node):\n+        raise Error\n     return eval_object(node)\n"
)
REC = {
    "id": "GHSA-xxxx",
    "aliases": ["CVE-2020-1747"],
    "summary": "Arbitrary code execution in construct_python_object",
    "affected": [],
}


def prepared_fix() -> Prepared:
    aff, fix = releases()
    cs = build_candidates(
        parse_unified(DIFF), {"yaml/loader.py": FIX["yaml/loader.py"]}, REC["summary"]
    )
    ref = FixRef(
        "yaml", "pyyaml", "commit", "a" * 40, "https://github.com/yaml/pyyaml/commit/" + "a" * 40
    )
    return Prepared(
        REC,
        "PyPI",
        "pyyaml",
        "fix",
        fix=Fix(ref, "a" * 40, parse_unified(DIFF)),
        cset=cs,
        ranked=rank(cs.candidates, Ranker(weights=dict(HEURISTIC))),
        affected=aff,
        fixed=fix,
        versions=("5.3", "5.4"),
    )


def test_finalize_records_the_verified_symbol_its_entry_points_and_evidence() -> None:
    p = prepared_fix()
    r = finalize(p)
    assert r is not None
    assert r.symbol == "yaml.loader.construct_python_object" and r.method == "fix-diff"
    assert r.verified == "verified" and r.aliases == ["CVE-2020-1747"]
    assert "yaml.loader.load" in r.entry_points and "yaml.load" in r.entry_points  # re-export
    assert "yaml.safe_load" in r.entry_points
    assert r.evidence["fix"].endswith("a" * 40) and r.llm is None


def test_finalize_puts_the_llm_choice_first_and_records_its_provenance() -> None:
    p = prepared_fix()
    caller = next(c for c in p.ranked if c.via_caller).symbol
    ch = Choice("GHSA-xxxx", caller, [caller], 0.7, "x", False, "r", "m:free", "h" * 64)
    r = finalize(p, ch)
    assert r is not None and r.symbol == caller and r.method == "fix-diff+llm"
    assert r.llm and r.llm["model"] == "m:free" and r.confidence == 0.7


def test_an_llm_none_in_search_mode_abstains() -> None:
    aff, fix = releases()
    hits, _ = search("code execution constructing python objects", aff, fix)
    p = Prepared(REC, "PyPI", "pyyaml", "search", hits=hits, affected=aff, fixed=fix)
    assert task_for(p) is not None and task_for(p).mode == "search"  # type: ignore[union-attr]
    assert finalize(p, Choice("GHSA-xxxx", None, model="m")) is None
    assert finalize(p) is not None


def test_dataset_roundtrip_and_tamper_check(tmp_path: Path) -> None:
    r = finalize(prepared_fix())
    assert r is not None
    path = tmp_path / "pypi.jsonl"
    m = write([r.to_dict()], path, generator="unit")
    assert m["count"] == 1 and m["methods"] == ["fix-diff"]
    idx = load(path)
    assert idx.get(["CVE-2020-1747"])["symbol"] == r.symbol  # type: ignore[index]
    assert idx.get(["CVE-2020-1747"], package="other") is None
    path.write_text(path.read_text().replace("construct", "Construct"))
    with pytest.raises(DatasetError):
        load(path)
    assert len(load(tmp_path / "missing.jsonl")) == 0
    json.dumps({})
