"""Go source references, npm transitive reachability, and the MCP vulnerable-function field."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from scgraph.cli import main
from scgraph.scan.reachability import classify, referenced_names_go, scan_go
from scgraph.symbols.dataset import write
from scgraph.symbols.entry import entry_points
from scgraph.symbols.js import available
from scgraph.symbols.source import Release
from scgraph.symbols.transitive import propagate

GO_SRC = """package main

import (
	"fmt"
	etcd "go.etcd.io/etcd/wal"
	"github.com/foo/bar/v2"
	_ "embed"
)

import "net/http"

func main() {
	w, _ := etcd.Create("etcd.Fake") // etcd.Comment
	var d etcd.Decoder
	bar.New().Run()
	http.ListenAndServe(":80", nil)
	fmt.Println(w, d)
}
"""


def test_go_references_resolve_aliases_versions_and_ignore_strings() -> None:
    names = referenced_names_go(GO_SRC)
    assert {
        "go.etcd.io/etcd/wal.Create",
        "go.etcd.io/etcd/wal.Decoder",
        "github.com/foo/bar/v2.New",
        "net/http.ListenAndServe",
    } <= names
    assert not any("Fake" in n or "Comment" in n or n.endswith(".io") for n in names)
    assert referenced_names_go("package x\nfunc f() { y.Z() }") == set()  # never imported


def test_go_classify_uses_the_symbols_the_go_database_names() -> None:
    direct = ["app", "go.etcd.io/etcd@v3.4.9"]
    syms = ["go.etcd.io/etcd/wal.Create", "go.etcd.io/etcd/wal.WAL.ReadAll"]
    assert classify("Go", direct, syms, {"go.etcd.io/etcd/wal.Create"}) == "reachable"
    assert classify("Go", direct, syms, {"go.etcd.io/etcd/wal.WAL"}) == "class_used"
    assert classify("Go", direct, syms, {"go.etcd.io/etcd/wal.Other"}) == "not_called"


def test_scan_go_skips_tests_and_vendored_code(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text(GO_SRC)
    (tmp_path / "main_test.go").write_text('package main\nimport "x/y"\nfunc T() { y.Z() }')
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "v.go").write_text('package v\nimport "a/b"\nfunc F() { b.C() }')
    names = scan_go(tmp_path)
    assert "go.etcd.io/etcd/wal.Create" in names and "x/y.Z" not in names and "a/b.C" not in names


def test_go_scan_end_to_end(tmp_path: Path, capsys) -> None:
    proj = tmp_path / "p"
    proj.mkdir()
    (proj / "go.mod").write_text("module app\n\ngo 1.21\n\nrequire go.etcd.io/etcd v3.4.9\n")
    (proj / "main.go").write_text(GO_SRC)
    osv = tmp_path / "osv"
    osv.mkdir()
    rec = {
        "id": "GO-2020-0005",
        "summary": "wal",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [
            {
                "package": {"ecosystem": "Go", "name": "go.etcd.io/etcd"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "3.5.0"}]}],
                "ecosystem_specific": {
                    "imports": [{"path": "go.etcd.io/etcd/wal", "symbols": ["Create", "Repair"]}]
                },
            }
        ],
    }
    with zipfile.ZipFile(osv / "go.zip", "w") as z:
        z.writestr("GO-2020-0005.json", json.dumps(rec))
    main(
        [
            "scan",
            str(proj),
            "--offline",
            str(osv),
            "--no-signals",
            "--no-registry",
            "-f",
            "json",
            "--reachability",
        ]
    )
    alert = json.loads(capsys.readouterr().out)["results"][0]["alerts"][0]
    assert alert["reachability"] == "reachable" and alert["symbols_source"] == "osv"


# ----------------------------------------------------------------------------- npm transitive

needs_js = pytest.mark.skipif(not available(), reason="tree-sitter-javascript not installed")


def _npm(name: str, **files: str) -> Release:
    rel = Release("npm", name, "1.0.0", {f"{k.replace('__', '/')}.js": v for k, v in files.items()})
    rel.main = "index.js"
    return rel


@needs_js
def test_npm_chain_reaches_through_the_parents_export_names() -> None:
    child = _npm(
        "kid",
        index="module.exports = require('./lib/parse');\n",
        lib__parse="function decode(s) { return _risky(s); }\nfunction _risky(s) { return eval(s); }\n"
        "module.exports = { decode };\n",
    )
    parent = _npm(
        "par",
        index="const kid = require('kid');\nfunction fetch(u) { return kid.decode(u); }\n"
        "function other(u) { return u; }\nmodule.exports = { fetch, other };\n",
    )
    top = _npm(
        "top",
        index="const par = require('par');\nfunction run(x) { return par.fetch(x); }\nmodule.exports = { run };\n",
    )
    seeds = entry_points(child, "kid/lib/parse", "_risky")
    two = propagate([parent, child], seeds)
    assert two.reached and "par.fetch" in two.names and "par/index.fetch" in two.names
    assert not any("other" in n for n in two.names)  # `other` does not reach it
    three = propagate([top, parent, child], seeds)
    assert three.reached and "top.run" in three.names


@needs_js
def test_npm_chain_breaks_when_the_parent_never_requires_the_child() -> None:
    child = _npm(
        "kid", index="function decode(s) { return eval(s); }\nmodule.exports = { decode };\n"
    )
    stranger = _npm(
        "par", index="function fetch(u) { return u.decode(); }\nmodule.exports = { fetch };\n"
    )
    p = propagate([stranger, child], entry_points(child, "kid/index", "decode"))
    assert not p.reached and p.broke_at == "par"


@needs_js
def test_npm_import_time_calls_become_a_package_wildcard() -> None:
    child = _npm("kid", index="function boot() { return eval('1'); }\nmodule.exports = { boot };\n")
    parent = _npm(
        "par",
        index="const kid = require('kid');\nconst ready = kid.boot();\nmodule.exports = { ready };\n",
    )
    p = propagate([parent, child], entry_points(child, "kid/index", "boot"))
    assert p.reached and "par.*" in p.names


# ----------------------------------------------------------------------------- MCP


def test_explain_advisory_returns_the_verified_function(tmp_path: Path, monkeypatch) -> None:
    from scgraph.scan.agent import _vulnerable_function

    write(
        [
            {
                "id": "GHSA-aaaa-bbbb-cccc",
                "aliases": ["CVE-2024-0001"],
                "ecosystem": "PyPI",
                "package": "pyyaml",
                "symbol": "yaml.load",
                "entry_points": ["yaml.load"],
                "method": "fix-diff",
                "confidence": 0.9,
                "evidence": {"fix": "https://github.com/yaml/pyyaml/commit/abc"},
            }
        ],
        tmp_path / "pypi.jsonl",
    )
    monkeypatch.setenv("SCGRAPH_SYMBOLS", str(tmp_path))
    hit = _vulnerable_function({"id": "CVE-2024-0001", "aliases": []})
    assert hit and hit["symbol"] == "yaml.load" and hit["evidence"].endswith("/commit/abc")
    assert _vulnerable_function({"id": "CVE-9999-0000", "aliases": []}) is None
    (tmp_path / "pypi.jsonl").write_text(
        "{}\n"
    )  # changed after signing the hash: ignored, not fatal
    assert _vulnerable_function({"id": "CVE-2024-0001", "aliases": []}) is None
