"""npm: the JavaScript parser, export names, project references and an end-to-end scan."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from scgraph.cli import main
from scgraph.scan.reachability import classify, scan_js
from scgraph.symbols.candidates import build_candidates, is_test_path
from scgraph.symbols.dataset import write
from scgraph.symbols.diff import parse_unified
from scgraph.symbols.entry import dotted_names, entry_points
from scgraph.symbols.js import available, parse_js, referenced_names_js
from scgraph.symbols.source import Release

pytestmark = pytest.mark.skipif(not available(), reason="tree-sitter-javascript not installed")

SAMPLE = """
const {parse: p2} = require('qs');
const http = require('http');
class Client extends Base {
  static async make() { return new Client(); }
  get host() { return http.x; }
  send(a) { return http.request(a); }
  _hidden() {}
}
function top(x) { return p2(x) || helper(x); }
function helper(y) { return y; }
const arrow = async (q) => http.get(q);
exports.foo = function named(z) { return top(z); };
module.exports.bar = arrow;
module.exports = { top, baz: helper, qux() { return 1; } };
"""


def test_functions_exports_and_visibility() -> None:
    f = parse_js(SAMPLE)
    by = {x.qualname: x for x in f.functions}
    assert set(by) >= {
        "Client.make",
        "Client.host",
        "Client.send",
        "top",
        "helper",
        "arrow",
        "foo",
        "qux",
    }
    assert f.exports == {"foo": "foo", "bar": "arrow", "top": "top", "baz": "helper", "qux": "qux"}
    assert by["top"].public and by["helper"].public and by["foo"].public and by["arrow"].public
    assert not by["Client.send"].public  # Client is not exported
    assert by["Client.host"].is_property and by["Client.host"].is_method
    assert by["top"].calls == {"helper", "p2"} and "qs.parse" in by["top"].refs


def test_es_module_exports_and_reexports() -> None:
    f = parse_js(
        "export function a(){}\nexport const b = () => 1;\nexport default class K { m(){} }\n"
        "export { a as z };\nexport * from './y';\nexport {q as r} from './r';\n"
    )
    assert f.exports == {"a": "a", "b": "b", "z": "a", "default": "K"}
    assert f.reexports == [("./y", None), ("./r", [("q", "r")])]
    assert {x.qualname: x.public for x in f.functions}["K.m"]  # a method of an exported class


def test_iife_bundles_and_unparseable_source() -> None:
    f = parse_js("(function(root){ root.u = function(){ return 2 }; })(this);")
    assert [x.qualname for x in f.functions] == ["u"]
    assert parse_js("function ((( {").functions == []


def test_project_references_resolve_through_require_and_import() -> None:
    names = referenced_names_js(
        "const _ = require('lodash');\nconst {merge: m} = require('lodash/fp');\n"
        "import d, {x as y} from 'dep';\nimport * as ns from '@s/pkg';\n"
        "_.template(a); m(b); d.go(); y(); ns.run(); require('direct').fn(); const f = require('callme'); f(1);\n"
        "const local = require('./local'); local.nope();"
    )
    assert {
        "lodash.template",
        "lodash/fp.merge",
        "dep.go",
        "dep.x",
        "@s/pkg.run",
        "direct.fn",
        "callme",
    } <= names
    assert not any(n.startswith("./") or "local" in n for n in names)


PKG = Release(
    "npm",
    "qs-like",
    "1.0.0",
    {
        "index.js": "module.exports = require('./lib/parse');\n",
        "lib/parse.js": (
            "function parse(s) { return _decode(s); }\nfunction _decode(s) { return eval(s); }\n"
            "class Parser { run(x) { return _decode(x); } }\n"
            "module.exports = { parse, Parser };\n"
        ),
        "lib/util.js": "exports.helper = function(x) { return x; };\n",
    },
)
PKG.main = "index.js"


def test_names_a_project_uses_for_a_function() -> None:
    mod = "qs-like/lib/parse"
    assert PKG.find(mod, "_decode") is not None
    eps = entry_points(PKG, mod, "_decode")
    assert (mod, "parse") in eps and (mod, "Parser.run") in eps
    names = dotted_names(PKG, eps)
    assert "qs-like.parse" in names  # re-exported from the package entry
    assert "qs-like/lib/parse.parse" in names  # a deep import
    assert "qs-like.Parser.run" in names and "qs-like/lib/parse.Parser.run" in names
    assert not any("helper" in n for n in names)


def test_repository_paths_resolve_to_released_modules() -> None:
    # the fix touched src/parse.js; the package ships lib/parse.js
    loc = PKG.locate("src/parse", "parse")
    assert loc is not None and loc[0] == "qs-like/lib/parse"


def test_classify_and_test_paths_for_npm() -> None:
    assert is_test_path("test/foo.js") and is_test_path("lib/foo.spec.js")
    assert is_test_path("a/__tests__/x.js") and not is_test_path("lib/parse.js")
    direct = ["app", "qs-like@1.0.0"]
    assert classify("npm", direct, ["qs-like.parse"], {"qs-like.parse"}) == "reachable"
    assert classify("npm", direct, ["qs-like.Parser.run"], {"qs-like.Parser"}) == "class_used"
    assert classify("npm", direct, ["qs-like.parse"], {"qs-like.other"}) == "not_called"


def test_candidates_from_a_javascript_fix() -> None:
    diff = (
        "--- a/lib/parse.js\n+++ b/lib/parse.js\n@@ -1,3 +1,4 @@\n function parse(s) { return _decode(s); }\n"
        "-function _decode(s) { return eval(s); }\n+function _decode(s) { if (!s) throw 1; return eval(s); }\n"
    )
    cs = build_candidates(
        parse_unified(diff), {"lib/parse.js": PKG.files["lib/parse.js"]}, "eval in decode"
    )
    by = {c.qualname: c for c in cs.candidates}
    assert "_decode" in by and by["_decode"].module == "lib/parse"
    assert by["parse"].via_caller and by["Parser.run"].via_caller


# ----------------------------------------------------------------------------- scan


def _project(tmp_path: Path, source: str) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "package.json").write_text(
        json.dumps({"name": "app", "dependencies": {"qs-like": "1.0.0"}})
    )
    (proj / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "app",
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "app", "dependencies": {"qs-like": "1.0.0"}},
                    "node_modules/qs-like": {"version": "1.0.0"},
                },
            }
        )
    )
    (proj / "app.js").write_text(source)
    osv = tmp_path / "osv"
    osv.mkdir()
    rec = {
        "id": "GHSA-qs-like",
        "summary": "eval in decode",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "qs-like"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.1.0"}]}],
            }
        ],
    }
    with zipfile.ZipFile(osv / "npm.zip", "w") as z:
        z.writestr("GHSA-qs-like.json", json.dumps(rec))
    write(
        [
            {
                "id": "GHSA-qs-like",
                "aliases": [],
                "ecosystem": "npm",
                "package": "qs-like",
                "symbol": "qs-like/lib/parse._decode",
                "entry_points": ["qs-like/lib/parse.parse", "qs-like.parse", "qs-like.Parser.run"],
                "method": "fix-diff",
                "evidence": {"fix": "https://github.com/x/qs-like/commit/abc"},
            }
        ],
        tmp_path / "symbols" / "npm.jsonl",
    )
    return proj


def _scan(proj: Path, tmp_path: Path, capsys, monkeypatch) -> dict:
    monkeypatch.setenv("SCGRAPH_SYMBOLS", str(tmp_path / "symbols"))
    code = main(
        [
            "scan",
            str(proj),
            "--offline",
            str(tmp_path / "osv"),
            "--no-signals",
            "--no-registry",
            "-f",
            "json",
            "--reachability",
        ]
    )
    assert code == 1
    return json.loads(capsys.readouterr().out)["results"][0]["alerts"][0]


def test_scan_marks_npm_alerts_from_the_inferred_dataset(tmp_path, capsys, monkeypatch) -> None:
    proj = _project(tmp_path, "const q = require('qs-like');\nq.parse(process.argv[2]);\n")
    a = _scan(proj, tmp_path, capsys, monkeypatch)
    assert a["reachability"] == "reachable" and a["symbols_source"] == "inferred"
    proj2 = tmp_path / "p2"
    proj2.mkdir()
    for f in ("package.json", "package-lock.json"):
        (proj2 / f).write_text((proj / f).read_text())
    (proj2 / "app.js").write_text("const q = require('qs-like');\nq.stringify({});\n")
    assert _scan(proj2, tmp_path, capsys, monkeypatch)["reachability"] == "not_called"


def test_scan_js_skips_vendored_directories(tmp_path: Path) -> None:
    (tmp_path / "a.js").write_text("const _ = require('lodash'); _.chunk();")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text("const e = require('evil'); e.run();")
    names = scan_js(tmp_path)
    assert "lodash.chunk" in names and not any("evil" in n for n in names)


def test_umd_factories_expose_the_functions_they_assign() -> None:
    body = "\n".join(f"  var pad{i} = 1;" for i in range(45))
    src = (
        ";(function() {\n  var runInContext = (function runInContext(context) {\n"
        f"{body}\n"
        "    function template(s) { return Function(s); }\n"
        "    function _internal(x) { return x; }\n"
        "    var lodash = {};\n    lodash.template = template;\n    return lodash;\n"
        "  });\n  var _ = runInContext();\n  (freeModule.exports = _)._ = _;\n}.call(this));\n"
    )
    f = parse_js(src)
    by = {x.qualname: x for x in f.functions}
    assert by["template"].public and not by["_internal"].public
    assert f.exports.get("template") == "template"
    for shape in (
        "(() => { function a(){} exports.a = a; })();",
        "!function(){ function b(){} exports.b = b; }();",
    ):
        assert parse_js(shape).exports  # arrow and `!function` wrappers are recognised too


def test_typescript_sources_and_member_visibility() -> None:
    from scgraph.symbols.js import ts_available

    if not ts_available():
        pytest.skip("tree-sitter-typescript not installed")
    f = parse_js(
        "export abstract class Base<T> {\n  private x = 1;\n  protected foo(a: string): void {}\n"
        "  public static bar<U>(q: U): U { return q as U }\n  get v(): number { return 1 }\n}\n"
        "export function top<T>(x: T): T { return helper(x!) }\nfunction helper<T>(x: T) { return x }\n",
        ts=True,
    )
    pub = {x.qualname: x.public for x in f.functions}
    assert pub == {
        "Base.foo": False,
        "Base.bar": True,
        "Base.v": True,
        "top": True,
        "helper": False,
    }
    assert is_test_path("src/index.spec.ts") and is_test_path("types/a.d.ts")
    assert referenced_names_js("import {x as y} from 'dep'; (y as any)();", ts=True) >= {"dep.x"}
