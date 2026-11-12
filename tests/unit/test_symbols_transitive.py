"""Transitive reachability: backward propagation through released source, and `scan --deep`."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from scgraph.cli import main
from scgraph.symbols.dataset import write
from scgraph.symbols.deep import DeepAnalyzer
from scgraph.symbols.entry import entry_points
from scgraph.symbols.source import Release
from scgraph.symbols.transitive import propagate

CHILD = Release(
    "PyPI",
    "child",
    "1.0",
    {
        "child/__init__.py": "from .core import decode\n",
        "child/core.py": (
            "def decode(data):\n    return _risky_parse(data)\n\n"
            "def _risky_parse(data):\n    return eval(data)\n\n"
            "def unrelated(data):\n    return data\n"
        ),
    },
)
PARENT = Release(
    "PyPI",
    "parent",
    "2.0",
    {
        "parent/__init__.py": "from .api import fetch\n",
        "parent/api.py": (
            "from child.core import decode\n\n"
            "def fetch(url):\n    return _load(url)\n\n"
            "def _load(url):\n    return decode(url)\n\n"
            "def unrelated(url):\n    return url\n"
        ),
    },
)
TOP = Release(
    "PyPI",
    "top",
    "3.0",
    {
        "top/__init__.py": "",
        "top/app.py": "import parent\n\ndef run(x):\n    return parent.fetch(x)\n\ndef other():\n    pass\n",
    },
)


def seeds(rel: Release) -> list[tuple[str, str]]:
    return entry_points(rel, "child.core", "_risky_parse")


def test_two_packages_reach_the_public_api_with_its_alias() -> None:
    p = propagate([PARENT, CHILD], seeds(CHILD))
    assert p.reached and p.broke_at == ""
    assert p.names == ["parent.api.fetch", "parent.fetch"]  # `unrelated` is not reached
    assert [(h.package, h.callers) for h in p.hops] == [("parent", 1)]


def test_three_packages_chain_hop_by_hop() -> None:
    p = propagate([TOP, PARENT, CHILD], seeds(CHILD))
    assert p.reached and p.names == ["top.app.run"]
    assert [h.package for h in p.hops] == ["top", "parent"]


def test_a_package_that_never_calls_in_breaks_the_chain() -> None:
    lonely = Release(
        "PyPI",
        "lonely",
        "1",
        {"lonely/__init__.py": "", "lonely/m.py": "def go(x):\n    return x\n"},
    )
    p = propagate([lonely, CHILD], seeds(CHILD))
    assert not p.reached and p.broke_at == "lonely" and p.names == []
    q = propagate([TOP, lonely, CHILD], seeds(CHILD))
    assert not q.reached and q.broke_at == "lonely"


def test_a_caller_must_import_the_package_below() -> None:
    shadow = Release(  # calls a function named `decode` but never imports child
        "PyPI",
        "shadow",
        "1",
        {"shadow/__init__.py": "", "shadow/m.py": "def go(x):\n    return x.decode()\n"},
    )
    assert not propagate([shadow, CHILD], seeds(CHILD)).reached


def test_very_common_names_do_not_connect_packages() -> None:
    child = Release(
        "PyPI", "c2", "1", {"c2/__init__.py": "", "c2/m.py": "def get(x):\n    return eval(x)\n"}
    )
    parent = Release(
        "PyPI",
        "p2",
        "1",
        {"p2/__init__.py": "", "p2/m.py": "import c2\n\ndef use(x):\n    return c2.get(x)\n"},
    )
    assert not propagate([parent, child], [("c2.m", "get")]).reached


# ----------------------------------------------------------------------------- scan --deep


def _lock(tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "pyproject.toml").write_text(
        '[tool.poetry.dependencies]\npython = "^3.11"\nparent = "*"\n'
    )
    (proj / "poetry.lock").write_text(
        '[[package]]\nname = "parent"\nversion = "2.0"\n[package.dependencies]\nchild = "*"\n'
        '[[package]]\nname = "child"\nversion = "1.0"\n'
    )
    osv = tmp_path / "osv"
    osv.mkdir()
    rec = {
        "id": "GHSA-child",
        "summary": "eval in decode",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "child"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1"}]}
                ],
            }
        ],
    }
    with zipfile.ZipFile(osv / "pypi.zip", "w") as z:
        z.writestr("GHSA-child.json", json.dumps(rec))
    return proj


@pytest.fixture
def deep_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    proj = _lock(tmp_path)
    write(
        [
            {
                "id": "GHSA-child",
                "aliases": [],
                "ecosystem": "PyPI",
                "package": "child",
                "symbol": "child.core._risky_parse",
                "module": "child.core",
                "qualname": "_risky_parse",
                "entry_points": ["child.core.decode"],
                "method": "fix-diff",
                "evidence": {"fix": "https://github.com/x/child/commit/abc"},
            }
        ],
        tmp_path / "symbols" / "pypi.jsonl",
    )
    monkeypatch.setenv("SCGRAPH_SYMBOLS", str(tmp_path / "symbols" / "pypi.jsonl"))
    rels = {("parent", "2.0"): PARENT, ("child", "1.0"): CHILD}
    monkeypatch.setattr(DeepAnalyzer, "release", lambda self, n, v, e="PyPI": rels.get((n, v)))
    return proj


def _scan(proj: Path, tmp_path: Path, capsys, *extra: str) -> dict:
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
            *extra,
        ]
    )
    assert code == 1  # the alert and the exit code never change
    return json.loads(capsys.readouterr().out)["results"][0]["alerts"][0]


def test_deep_scan_reaches_through_the_direct_dependency(deep_env, tmp_path, capsys) -> None:
    (deep_env / "app.py").write_text("import parent\nparent.fetch('x')\n")
    a = _scan(deep_env, tmp_path, capsys, "--deep")
    assert a["reachability"] == "reachable" and a["reach_hops"] == 2
    assert a["symbols_source"] == "inferred" and "parent.fetch" in a["symbols"]


def test_deep_scan_says_not_called_when_the_reaching_api_is_unused(
    deep_env, tmp_path, capsys
) -> None:
    (deep_env / "app.py").write_text("import parent\nparent.other_thing()\n")
    assert _scan(deep_env, tmp_path, capsys, "--deep")["reachability"] == "not_called"


def test_without_deep_a_transitive_alert_stays_not_analyzed(deep_env, tmp_path, capsys) -> None:
    (deep_env / "app.py").write_text("import parent\nparent.fetch('x')\n")
    assert _scan(deep_env, tmp_path, capsys, "--reachability")["reachability"] == "not_analyzed"


def test_deep_scan_degrades_to_not_analyzed_when_source_is_unavailable(
    deep_env, tmp_path, capsys, monkeypatch
) -> None:
    monkeypatch.setattr(DeepAnalyzer, "release", lambda self, n, v, e="PyPI": None)
    (deep_env / "app.py").write_text("import parent\nparent.fetch('x')\n")
    a = _scan(deep_env, tmp_path, capsys, "--deep")
    assert a["reachability"] == "not_analyzed" and "unavailable" in a["symbol_evidence"]


# ----------------------------------------------------------------------------- mechanisms


def _pkg(name: str, **mods: str) -> Release:
    files = {f"{name}/__init__.py": ""}
    files.update({f"{name}/{m}.py": src for m, src in mods.items()})
    return Release("PyPI", name, "1", files)


def _reach(parent: Release, child: Release, mod: str, qn: str) -> list[str]:
    seeds = entry_points(child, mod, qn)
    if (mod, qn) not in seeds:
        seeds.append((mod, qn))
    return propagate([parent, child], seeds).names


def test_a_dunder_runs_when_its_class_is_instantiated() -> None:
    child = _pkg("kid", buf="class Buf:\n    def __len__(self):\n        return eval('1')\n")
    parent = _pkg("par", api="from kid.buf import Buf\n\ndef make():\n    return Buf()\n")
    assert _reach(parent, child, "kid.buf", "Buf.__len__") == ["par.api.make"]


def test_a_property_runs_when_it_is_read() -> None:
    child = _pkg(
        "kid2",
        conn="class Conn:\n    @property\n    def hostname(self):\n        return eval('h')\n",
    )
    parent = _pkg(
        "par2",
        api="import kid2\n\ndef where(c):\n    return c.hostname\n\ndef other(c):\n    return c\n",
    )
    assert _reach(parent, child, "kid2.conn", "Conn.hostname") == ["par2.api.where"]


def test_getattr_dispatch_reaches_the_prefixed_methods() -> None:
    child = _pkg(
        "kid3",
        vis=(
            "class Visitor:\n    def visit(self, node):\n"
            "        return getattr(self, 'visit_' + node)()\n\n"
            "class Gen(Visitor):\n    def visit_Output(self):\n        return eval('x')\n"
        ),
    )
    parent = _pkg(
        "par3", api="from kid3.vis import Gen\n\ndef run(n):\n    return Gen().visit(n)\n"
    )
    assert "par3.api.run" in _reach(parent, child, "kid3.vis", "Gen.visit_Output")


def test_import_time_calls_become_a_package_wildcard() -> None:
    child = _pkg("kid4", sig="def make_signal(n):\n    return eval(n)\n")
    src = "from kid4.sig import make_signal\n\nREADY = make_signal('ready')\n"
    eager = Release(
        "PyPI", "par4", "1", {"par4/__init__.py": "from . import signals\n", "par4/signals.py": src}
    )
    assert _reach(eager, child, "kid4.sig", "make_signal") == ["par4.*"]
    lazy = Release("PyPI", "par5", "1", {"par5/__init__.py": "", "par5/signals.py": src})
    assert _reach(lazy, child, "kid4.sig", "make_signal") == ["par5.signals.*"]


def test_a_function_passed_as_a_value_counts_as_a_call() -> None:
    child = _pkg("kid6", m="def risky_hook(x):\n    return eval(x)\n")
    parent = _pkg(
        "par6",
        api=(
            "import functools\nfrom kid6.m import risky_hook\n\n"
            "def _wrapped(x):\n    return risky_hook(x)\n\n"
            "TABLE = {'a': functools.partial(_wrapped)}\n\n"
            "def use(k):\n    return TABLE[k]\n"
        ),
    )
    assert _reach(parent, child, "kid6.m", "risky_hook")  # reached via the module-level table


def test_a_resolved_reference_overrides_the_common_name_stoplist() -> None:
    child = _pkg("kid7", core="def send(x):\n    return eval(x)\n")
    parent = _pkg("par7", api="import kid7.core as core\n\ndef go(x):\n    return core.send(x)\n")
    assert _reach(parent, child, "kid7.core", "send") == ["par7.api.go"]
    other = _pkg("par8", api="import kid7\n\ndef go(sock, x):\n    return sock.send(x)\n")
    assert _reach(other, child, "kid7.core", "send") == []  # an unrelated .send() is not matched


def test_classify_treats_a_wildcard_as_reached_when_the_package_is_used() -> None:
    from scgraph.scan.reachability import classify

    path = ["app", "par4@1", "kid4@1"]
    assert classify("PyPI", path, ["par4.*"], {"par4.Thing"}, deep=True) == "reachable"
    assert classify("PyPI", path, ["par4.*"], {"other.Thing"}, deep=True) == "not_called"
