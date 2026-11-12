"""Function-level reachability: resolve what source references, never suppress an alert."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from scgraph.cli import main
from scgraph.scan.reachability import classify, referenced_names, scan_python, symbols_of


def names(src: str) -> set[str]:
    return referenced_names(src)


def test_import_aliases_resolve_to_the_dotted_name_an_advisory_uses() -> None:
    assert "yaml.load" in names("import yaml\nyaml.load(x)")
    assert "yaml.load" in names("import yaml as y\ny.load(x)")
    assert "yaml.load" in names("from yaml import load\nload(x)")
    assert "yaml.load" in names("from yaml import load as ld\nld(x)")
    assert "a.b.f" in names("import a.b\na.b.f()")
    assert "django.utils.html.urlize" in names("from django.utils import html\nhtml.urlize(t)")


def test_a_function_that_is_only_passed_around_still_counts() -> None:
    assert "yaml.load" in names("import yaml\nlist(map(yaml.load, docs))")


def test_names_that_are_not_imported_or_are_relative_do_not_resolve() -> None:
    assert names("def load(x): pass\nload(1)") == set()  # a local function, not the package's
    assert names("from . import yaml\nyaml.load(x)") == set()  # relative: not the package
    assert names("yaml.load(x)") == set()  # never imported, so not the package


def test_unparseable_source_is_ignored_not_fatal() -> None:
    assert names("def broken(:\n") == set()


def test_symbols_come_from_affected_functions_and_the_go_layout() -> None:
    py = {"ecosystem_specific": {"affected_functions": ["yaml.load", "yaml.load_all"]}}
    go = {"ecosystem_specific": {"imports": [{"path": "net/http", "symbols": ["Serve"]}]}}
    assert symbols_of([py]) == ["yaml.load", "yaml.load_all"]
    assert symbols_of([go]) == ["net/http.Serve"]
    assert symbols_of([{}, {"ecosystem_specific": {"affected_functions": [1, "", None]}}]) == []


def test_classify_gives_one_verdict_per_situation() -> None:
    syms = ["yaml.load"]
    direct = ["app", "pyyaml@5.3"]
    assert classify("PyPI", direct, syms, {"yaml.load"}) == "reachable"
    assert classify("PyPI", direct, syms, {"yaml.safe_load"}) == "not_called"
    assert classify("PyPI", direct, [], {"yaml.load"}) == "not_analyzed"  # advisory lists none
    assert classify("PyPI", ["app", "web@1", "pyyaml@5.3"], syms, {"yaml.load"}) == "not_analyzed"
    assert classify("npm", direct, syms, {"yaml.load"}) == "reachable"  # npm is analysed too
    assert classify("crates.io", direct, syms, {"yaml.load"}) == "not_analyzed"
    assert classify("PyPI", None, syms, {"yaml.load"}) == "not_analyzed"


def test_scan_python_skips_vendored_directories_and_bad_files(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("import yaml\nyaml.load(x)\n")
    (tmp_path / "broken.py").write_text("def x(:\n")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "lib.py").write_text("import evil\nevil.run()\n")
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "v.py").write_text("import vend\nvend.run()\n")
    found = scan_python(tmp_path)
    assert "yaml.load" in found  # the real source is read, and the broken file is survived
    assert not {n for n in found if n.startswith(("evil", "vend"))}  # skipped directories


def _setup(tmp_path: Path, source: str, functions: list[str] | None = ("yaml.load",)) -> list[str]:
    eco = {"affected_functions": list(functions)} if functions else {}
    rec = {
        "id": "GHSA-yaml",
        "summary": "unsafe load",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "pyyaml"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.4"}]}
                ],
                "ecosystem_specific": eco,
            }
        ],
    }
    osv = tmp_path / "osv"
    osv.mkdir(exist_ok=True)
    with zipfile.ZipFile(osv / "pypi.zip", "w") as z:
        z.writestr("GHSA-yaml.json", json.dumps(rec))
    proj = tmp_path / "proj"
    proj.mkdir(exist_ok=True)
    (proj / "requirements.txt").write_text("pyyaml==5.3\n")
    (proj / "app.py").write_text(source)
    base = ["scan", str(proj), "--offline", str(osv), "--no-signals", "--no-registry"]
    return [*base, "-f", "json"]


def verdict(args: list[str], capsys, *extra: str) -> tuple[int, dict]:
    code = main([*args, *extra])
    return code, json.loads(capsys.readouterr().out)["results"][0]["alerts"][0]


def test_cli_reachable_when_the_vulnerable_function_is_called(tmp_path: Path, capsys) -> None:
    args = _setup(tmp_path, "import yaml as y\ny.load(open('c.yml'))\n")
    code, alert = verdict(args, capsys, "--reachability")
    assert code == 1 and alert["reachability"] == "reachable"
    assert alert["symbols"] == ["yaml.load"]


def test_cli_not_called_is_a_hint_and_never_a_pass(tmp_path: Path, capsys) -> None:
    args = _setup(tmp_path, "import yaml\nyaml.safe_load(open('c.yml'))\n")
    code, alert = verdict(args, capsys, "--reachability")
    assert code == 1  # the alert and the exit code are unchanged
    assert alert["reachability"] == "not_called"


def test_cli_no_function_list_means_not_analyzed_and_no_flag_means_nothing(
    tmp_path: Path, capsys
) -> None:
    bare = _setup(tmp_path, "import yaml\nyaml.load(x)\n", functions=None)
    assert verdict(bare, capsys, "--reachability")[1]["reachability"] == "not_analyzed"
    named = _setup(tmp_path, "import yaml\nyaml.load(x)\n")
    assert verdict(named, capsys)[1]["reachability"] == ""  # off by default


def test_the_text_output_names_the_verdict(tmp_path: Path, capsys) -> None:
    args = _setup(tmp_path, "import yaml\nyaml.load(x)\n")
    main([*args[:-2], "--reachability"])
    assert "vulnerable function called" in capsys.readouterr().out


def test_a_method_symbol_with_its_class_referenced_is_class_used_not_not_called() -> None:
    direct = ["app", "requests@2.30.0"]
    syms = ["requests.sessions.Session.request", "requests.Session.request"]
    assert classify("PyPI", direct, syms, {"requests.Session"}) == "class_used"
    assert classify("PyPI", direct, syms, {"requests.get"}) == "not_called"
    assert (
        classify("PyPI", direct, ["yaml.load"], {"yaml"}) == "not_called"
    )  # a module is not a class


def _inferred(tmp_path: Path, monkeypatch, symbol: str, entry_points: list[str]) -> None:
    from scgraph.symbols.dataset import write

    rec = {
        "id": "PYSEC-yaml",
        "aliases": ["GHSA-yaml"],
        "ecosystem": "PyPI",
        "package": "pyyaml",
        "symbol": symbol,
        "entry_points": entry_points,
        "method": "fix-diff",
        "evidence": {"fix": "https://github.com/yaml/pyyaml/commit/abc"},
    }
    path = tmp_path / "symbols" / "pypi.jsonl"
    write([rec], path)
    monkeypatch.setenv("SCGRAPH_SYMBOLS", str(path))


def test_cli_uses_inferred_symbols_when_the_advisory_names_none(
    tmp_path: Path, capsys, monkeypatch
) -> None:
    _inferred(tmp_path, monkeypatch, "yaml.constructor.construct_python_object", ["yaml.load"])
    args = _setup(tmp_path, "import yaml\nyaml.load(x)\n", functions=None)
    code, alert = verdict(args, capsys, "--reachability")
    assert code == 1 and alert["reachability"] == "reachable"
    assert alert["symbols_source"] == "inferred"
    assert alert["symbol_evidence"] == "https://github.com/yaml/pyyaml/commit/abc"
    main([*args[:-2], "--reachability"])
    assert "vulnerable function called (inferred)" in capsys.readouterr().out


def test_published_functions_win_over_inferred_ones(tmp_path: Path, capsys, monkeypatch) -> None:
    _inferred(tmp_path, monkeypatch, "yaml.other", [])
    args = _setup(tmp_path, "import yaml\nyaml.load(x)\n")  # the advisory names yaml.load
    _, alert = verdict(args, capsys, "--reachability")
    assert alert["symbols"] == ["yaml.load"] and alert["symbols_source"] == "osv"


def test_a_tampered_dataset_is_ignored_with_a_warning(tmp_path: Path, capsys, monkeypatch) -> None:
    _inferred(tmp_path, monkeypatch, "yaml.load", [])
    p = tmp_path / "symbols" / "pypi.jsonl"
    p.write_text(p.read_text().replace("yaml.load", "yaml.LOAD"))
    args = _setup(tmp_path, "import yaml\nyaml.load(x)\n", functions=None)
    code = main([*args, "--reachability"])
    out = capsys.readouterr()
    assert code == 1 and "does not match" in out.err
    assert json.loads(out.out)["results"][0]["alerts"][0]["reachability"] == "not_analyzed"
