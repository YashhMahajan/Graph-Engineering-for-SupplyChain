"""The import-level hint: what it can say about a dependency, and what it refuses to."""

from __future__ import annotations

from pathlib import Path

import pytest

from scgraph.scan.imports import Imports, _package_of, classify, scan_sources


def write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


@pytest.mark.parametrize(
    ("spec", "want"),
    [
        ("lodash", "lodash"),
        ("lodash/fp", "lodash"),
        ("@scope/pkg", "@scope/pkg"),
        ("@scope/pkg/sub/deep", "@scope/pkg"),
        ("./local", None),
        ("../up", None),
        ("/abs/path", None),
        ("node:fs", None),
        ("#internal", None),
        ("https://cdn.example/x.js", None),
    ],
)
def test_package_of_maps_specifiers_to_package_names(spec: str, want: str | None) -> None:
    assert _package_of(spec) == want


def test_every_import_form_is_found_in_js_and_ts(tmp_path: Path) -> None:
    write(
        tmp_path,
        "src/a.ts",
        "import x from 'express';\nimport { y } from \"@scope/widget/button\";\n"
        "import 'side-effect';\nconst z = require('lodash/fp');\n"
        "const w = await import('dynamic-pkg');\nexport * from 'reexported';\n"
        "import local from './local';\nimport fs from 'node:fs';\n",
    )
    imp = scan_sources(tmp_path)
    assert imp.npm == {
        "express", "@scope/widget", "side-effect", "lodash", "dynamic-pkg", "reexported",
    }  # fmt: skip
    assert imp.js_files == 1


def test_vendored_build_and_hidden_directories_are_skipped(tmp_path: Path) -> None:
    write(tmp_path, "src/app.js", "require('real')")
    write(tmp_path, "node_modules/dep/index.js", "require('from-node-modules')")
    write(tmp_path, "dist/bundle.js", "require('from-dist')")
    write(tmp_path, ".hidden/x.js", "require('from-hidden')")
    assert scan_sources(tmp_path).npm == {"real"}


def test_python_imports_are_normalised_and_counted(tmp_path: Path) -> None:
    write(tmp_path, "app.py", "import yaml\nfrom Flask_Cors import CORS\n  import os.path\n")
    imp = scan_sources(tmp_path)
    assert imp.pypi == {"yaml", "flask-cors", "os"} and imp.py_files == 1


def test_npm_imported_via_the_direct_dependency_that_pulls_it_in() -> None:
    imp = Imports(npm={"express"}, js_files=3)
    assert classify("npm", ["app", "express@4.21.2", "qs@6.11.0"], imp) == "imported"  # transitive
    assert classify("npm", ["app", "express@4.21.2"], imp) == "imported"  # direct
    assert classify(
        "npm", ["app", "@scope/pkg@1.0.0"], Imports(npm={"@scope/pkg"}, js_files=1)
    ) == ("imported")


def test_npm_not_imported_is_a_hint_only_when_js_source_exists() -> None:
    assert classify("npm", ["app", "left-pad@1.3.0"], Imports(npm={"express"}, js_files=3)) == (
        "not_imported"
    )
    assert classify("npm", ["app", "left-pad@1.3.0"], Imports(js_files=0)) == "unknown"


def test_pypi_can_confirm_an_import_but_never_denies_one() -> None:
    imp = Imports(pypi={"requests"}, py_files=4)
    assert classify("PyPI", ["app", "requests@2.31.0"], imp) == "imported"
    # pyyaml is imported as "yaml": not seeing the name proves nothing
    assert classify("PyPI", ["app", "pyyaml@6.0"], imp) == "unknown"
    assert classify("PyPI", ["app", "Requests@2.31.0"], imp) == "imported"  # PEP 503 match


def test_other_ecosystems_and_missing_paths_are_unknown() -> None:
    imp = Imports(npm={"a"}, js_files=1)
    assert classify("crates.io", ["app", "serde@1.0.0"], imp) == "unknown"
    assert classify("npm", None, imp) == "unknown"
    assert classify("npm", ["app"], imp) == "unknown"


def test_oversized_files_are_skipped_without_error(tmp_path: Path, monkeypatch) -> None:
    import scgraph.scan.imports as m

    write(tmp_path, "big.js", "require('big-dep')")
    monkeypatch.setattr(m, "_MAX_BYTES", 5)
    assert m.scan_sources(tmp_path).npm == set()
