"""Lockfile parsers: real file shapes, the edges they publish, and the dev/prod split."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scgraph.scan.lockfiles import find_lockfiles, parse


def _labels(g, idxs):
    return sorted(g.pkgs[i].label for i in idxs)


def _edge_labels(g):
    return sorted((g.pkgs[a].label, g.pkgs[b].label) for a, b in g.edges)


def _write(tmp: Path, name: str, text: str) -> Path:
    p = tmp / name
    p.write_text(text, encoding="utf-8")
    return p


def test_package_lock_v3_nested_resolution_and_dev(tmp_path: Path) -> None:
    lock = {
        "name": "app",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "app",
                "dependencies": {"express": "4"},
                "devDependencies": {"mocha": "5"},
            },
            "node_modules/express": {
                "version": "4.21.2",
                "dependencies": {"debug": "2.6.9", "body-parser": "1"},
            },
            "node_modules/body-parser": {"version": "1.20.3", "dependencies": {"debug": "4"}},
            "node_modules/body-parser/node_modules/debug": {"version": "4.4.2"},
            "node_modules/debug": {"version": "2.6.9"},
            "node_modules/mocha": {
                "version": "5.2.0",
                "dev": True,
                "dependencies": {"minimist": "0"},
            },
            "node_modules/minimist": {"version": "0.0.8", "dev": True},
        },
    }
    g = parse(_write(tmp_path, "package-lock.json", json.dumps(lock)))
    assert g.ecosystem == "npm"
    assert ("body-parser@1.20.3", "debug@4.4.2") in _edge_labels(g)  # nested copy wins
    assert ("express@4.21.2", "debug@2.6.9") in _edge_labels(g)  # hoisted copy
    assert _labels(g, [i for i, s in g.direct.items() if s == "prod"]) == ["express@4.21.2"]
    dev = {p.label for p in g.pkgs if p.dev}
    assert dev == {"mocha@5.2.0", "minimist@0.0.8"}


def test_package_lock_v1_tree_with_package_json(tmp_path: Path) -> None:
    lock = {
        "lockfileVersion": 1,
        "dependencies": {
            "a": {"version": "1.0.0", "requires": {"b": "^1"}},
            "b": {"version": "1.2.0"},
            "c": {
                "version": "2.0.0",
                "dev": True,
                "requires": {"b": "^2"},
                "dependencies": {"b": {"version": "2.0.0"}},
            },
        },
    }
    _write(
        tmp_path,
        "package.json",
        json.dumps({"dependencies": {"a": "1"}, "devDependencies": {"c": "2"}}),
    )
    g = parse(_write(tmp_path, "package-lock.json", json.dumps(lock)))
    assert ("a@1.0.0", "b@1.2.0") in _edge_labels(g)
    assert ("c@2.0.0", "b@2.0.0") in _edge_labels(g)  # c's nested b, not the hoisted one
    assert {p.label for p in g.pkgs if p.dev} == {"c@2.0.0", "b@2.0.0"}


YARN_V1 = """# yarn lockfile v1

"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":
  version "7.12.13"
  resolved "https://registry.yarnpkg.com/x"
  dependencies:
    "@babel/highlight" "^7.12.13"

"@babel/highlight@^7.12.13":
  version "7.13.10"

left-pad@^1.3.0:
  version "1.3.0"
"""

YARN_BERRY = """__metadata:
  version: 6

"app@workspace:.":
  version: 0.0.0-use.local
  resolution: "app@workspace:."
  dependencies:
    lodash: ^4.17.0
  languageName: unknown
  linkType: soft

"lodash@npm:^4.17.0":
  version: 4.17.15
  resolution: "lodash@npm:4.17.15"
  languageName: node
  linkType: hard
"""


def test_yarn_classic(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "package.json",
        json.dumps(
            {
                "dependencies": {"@babel/code-frame": "^7.0.0"},
                "devDependencies": {"left-pad": "^1.3.0"},
            }
        ),
    )
    g = parse(_write(tmp_path, "yarn.lock", YARN_V1))
    assert _edge_labels(g) == [("@babel/code-frame@7.12.13", "@babel/highlight@7.13.10")]
    assert {p.label for p in g.pkgs if p.dev} == {"left-pad@1.3.0"}


def test_yarn_berry_workspace_root(tmp_path: Path) -> None:
    g = parse(_write(tmp_path, "yarn.lock", YARN_BERRY))
    assert ("app@0.0.0-use.local", "lodash@4.17.15") in _edge_labels(g)
    assert not any(p.dev for p in g.pkgs)


def test_requirements_follows_includes_and_reports_unpinned(tmp_path: Path) -> None:
    _write(tmp_path, "base.txt", "Django==3.2.0\n")
    p = _write(
        tmp_path,
        "requirements.txt",
        "-r base.txt\nrequests[socks]==2.25.0 ; python_version > '3'  # pinned\n"
        "urllib3 \\\n  ==1.26.4\nflask>=2\n--hash sha256:abc\n-e .\n",
    )
    g = parse(p)
    assert sorted(x.label for x in g.pkgs) == ["django@3.2.0", "requests@2.25.0", "urllib3@1.26.4"]
    assert g.unpinned == ["flask>=2"]


def test_poetry_lock_with_pyproject(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "pyproject.toml",
        '[tool.poetry.dependencies]\npython = "^3.11"\nrequests = "*"\n'
        '[tool.poetry.group.dev.dependencies]\npytest = "*"\n',
    )
    lock = """
[[package]]
name = "requests"
version = "2.25.0"
[package.dependencies]
urllib3 = ">=1.21"
[[package]]
name = "urllib3"
version = "1.26.4"
[[package]]
name = "pytest"
version = "6.2.0"
[package.dependencies]
iniconfig = "*"
[[package]]
name = "iniconfig"
version = "1.1.1"
"""
    g = parse(_write(tmp_path, "poetry.lock", lock))
    assert ("requests@2.25.0", "urllib3@1.26.4") in _edge_labels(g)
    assert {p.label for p in g.pkgs if p.dev} == {"pytest@6.2.0", "iniconfig@1.1.1"}


UV_LOCK = """
version = 1
[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "requests" }]
[package.dev-dependencies]
dev = [{ name = "pytest" }]

[[package]]
name = "requests"
version = "2.25.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "idna" }]

[[package]]
name = "idna"
version = "2.10"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "6.2.0"
source = { registry = "https://pypi.org/simple" }
"""


def test_uv_lock_dev_group_is_not_a_prod_edge(tmp_path: Path) -> None:
    g = parse(_write(tmp_path, "uv.lock", UV_LOCK))
    assert ("demo@0.1.0", "pytest@6.2.0") not in _edge_labels(g)
    assert ("requests@2.25.0", "idna@2.10") in _edge_labels(g)
    assert {p.label for p in g.pkgs if p.dev} == {"pytest@6.2.0"}
    assert [p.label for p in g.pkgs if p.local] == ["demo@0.1.0"]


def test_cargo_lock_disambiguates_versions(tmp_path: Path) -> None:
    lock = """
version = 3
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["rand 0.8.5", "serde"]
[[package]]
name = "rand"
version = "0.8.5"
source = "registry+https://github.com/rust-lang/crates.io-index"
[[package]]
name = "rand"
version = "0.7.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""
    g = parse(_write(tmp_path, "Cargo.lock", lock))
    assert _edge_labels(g) == [("app@0.1.0", "rand@0.8.5"), ("app@0.1.0", "serde@1.0.0")]
    assert g.ecosystem == "crates.io"


def test_go_mod_gemfile_composer_pipfile(tmp_path: Path) -> None:
    gm = parse(
        _write(
            tmp_path,
            "go.mod",
            "module x\n\nrequire (\n\tgithub.com/a/b v1.2.3\n"
            "\tgolang.org/x/net v0.1.0 // indirect\n)\n"
            "require github.com/c/d v0.0.1\n",
        )
    )
    assert sorted(p.label for p in gm.pkgs) == [
        "github.com/a/b@1.2.3",
        "github.com/c/d@0.0.1",
        "golang.org/x/net@0.1.0",
    ]

    gem = parse(
        _write(
            tmp_path,
            "Gemfile.lock",
            "GEM\n  remote: https://rubygems.org/\n  specs:\n"
            "    rails (6.0.0)\n      actionpack (= 6.0.0)\n"
            "    actionpack (6.0.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails (~> 6.0)\n",
        )
    )
    assert _edge_labels(gem) == [("rails@6.0.0", "actionpack@6.0.0")]
    assert _labels(gem, gem.direct) == ["rails@6.0.0"]

    comp = parse(
        _write(
            tmp_path,
            "composer.lock",
            json.dumps(
                {
                    "packages": [
                        {
                            "name": "Monolog/Monolog",
                            "version": "v2.0.0",
                            "require": {"psr/log": "^1", "php": ">=7"},
                        },
                        {"name": "psr/log", "version": "1.1.0"},
                    ],
                    "packages-dev": [{"name": "phpunit/phpunit", "version": "9.0.0"}],
                }
            ),
        )
    )
    assert ("monolog/monolog@2.0.0", "psr/log@1.1.0") in _edge_labels(comp)
    assert {p.label for p in comp.pkgs if p.dev} == {"phpunit/phpunit@9.0.0"}

    pf = parse(
        _write(
            tmp_path,
            "Pipfile.lock",
            json.dumps(
                {
                    "default": {"Django": {"version": "==3.2"}},
                    "develop": {"black": {"version": "==22.1.0"}},
                }
            ),
        )
    )
    assert {p.label: p.dev for p in pf.pkgs} == {"django@3.2": False, "black@22.1.0": True}


def test_find_lockfiles_skips_vendored(tmp_path: Path) -> None:
    (tmp_path / "svc").mkdir()
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    _write(tmp_path / "svc", "package-lock.json", "{}")
    _write(tmp_path / "node_modules" / "x", "package-lock.json", "{}")
    _write(tmp_path, "requirements-dev.txt", "")
    _write(tmp_path, "README.md", "")
    found = [p.relative_to(tmp_path).as_posix() for p in find_lockfiles(tmp_path)]
    assert found == ["requirements-dev.txt", "svc/package-lock.json"]


def test_unknown_file_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not a supported lockfile"):
        parse(_write(tmp_path, "notes.txt", "x"))


def test_content_override_parses_without_disk(tmp_path: Path) -> None:
    g = parse("requirements.txt", content="jinja2==2.10\n")
    assert [p.label for p in g.pkgs] == ["jinja2@2.10"]


def test_prefixed_names_are_lockfiles(tmp_path: Path) -> None:
    from scgraph.scan.lockfiles import lockfile_kind, lockfile_project

    assert lockfile_kind("api.uv.lock") == "uv.lock"
    assert lockfile_kind("web.package-lock.json") == "package-lock.json"
    assert lockfile_kind("requirements-dev.txt") == "requirements.txt"
    assert lockfile_kind("lock.json") is None
    p = _write(tmp_path, "api.requirements.txt", "flask==2.0.0\n")
    assert [x.label for x in parse(p).pkgs] == ["flask@2.0.0"]
    assert lockfile_project(p) == "api"
    assert find_lockfiles(tmp_path) == [p]
