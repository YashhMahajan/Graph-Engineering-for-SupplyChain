"""The extra input formats: pnpm, bun, Gradle and SBOMs."""

from __future__ import annotations

from pathlib import Path

import pytest

from scgraph.scan.formats import _yaml_map
from scgraph.scan.lockfiles import find_lockfiles, is_lockfile, parse

PNPM_V9 = """\
lockfileVersion: '9.0'

settings:
  autoInstallPeers: true

importers:
  .:
    dependencies:
      express:
        specifier: ^4.18.0
        version: 4.18.2
      '@scope/widget':
        specifier: ^1.0.0
        version: 1.0.0(react@18.2.0)
      shared:
        specifier: workspace:*
        version: link:../shared
    devDependencies:
      jest: {specifier: ^29.0.0, version: 29.7.0}
      oldname:
        specifier: npm:left-pad@^1.3.0
        version: left-pad@1.3.0

packages:
  express@4.18.2:
    resolution: {integrity: sha512-aaa==}
  accepts@1.3.8:
    resolution: {integrity: sha512-bbb==}
  jest@29.7.0:
    resolution: {integrity: sha512-ccc==}
  '@scope/widget@1.0.0':
    resolution: {integrity: sha512-ddd==}
  react@18.2.0:
    resolution: {integrity: sha512-eee==}
  left-pad@1.3.0:
    resolution: {integrity: sha512-fff==}
  fsevents@2.3.3:
    resolution: {integrity: sha512-ggg==}

snapshots:
  express@4.18.2:
    dependencies:
      accepts: 1.3.8
  accepts@1.3.8: {}
  jest@29.7.0:
    optionalDependencies:
      fsevents: 2.3.3
  '@scope/widget@1.0.0(react@18.2.0)':
    dependencies:
      react: 18.2.0
  react@18.2.0: {}
  left-pad@1.3.0: {}
  fsevents@2.3.3: {}
"""


def names(g):
    return {p.label for p in g.pkgs}


def edge_labels(g):
    return {(g.pkgs[a].label, g.pkgs[b].label) for a, b in g.edges}


def direct(g):
    return {g.pkgs[i].label: s for i, s in g.direct.items()}


def test_yaml_map_handles_quoted_keys_flow_maps_and_nesting() -> None:
    doc = _yaml_map(
        "a:\n  'b@1(c@2)':\n    resolution: {integrity: sha512-x==, tarball: 'https://h/p'}\n"
        "  d: plain\n# comment\n  - ignored\n"
    )
    assert doc["a"]["b@1(c@2)"]["resolution"] == {
        "integrity": "sha512-x==",
        "tarball": "https://h/p",
    }
    assert doc["a"]["d"] == "plain"


def test_pnpm_v9_graph_scopes_peers_aliases_and_links(tmp_path: Path) -> None:
    f = tmp_path / "pnpm-lock.yaml"
    f.write_text(PNPM_V9, encoding="utf-8")
    g = parse(f)
    assert g.format == "pnpm-lock.yaml" and g.ecosystem == "npm"
    assert names(g) == {
        "express@4.18.2",
        "accepts@1.3.8",
        "jest@29.7.0",
        "@scope/widget@1.0.0",  # the (react@18.2.0) peer suffix is not part of the version
        "react@18.2.0",
        "left-pad@1.3.0",
        "fsevents@2.3.3",
    }
    assert edge_labels(g) == {
        ("express@4.18.2", "accepts@1.3.8"),
        ("jest@29.7.0", "fsevents@2.3.3"),  # optionalDependencies count
        ("@scope/widget@1.0.0", "react@18.2.0"),  # resolved through the peer-suffixed key
    }
    assert direct(g) == {
        "express@4.18.2": "prod",
        "@scope/widget@1.0.0": "prod",
        "jest@29.7.0": "dev",
        "left-pad@1.3.0": "dev",  # npm: alias resolved to the real package
    }  # `link:../shared` is a workspace link, not a registry package
    dev = {p.label for p in g.pkgs if p.dev}
    assert "jest@29.7.0" in dev and "fsevents@2.3.3" in dev and "express@4.18.2" not in dev


def test_pnpm_v6_keeps_dependencies_inside_packages(tmp_path: Path) -> None:
    f = tmp_path / "pnpm-lock.yaml"
    f.write_text(
        "lockfileVersion: '6.0'\n"
        "dependencies:\n  web:\n    specifier: ^1\n    version: 1.0.0\n"
        "packages:\n"
        "  /web@1.0.0:\n    dependencies:\n      parser: 1.2.0\n    dev: false\n"
        "  /parser@1.2.0:\n    dev: false\n",
        encoding="utf-8",
    )
    g = parse(f)
    assert edge_labels(g) == {("web@1.0.0", "parser@1.2.0")}
    assert direct(g) == {"web@1.0.0": "prod"}


def test_pnpm_before_v6_is_refused_with_advice(tmp_path: Path) -> None:
    f = tmp_path / "pnpm-lock.yaml"
    f.write_text("lockfileVersion: 5.4\npackages:\n  /a/1.0.0:\n    dev: false\n", encoding="utf-8")
    with pytest.raises(ValueError, match="pnpm install"):
        parse(f)


def test_pnpm_lockfile_is_discovered_by_name(tmp_path: Path) -> None:
    (tmp_path / "pnpm-lock.yaml").write_text(PNPM_V9, encoding="utf-8")
    assert is_lockfile(tmp_path / "pnpm-lock.yaml")
    assert [p.name for p in find_lockfiles(tmp_path)] == ["pnpm-lock.yaml"]


@pytest.mark.parametrize("written", ["left-pad@1.3.0", "/left-pad@1.3.0", "npm:left-pad@1.3.0"])
def test_pnpm_aliased_dependency_forms_all_resolve_to_the_real_package(
    tmp_path: Path, written: str
) -> None:
    f = tmp_path / "pnpm-lock.yaml"
    f.write_text(
        "lockfileVersion: '9.0'\n"
        "importers:\n  .:\n    dependencies:\n      web:\n"
        "        specifier: ^1\n        version: 1.0.0\n"
        "snapshots:\n"
        f"  web@1.0.0:\n    dependencies:\n      renamed: {written}\n"
        "  left-pad@1.3.0: {}\n",
        encoding="utf-8",
    )
    assert edge_labels(parse(f)) == {("web@1.0.0", "left-pad@1.3.0")}
