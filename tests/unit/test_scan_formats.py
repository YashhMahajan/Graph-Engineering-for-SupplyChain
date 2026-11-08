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


BUN = """\
{
  // written by bun
  "lockfileVersion": 1,
  "workspaces": {
    "": {
      "name": "app",
      "dependencies": {
        "express": "^4.18.2",
        "@scope/widget": "^1.0.0",
      },
      "devDependencies": {
        "typescript": "^5.0.0",
      },
    },
  },
  "packages": {
    "app": ["app@workspace:."],
    "express": ["express@4.18.2", "", {
      "dependencies": { "qs": "6.11.0", "accepts": "~1.3.8" } }, "sha512-a"],
    "accepts": ["accepts@1.3.8", "", {}, "sha512-b"],
    "qs": ["qs@6.14.0", "", {}, "sha512-c"],
    "express/qs": ["qs@6.11.0", "", {}, "sha512-d"],
    "@scope/widget": ["@scope/widget@1.0.0", "", { "dependencies": { "qs": "^6" } }, "sha512-e"],
    "typescript": ["typescript@5.4.0", "", {}, "sha512-f"],
    "tarball-dep": ["tarball-dep@https://example.com/x.tgz", ""],
  }
}
"""


def test_bun_lock_resolves_nested_overrides_before_the_hoisted_copy(tmp_path: Path) -> None:
    f = tmp_path / "bun.lock"
    f.write_text(BUN, encoding="utf-8")
    g = parse(f)
    assert g.format == "bun.lock" and g.ecosystem == "npm"
    assert edge_labels(g) == {
        ("express@4.18.2", "qs@6.11.0"),  # express/qs shadows the top-level qs
        ("express@4.18.2", "accepts@1.3.8"),
        ("@scope/widget@1.0.0", "qs@6.14.0"),  # no override here: the hoisted copy
    }
    assert direct(g) == {
        "express@4.18.2": "prod",
        "@scope/widget@1.0.0": "prod",
        "typescript@5.4.0": "dev",
    }


def test_bun_workspace_members_and_non_registry_packages_are_never_reported(tmp_path: Path) -> None:
    f = tmp_path / "bun.lock"
    f.write_text(BUN, encoding="utf-8")
    g = parse(f)
    local = {p.label for p in g.pkgs if p.local}
    assert local == {"app@workspace:.", "tarball-dep@https://example.com/x.tgz"}


def test_jsonc_keeps_comment_markers_inside_strings_and_drops_trailing_commas() -> None:
    from scgraph.scan.formats import loads_jsonc

    doc = loads_jsonc(
        '{ "url": "https://example.com/a//b", /* block */ "n": [1, 2,], // line\n "s": "a,}",}'
    )
    assert doc == {"url": "https://example.com/a//b", "n": [1, 2], "s": "a,}"}
    assert loads_jsonc('{"q": "say \\"hi\\" // not a comment",}') == {
        "q": 'say "hi" // not a comment'
    }


def test_bun_scoped_parent_chain_resolves_overrides_inside_scopes(tmp_path: Path) -> None:
    f = tmp_path / "bun.lock"
    f.write_text(
        '{"lockfileVersion":1,"workspaces":{"":{"dependencies":{"@s/p":"1"}}},"packages":{'
        '"@s/p":["@s/p@1.0.0","",{"dependencies":{"x":"1"}}],'
        '"x":["x@1.0.0","",{}],'
        '"@s/p/x":["x@2.0.0","",{}]}}',
        encoding="utf-8",
    )
    assert edge_labels(parse(f)) == {("@s/p@1.0.0", "x@2.0.0")}


# ---- Gradle ---------------------------------------------------------------------------
def test_gradle_lockfile_marks_test_only_dependencies_as_dev(tmp_path: Path) -> None:
    f = tmp_path / "gradle.lockfile"
    f.write_text(
        "# This is a Gradle generated file for dependency locking.\n"
        "com.google.guava:guava:31.1-jre=compileClasspath,runtimeClasspath\n"
        "org.junit.jupiter:junit-jupiter:5.9.0=testCompileClasspath,testRuntimeClasspath\n"
        "org.slf4j:slf4j-api:2.0.7=compileClasspath,testCompileClasspath\n"
        "empty=annotationProcessor\n",
        encoding="utf-8",
    )
    g = parse(f)
    assert g.ecosystem == "Maven" and g.format == "gradle.lockfile"
    assert direct(g) == {
        "com.google.guava:guava@31.1-jre": "prod",
        "org.junit.jupiter:junit-jupiter@5.9.0": "dev",
        "org.slf4j:slf4j-api@2.0.7": "prod",  # one production configuration is enough
    }
    assert g.edges == set()  # Gradle records no edges


def test_buildscript_gradle_lockfile_is_recognised(tmp_path: Path) -> None:
    f = tmp_path / "buildscript-gradle.lockfile"
    f.write_text("org.a:b:1.0=classpath\n", encoding="utf-8")
    assert is_lockfile(f) and names(parse(f)) == {"org.a:b@1.0"}


# ---- SBOMs ----------------------------------------------------------------------------
CDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "metadata": {"component": {"bom-ref": "app", "name": "app"}},
    "components": [
        {"bom-ref": "express", "purl": "pkg:npm/express@4.18.2"},
        {
            "bom-ref": "widget",
            "purl": "pkg:npm/%40scope/widget@1.0.0",
            "components": [{"bom-ref": "nested", "purl": "pkg:npm/qs@6.11.0"}],
        },
        {
            "bom-ref": "jest",
            "purl": "pkg:npm/jest@29.7.0",
            "properties": [{"name": "cdx:npm:package:development", "value": "true"}],
        },
        {"bom-ref": "requests", "purl": "pkg:pypi/Requests@2.31.0"},
        {"bom-ref": "guava", "purl": "pkg:maven/com.google.guava/guava@31.1-jre?type=jar"},
        {"bom-ref": "unpinned", "purl": "pkg:npm/unpinned"},
        {"bom-ref": "odd", "purl": "pkg:deb/debian/curl@7.88"},
        {"bom-ref": "nopurl", "name": "something"},
    ],
    "dependencies": [
        {"ref": "app", "dependsOn": ["express", "widget", "jest", "requests", "guava", "unpinned"]},
        {"ref": "express", "dependsOn": ["nested", "odd"]},
    ],
}


def test_cyclonedx_builds_a_mixed_ecosystem_graph(tmp_path: Path) -> None:
    import json

    f = tmp_path / "app.cdx.json"
    f.write_text(json.dumps(CDX), encoding="utf-8")
    g = parse(f)
    assert g.format == "CycloneDX" and g.ecosystem == "mixed"
    assert {(p.ecosystem, p.label) for p in g.pkgs} == {
        ("npm", "express@4.18.2"),
        ("npm", "@scope/widget@1.0.0"),  # %40 decoded, scope kept
        ("npm", "qs@6.11.0"),  # a nested component is flattened
        ("npm", "jest@29.7.0"),
        ("PyPI", "requests@2.31.0"),  # PEP 503 normalised
        ("Maven", "com.google.guava:guava@31.1-jre"),  # group/artifact -> group:artifact
    }  # unpinned, unsupported (deb) and purl-less components are skipped
    assert edge_labels(g) == {("express@4.18.2", "qs@6.11.0")}
    assert direct(g)["jest@29.7.0"] == "dev" and direct(g)["express@4.18.2"] == "prod"
    assert "unpinned@" not in " ".join(names(g))


def test_spdx_uses_depends_on_dependency_of_and_the_described_root(tmp_path: Path) -> None:
    import json

    doc = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "packages": [
            {"SPDXID": "SPDXRef-app", "name": "app"},  # the product: no purl, not a package
            {
                "SPDXID": "SPDXRef-a",
                "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/a@1.0.0"}],
            },
            {
                "SPDXID": "SPDXRef-b",
                "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/b@2.0.0"}],
            },
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-app",
            },
            {
                "spdxElementId": "SPDXRef-app",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": "SPDXRef-a",
            },
            {
                "spdxElementId": "SPDXRef-b",
                "relationshipType": "DEPENDENCY_OF",
                "relatedSpdxElement": "SPDXRef-a",
            },
        ],
    }
    f = tmp_path / "app.spdx.json"
    f.write_text(json.dumps(doc), encoding="utf-8")
    g = parse(f)
    assert g.format == "SPDX"
    assert direct(g) == {"a@1.0.0": "prod"}
    assert edge_labels(g) == {("a@1.0.0", "b@2.0.0")}  # "b is a dependency of a" means a -> b


@pytest.mark.parametrize("name", ["x.cdx.json", "bom.json", "x.spdx.json"])
def test_a_json_file_that_is_not_an_sbom_is_refused(tmp_path: Path, name: str) -> None:
    f = tmp_path / name
    f.write_text('{"hello": "world"}', encoding="utf-8")
    with pytest.raises(ValueError, match=r"not an? (CycloneDX|SPDX)"):
        parse(f)


def test_a_mixed_ecosystem_sbom_alerts_in_each_registry(tmp_path: Path) -> None:
    import json
    import zipfile

    from scgraph.scan.engine import scan_graph
    from scgraph.scan.sources import OSVOffline, Signals

    def rec(eco, name, id_):
        return {
            "id": id_,
            "summary": id_,
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
            ],
            "affected": [
                {
                    "package": {"ecosystem": eco, "name": name},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                }
            ],
        }

    osv = tmp_path / "osv"
    osv.mkdir()
    for eco, zname, name, id_ in [
        ("npm", "npm", "express", "GHSA-npm"),
        ("PyPI", "pypi", "requests", "GHSA-py"),
        ("Maven", "maven", "com.google.guava:guava", "GHSA-mvn"),
    ]:
        with zipfile.ZipFile(osv / f"{zname}.zip", "w") as z:
            z.writestr(f"{id_}.json", json.dumps(rec(eco, name, id_)))
    f = tmp_path / "app.cdx.json"
    f.write_text(json.dumps(CDX), encoding="utf-8")
    res = scan_graph(parse(f), OSVOffline(osv), Signals(enabled=False))
    assert {x.id for x in res.alerts} == {"GHSA-npm", "GHSA-py", "GHSA-mvn"}
    assert res.ecosystem == "mixed"
    npm = next(x for x in res.alerts if x.id == "GHSA-npm")
    assert npm.path[1:] == ["express@4.18.2"]  # a direct dependency of the described app
