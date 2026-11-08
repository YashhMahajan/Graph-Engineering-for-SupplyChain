"""The scan engine: paths as proof, the gate ladder, merging, ranking and fix planning."""

from __future__ import annotations

import json
import zipfile
from datetime import date
from pathlib import Path

import pytest

from scgraph.scan import render
from scgraph.scan.engine import Ignore, Policy, load_ignores, scan_graph
from scgraph.scan.lockfiles import parse
from scgraph.scan.sources import OSVOffline, Signals
from scgraph.scan.upgrade import parent_upgrades


def rec(
    id_,
    name,
    intro="0",
    fixed=None,
    eco="npm",
    aliases=(),
    sev=None,
    withdrawn=None,
    versions=None,
    summary="",
):
    events = [{"introduced": intro}] + ([{"fixed": fixed}] if fixed else [])
    aff = {
        "package": {"ecosystem": eco, "name": name},
        "ranges": [{"type": "SEMVER", "events": events}],
    }
    if versions:
        aff = {"package": {"ecosystem": eco, "name": name}, "versions": versions}
    r = {"id": id_, "aliases": list(aliases), "affected": [aff], "summary": summary or id_}
    if sev:
        r["severity"] = [{"type": "CVSS_V3", "score": sev}]
    if withdrawn:
        r["withdrawn"] = withdrawn
    return r


CRIT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8
LOW = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N"  # 3.1


class FakeOSV:
    name = "fake"

    def __init__(self, records):
        self.records = records

    def query(self, pkgs):
        from scgraph.versions import affected

        out = {}
        for i, p in enumerate(pkgs):
            for r in self.records:
                for a in r["affected"]:
                    if a["package"]["name"] == p.name and affected(p.version, a, "npm"):
                        out.setdefault(i, []).append(r)
                        break
        return out


class FakeSignals(Signals):
    def __init__(self, kev=(), epss=None):
        super().__init__(enabled=True)
        self._kev = set(kev)
        self._epss_map = epss or {}
        self.status = {"kev": "ok", "epss": "ok"}

    def epss(self, cves):
        return {c: v for c, v in self._epss_map.items() if c in set(cves)}


@pytest.fixture
def lock(tmp_path: Path) -> Path:
    doc = {
        "name": "app",
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"web": "1", "chalk": "5"}, "devDependencies": {"testkit": "1"}},
            "node_modules/web": {"version": "1.0.0", "dependencies": {"parser": "1"}},
            "node_modules/parser": {"version": "1.2.0"},
            "node_modules/chalk": {"version": "5.6.1"},
            "node_modules/testkit": {
                "version": "1.0.0",
                "dev": True,
                "dependencies": {"glob": "1"},
            },
            "node_modules/glob": {"version": "1.0.0", "dev": True},
            "node_modules/orphan": {"version": "1.0.0"},
        },
    }
    p = tmp_path / "app" / "package-lock.json"
    p.parent.mkdir()
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


RECORDS = [
    rec("GHSA-aaaa", "parser", fixed="1.3.0", aliases=["CVE-2024-0001"], sev=CRIT),
    rec("PYSEC-dup", "parser", fixed="1.3.0", aliases=["CVE-2024-0001"]),  # same issue, other id
    rec("GHSA-low", "parser", fixed="1.2.5", sev=LOW),
    rec("MAL-2025-1", "chalk", versions=["5.6.1"]),
    rec("GHSA-dev", "glob", fixed="2.0.0", sev=CRIT),
    rec("GHSA-dev-mal", "glob", versions=["1.0.0"]),
    rec("GHSA-gone", "web", fixed="2.0.0", sev=CRIT, withdrawn="2024-01-01T00:00:00Z"),
    rec("GHSA-orph", "orphan", fixed="2.0.0", sev=CRIT),
]


def by_id(res):
    return {f.id: f for f in res.findings}


def test_alerts_carry_paths_and_abstentions_carry_reasons(lock: Path) -> None:
    res = scan_graph(parse(lock), FakeOSV(RECORDS), FakeSignals())
    f = by_id(res)
    assert f["CVE-2024-0001"].alert
    assert f["CVE-2024-0001"].path == ["app", "web@1.0.0", "parser@1.2.0"]
    assert sorted(f["CVE-2024-0001"].ids) == ["GHSA-aaaa", "PYSEC-dup"]  # merged, one finding
    assert res.merged_duplicates == 1
    assert f["MAL-2025-1"].alert and f["MAL-2025-1"].priority == "P0"
    assert (f["GHSA-dev"].alert, f["GHSA-dev"].reason) == (False, "scope")
    assert (f["GHSA-gone"].alert, f["GHSA-gone"].reason) == (False, "withdrawn")
    assert (f["GHSA-orph"].alert, f["GHSA-orph"].reason) == (False, "path")
    assert res.alerts[0].id == "MAL-2025-1"  # ranked first


def test_malicious_is_never_exempt_by_scope(lock: Path) -> None:
    recs = [*RECORDS, rec("MAL-2025-9", "glob", versions=["1.0.0"])]
    res = scan_graph(parse(lock), FakeOSV(recs), FakeSignals())
    f = by_id(res)["MAL-2025-9"]
    assert f.alert and f.dev_only and f.path == ["app", "testkit@1.0.0", "glob@1.0.0"]


def test_include_dev_and_severity_floor_with_kev_override(lock: Path) -> None:
    pol = Policy(include_dev=True, min_severity=7.0)
    sig = FakeSignals(kev={"CVE-2024-0002"})
    recs = [*RECORDS, rec("GHSA-kev", "parser", fixed="1.2.9", aliases=["CVE-2024-0002"], sev=LOW)]
    f = by_id(scan_graph(parse(lock), FakeOSV(recs), sig, pol))
    assert f["GHSA-dev"].alert
    assert (f["GHSA-low"].alert, f["GHSA-low"].reason) == (False, "severity")
    assert f["CVE-2024-0002"].alert and f["CVE-2024-0002"].priority == "P1"  # KEV beats the floor


def test_epss_raises_priority(lock: Path) -> None:
    recs = [rec("GHSA-m", "parser", fixed="1.3.0", aliases=["CVE-2024-0003"], sev=LOW)]
    res = scan_graph(parse(lock), FakeOSV(recs), FakeSignals(epss={"CVE-2024-0003": (0.4, 0.99)}))
    assert res.alerts[0].priority == "P2" and res.alerts[0].epss == 0.4


def test_ignores_expire(lock: Path, tmp_path: Path) -> None:
    ig = tmp_path / ".scgraph-ignore"
    ig.write_text("CVE-2024-0001 until=2024-06-30  # accepted risk\nGHSA-low\n", encoding="utf-8")
    ignores = load_ignores(ig)
    assert ignores[0] == Ignore("CVE-2024-0001", "accepted risk", date(2024, 6, 30))
    before = by_id(
        scan_graph(
            parse(lock),
            FakeOSV(RECORDS),
            FakeSignals(),
            Policy(ignores=ignores, today=date(2024, 6, 1)),
        )
    )
    after = by_id(
        scan_graph(
            parse(lock),
            FakeOSV(RECORDS),
            FakeSignals(),
            Policy(ignores=ignores, today=date(2024, 7, 1)),
        )
    )
    assert before["CVE-2024-0001"].reason == "ignored"
    assert after["CVE-2024-0001"].alert  # the ignore expired
    assert after["GHSA-low"].reason == "ignored"


def test_incident_mode_filters_to_one_advisory(lock: Path) -> None:
    res = scan_graph(parse(lock), FakeOSV(RECORDS), FakeSignals(), Policy(only={"CVE-2024-0001"}))
    assert [f.id for f in res.findings] == ["CVE-2024-0001"]


def test_fix_plan_takes_smallest_version_clearing_everything(lock: Path) -> None:
    res = scan_graph(parse(lock), FakeOSV(RECORDS), FakeSignals())
    plan = {a["package"]: a for a in res.remediation}
    assert plan["parser"]["to"] == "1.3.0"  # 1.2.5 fixes one advisory but not the other
    assert plan["parser"]["via"] == ["web@1.0.0"]
    assert plan["chalk"]["action"] == "remove"


def test_parent_upgrade_finds_the_direct_bump(lock: Path) -> None:
    g = parse(lock)
    res = scan_graph(g, FakeOSV(RECORDS), FakeSignals())
    docs = {
        "web": {
            "versions": {
                "1.0.0": {"dependencies": {"parser": "1.2.0"}},
                "1.1.0": {"dependencies": {"parser": "~1.2.4"}},  # 1.2.5: still has GHSA-aaaa
                "1.2.0-beta": {"dependencies": {"parser": "^1.3.0"}},  # prerelease, skipped
                "1.2.0": {"dependencies": {"parser": "^1.3.0"}},
                "2.0.0": {"dependencies": {}},
            }
        },
        "parser": {"versions": {v: {} for v in ("1.2.0", "1.2.5", "1.3.0", "1.4.0")}},
    }

    def fetch(url: str):
        return docs.get(url.rsplit("/", 1)[-1])

    hits = FakeOSV(RECORDS).query(g.pkgs)
    bumps = parent_upgrades(g, res.findings, hits, fetch)
    assert bumps == [
        {
            "direct": "web",
            "from": "1.0.0",
            "to": "1.2.0",
            "major": False,
            "clears_packages": ["parser"],
            "clears": ["CVE-2024-0001", "GHSA-low"],
            "remaining": [],
        }
    ]


def test_renderers(lock: Path) -> None:
    res = scan_graph(parse(lock), FakeOSV(RECORDS), FakeSignals())
    text = render.to_text([res], color=False)
    assert "P0 MALICIOUS" in text and "└─ parser@1.2.0" in text and "fix plan" in text
    sarif = json.loads(render.to_sarif([res], base=str(lock.parent)))
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert {r["ruleId"] for r in run["results"]} == {f.id for f in res.alerts}
    assert all("security-severity" in r["properties"] for r in run["tool"]["driver"]["rules"])
    assert (
        run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "package-lock.json"
    )
    doc = json.loads(render.to_json([res]))
    assert doc["results"][0]["summary"]["alerts"] == len(res.alerts)
    md = render.to_markdown([res])
    assert "| **P0** |" in md and "app -> web@1.0.0 -> parser@1.2.0" in md


def test_offline_source_matches_dumps_and_builds_an_index(tmp_path: Path) -> None:
    osv = tmp_path / "osv"
    osv.mkdir()
    with zipfile.ZipFile(osv / "npm.zip", "w") as z:
        for r in RECORDS:
            z.writestr(f"{r['id']}.json", json.dumps(r))
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"parser": "1"}},
                    "node_modules/parser": {"version": "1.2.0"},
                },
            }
        ),
        encoding="utf-8",
    )
    src = OSVOffline(osv)
    res = scan_graph(parse(lock), src, Signals(enabled=False))
    assert {f.id for f in res.alerts} == {"CVE-2024-0001", "GHSA-low"}
    assert (osv / "npm.zip.index.json").exists()
    again = scan_graph(parse(lock), OSVOffline(osv), Signals(enabled=False))  # from the index
    assert {f.id for f in again.alerts} == {"CVE-2024-0001", "GHSA-low"}
    assert src.get("MAL-2025-1")["id"] == "MAL-2025-1"


def test_openvex_maps_alerts_and_graph_proven_abstentions(lock: Path) -> None:
    res = scan_graph(parse(lock), FakeOSV(RECORDS), FakeSignals())
    doc = json.loads(render.to_openvex([res]))
    assert doc["@context"] == "https://openvex.dev/ns/v0.2.0"
    st = {s["vulnerability"]["name"]: s for s in doc["statements"]}
    # alert -> affected, with the dependency path as the action statement
    a = st["CVE-2024-0001"]
    assert a["status"] == "affected"
    assert "app -> web@1.0.0 -> parser@1.2.0" in a["action_statement"]
    assert a["vulnerability"]["aliases"] == ["GHSA-aaaa", "PYSEC-dup"]
    assert a["products"][0]["@id"].startswith("pkg:generic/app?")
    assert a["products"][0]["subcomponents"][0]["@id"].startswith("pkg:npm/")
    # graph-proven abstentions -> not_affected with a justification
    assert st["GHSA-orph"]["status"] == "not_affected"
    assert st["GHSA-orph"]["justification"] == "component_not_present"
    assert st["GHSA-dev"]["justification"] == "vulnerable_code_not_in_execute_path"
    # a withdrawn advisory is not a vulnerability: no statement
    assert "GHSA-gone" not in st


def test_openvex_never_turns_policy_into_a_not_affected_claim(lock: Path) -> None:
    ignores = [Ignore("CVE-2024-0001", "accepted risk")]
    res = scan_graph(
        parse(lock), FakeOSV(RECORDS), FakeSignals(), Policy(min_severity=9.0, ignores=ignores)
    )
    reasons = {f.id: f.reason for f in res.findings}
    assert reasons["CVE-2024-0001"] == "ignored" and reasons["GHSA-low"] == "severity"
    names = {s["vulnerability"]["name"] for s in json.loads(render.to_openvex([res]))["statements"]}
    assert not names & {"CVE-2024-0001", "GHSA-low"}  # ignored and below-floor stay silent


def test_openvex_product_purl_is_percent_encoded(tmp_path: Path) -> None:
    lock = tmp_path / "my app#x%" / "package-lock.json"  # legal on Windows too
    lock.parent.mkdir()
    lock.write_text(json.dumps({"lockfileVersion": 3, "packages": {"": {}}}), encoding="utf-8")
    res = scan_graph(parse(lock), FakeOSV([]), FakeSignals())
    res.findings.append(_stub_finding())
    doc = json.loads(render.to_openvex([res]))
    assert doc["statements"][0]["products"][0]["@id"].startswith("pkg:generic/my%20app%23x%25?")


def _stub_finding():
    from scgraph.scan.engine import Finding

    return Finding(
        id="GHSA-x",
        ids=["GHSA-x"],
        aliases=[],
        summary="",
        package="p",
        version="1.0.0",
        ecosystem="npm",
        purl="pkg:npm/p@1.0.0",
        score=None,
        severity="unknown",
        malicious=False,
        withdrawn=False,
        kev=False,
        epss=None,
        epss_percentile=None,
        path=None,
        dev_only=False,
        fixed_in=None,
        fix="",
        alert=False,
        reason="path",
    )


def _vex(*stmts, ts="2026-01-01T00:00:00Z"):
    from scgraph.scan.vex import VexIndex, parse_vex

    doc = {"@context": "https://openvex.dev/ns/v0.2.0", "timestamp": ts, "statements": list(stmts)}
    return VexIndex(parse_vex(doc))


def _vs(vuln, purl, status="not_affected", **kw):
    s = {"vulnerability": {"name": vuln}, "products": [{"@id": purl}], "status": status, **kw}
    if status == "not_affected":
        s.setdefault("impact_statement", "supplier says the code path is not used")
    if status == "affected":
        s.setdefault("action_statement", "upgrade")
    return s


def test_vex_not_affected_turns_an_alert_into_a_named_abstention(lock: Path) -> None:
    vex = _vex(_vs("CVE-2024-0001", "pkg:npm/parser@1.2.0"))
    res = scan_graph(parse(lock), FakeOSV(RECORDS), FakeSignals(), Policy(vex=vex))
    f = by_id(res)["CVE-2024-0001"]
    assert (f.alert, f.reason) == (False, "vex")
    assert "VEX" in f.detail


def test_vex_matches_on_any_alias_of_the_merged_finding(lock: Path) -> None:
    vex = _vex(_vs("GHSA-aaaa", "pkg:npm/parser@1.2.0"))  # the CVE finding merged this id
    res = scan_graph(parse(lock), FakeOSV(RECORDS), FakeSignals(), Policy(vex=vex))
    assert by_id(res)["CVE-2024-0001"].reason == "vex"


def test_vex_for_another_version_does_not_suppress(lock: Path) -> None:
    vex = _vex(_vs("CVE-2024-0001", "pkg:npm/parser@9.9.9"))
    res = scan_graph(parse(lock), FakeOSV(RECORDS), FakeSignals(), Policy(vex=vex))
    assert by_id(res)["CVE-2024-0001"].alert


def test_a_newer_affected_statement_revokes_the_suppression(lock: Path) -> None:
    old = _vs("CVE-2024-0001", "pkg:npm/parser@1.2.0", timestamp="2026-01-01T00:00:00Z")
    new = _vs("CVE-2024-0001", "pkg:npm/parser@1.2.0", "affected", timestamp="2026-02-01T00:00:00Z")
    res = scan_graph(parse(lock), FakeOSV(RECORDS), FakeSignals(), Policy(vex=_vex(old, new)))
    assert by_id(res)["CVE-2024-0001"].alert


def test_vex_can_never_suppress_malware(lock: Path) -> None:
    vex = _vex(_vs("MAL-2025-1", "pkg:npm/chalk@5.6.1"))
    res = scan_graph(parse(lock), FakeOSV(RECORDS), FakeSignals(), Policy(vex=vex))
    f = by_id(res)["MAL-2025-1"]
    assert f.alert and f.priority == "P0"


def test_openvex_products_stay_distinct_for_same_named_directories(tmp_path: Path) -> None:
    locks = []
    for repo in ("one", "two"):
        p = tmp_path / repo / "frontend" / "package-lock.json"
        p.parent.mkdir(parents=True)
        p.write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"dependencies": {"parser": "1"}},
                        "node_modules/parser": {"version": "1.2.0"},
                    },
                }
            ),
            encoding="utf-8",
        )
        locks.append(p)
    results = [scan_graph(parse(p), FakeOSV(RECORDS), FakeSignals()) for p in locks]
    ids = {s["products"][0]["@id"] for s in json.loads(render.to_openvex(results))["statements"]}
    assert len(ids) == 2 and all(i.startswith("pkg:generic/frontend?") for i in ids)
    assert not any(str(tmp_path) in i for i in ids)  # no absolute path is published
