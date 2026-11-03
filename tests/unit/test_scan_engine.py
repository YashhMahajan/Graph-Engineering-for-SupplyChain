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
