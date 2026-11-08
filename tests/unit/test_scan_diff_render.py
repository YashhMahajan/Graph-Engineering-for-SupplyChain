"""Diff output: terminal text, JSON, and a Markdown comment that a hostile lockfile cannot break."""

from __future__ import annotations

import json

from scgraph.scan.diff import Delta
from scgraph.scan.diff_render import MARKER, delta_json, delta_markdown, delta_text
from scgraph.scan.engine import Finding
from scgraph.scan.render import md_safe


def finding(id_="MAL-1", pkg="chalk", ver="5.6.1", prio="P0", path=None, fix="remove it"):
    return Finding(
        id=id_,
        ids=[id_],
        aliases=[],
        summary="s",
        package=pkg,
        version=ver,
        ecosystem="npm",
        purl=f"pkg:npm/{pkg}@{ver}",
        score=None,
        severity="malicious",
        malicious=True,
        withdrawn=False,
        kev=False,
        epss=None,
        epss_percentile=None,
        path=path or ["app", f"{pkg}@{ver}"],
        dev_only=False,
        fixed_in=None,
        fix=fix,
        alert=True,
        reason="alert",
        priority=prio,
    )


def delta(**kw):
    base = {"path": "package-lock.json", "base_exists": True}
    return Delta(**{**base, **kw})


def test_text_shows_new_alerts_with_paths_resolved_and_counts() -> None:
    d = delta(
        new_alerts=[finding(path=["app", "express@4.21.2", "chalk@5.6.1"])],
        resolved=[finding("GHSA-old", "parser", "1.2.0", "P2")],
        persisting=3,
        added=["chalk@5.6.1"],
    )
    out = delta_text([d], "main", color=False)
    assert "package-lock.json  vs main" in out and "+1 package" in out
    assert "NEW P0 MALICIOUS" in out and "└─ chalk@5.6.1" in out
    assert "resolved  GHSA-old" in out
    assert "1 new alert · 1 resolved · 3 unchanged" in out
    assert "\033[" not in out  # color is off


def test_text_marks_a_new_lockfile_and_totals_across_files() -> None:
    a, b = delta(base_exists=False, new_alerts=[finding()]), delta(path="svc/package-lock.json")
    out = delta_text([a, b], "origin/main", color=False)
    assert "(new lockfile)" in out and "total: 1 new alert" in out


def test_json_carries_summary_and_per_file_detail() -> None:
    d = delta(new_alerts=[finding()], persisting=2, changed=[("parser", "1.2.0", "1.3.0")])
    doc = json.loads(delta_json([d], "main"))
    assert doc["base"] == "main" and doc["summary"] == {
        "new_alerts": 1,
        "resolved": 0,
        "persisting": 2,
    }
    r = doc["results"][0]
    assert r["new_alerts"][0]["id"] == "MAL-1"
    assert r["packages"]["changed"] == [{"name": "parser", "from": "1.2.0", "to": "1.3.0"}]


def test_markdown_starts_with_the_marker_and_reports_a_clean_change() -> None:
    md = delta_markdown([delta(persisting=4)], "main")
    assert md.splitlines()[0] == MARKER
    assert "no new alerts in this change" in md and "4 unchanged" in md


def test_markdown_table_paths_and_resolved() -> None:
    d = delta(new_alerts=[finding()], resolved=[finding("GHSA-old", "parser", "1.2.0")])
    md = delta_markdown([d], "main")
    assert "1 new alert in this change" in md
    assert "| **P0** | [MAL-1](https://osv.dev/vulnerability/MAL-1) | `chalk@5.6.1` |" in md
    assert "MAL-1: app -> chalk@5.6.1" in md and "Resolved by this change: `GHSA-old`" in md


def test_md_safe_neutralises_every_markdown_breakout() -> None:
    assert md_safe("a`b<c>d|e\\f\ng\rh") == "a_b_c_d_e_f_g_h"
    assert md_safe(1) == "1" and md_safe("@types/node@1.0.0") == "@types/node@1.0.0"


def test_a_hostile_package_name_cannot_break_the_comment() -> None:
    evil = "x`</details><img src=//evil/p.png>|` ```\n## injected"
    d = delta(
        new_alerts=[finding(pkg=evil, fix=f"upgrade {evil}", path=["app", evil])],
        added=[evil],
        changed=[(evil, "1`", "2|")],
    )
    md = delta_markdown([d], "ma`in")
    assert "<img" not in md and "</details><" not in md.replace("</details>\n", "")
    row = next(line for line in md.splitlines() if line.startswith("| **P0**"))
    assert row.count("|") == 6  # the attacker's pipe did not add a table cell
    assert md.count("```") == 2  # exactly one fence, opened and closed by us
    assert "\n## injected" not in md  # the newline could not start a heading
