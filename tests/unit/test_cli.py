"""The `scgraph scan` command line: exit codes, formats, summaries, incident mode."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from scgraph.cli import main

RECORDS = [
    {
        "id": "GHSA-aaaa",
        "aliases": ["CVE-2024-0001"],
        "summary": "critical",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "parser"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.3.0"}]}],
            }
        ],
    },
    {
        "id": "GHSA-low",
        "aliases": [],
        "summary": "low",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N"}],
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "parser"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.5"}]}],
            }
        ],
    },
]


def test_cli_scan_exit_codes_and_formats(tmp_path: Path, monkeypatch, capsys) -> None:
    osv = tmp_path / "osv"
    osv.mkdir()
    with zipfile.ZipFile(osv / "npm.zip", "w") as z:
        for r in RECORDS:
            z.writestr(f"{r['id']}.json", json.dumps(r))
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "package-lock.json").write_text(
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
    base = ["scan", str(proj), "--offline", str(osv), "--no-signals", "--no-registry"]
    assert main(base) == 1
    assert "CVE-2024-0001" in capsys.readouterr().out
    assert main([*base, "--fail-on", "P0"]) == 0  # worst alert is P2
    capsys.readouterr()
    assert (
        main([*base, "--fail-on", "never", "-f", "sarif", "-o", str(tmp_path / "out.sarif")]) == 0
    )
    assert json.loads((tmp_path / "out.sarif").read_text())["version"] == "2.1.0"
    summ = tmp_path / "summary.md"
    assert main([*base, "-f", "json", "--summary", str(summ)]) == 1
    assert json.loads(capsys.readouterr().out)["results"][0]["summary"]["alerts"] == 2
    assert summ.read_text().startswith("## scgraph")
    assert main([*base, "--advisory", "GHSA-nothing"]) == 0
    assert main(["scan", str(tmp_path / "missing")]) == 2


def _project(tmp_path: Path) -> list[str]:
    osv = tmp_path / "osv"
    osv.mkdir()
    with zipfile.ZipFile(osv / "npm.zip", "w") as z:
        for r in RECORDS:
            z.writestr(f"{r['id']}.json", json.dumps(r))
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "package-lock.json").write_text(
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
    return ["scan", str(proj), "--offline", str(osv), "--no-signals", "--no-registry"]


def _vex_file(path: Path, *vulns: str) -> Path:
    stmts = [
        {
            "vulnerability": {"name": v},
            "products": [{"@id": "pkg:npm/parser@1.2.0"}],
            "status": "not_affected",
            "justification": "vulnerable_code_not_in_execute_path",
        }
        for v in vulns
    ]
    path.write_text(
        json.dumps({"@context": "https://openvex.dev/ns/v0.2.0", "statements": stmts}),
        encoding="utf-8",
    )
    return path


def test_cli_vex_suppresses_and_reports_the_reason(tmp_path: Path, capsys) -> None:
    base = _project(tmp_path)
    assert main(base) == 1
    capsys.readouterr()
    vex = _vex_file(tmp_path / "s.vex.json", "CVE-2024-0001", "GHSA-low")
    assert main([*base, "--vex", str(vex), "-f", "json"]) == 0
    summary = json.loads(capsys.readouterr().out)["results"][0]["summary"]
    assert summary["alerts"] == 0 and summary["abstained"] == {"vex": 2}


def test_cli_rejects_a_malformed_vex_file(tmp_path: Path, capsys) -> None:
    base = _project(tmp_path)
    bad = tmp_path / "bad.json"
    bad.write_text('{"@context": "https://openvex.dev/ns/v0.2.0", "statements": [{}]}')
    assert main([*base, "--vex", str(bad)]) == 2  # never scan without the file you asked for
    assert "scgraph:" in capsys.readouterr().err
    assert main([*base, "--vex", str(tmp_path / "missing.json")]) == 2


def test_cli_openvex_output_is_valid_input_for_vex(tmp_path: Path, capsys) -> None:
    from scgraph.scan.vex import parse_vex

    base = _project(tmp_path)
    main([*base, "-f", "openvex", "--fail-on", "never"])
    stmts = parse_vex(json.loads(capsys.readouterr().out))
    assert stmts and all(s.status == "affected" for s in stmts)  # both advisories alert


def test_cli_audit_exit_codes_output_and_errors(tmp_path: Path, capsys) -> None:
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"s": {"command": "node", "args": ["server.js"]}}})
    )
    assert main(["audit", str(tmp_path), "--offline-check"]) == 0  # only info: starts, not risky
    out = capsys.readouterr().out
    assert "1 command(s) run automatically, 0 finding(s)" in out and "-v lists" in out
    main(["audit", str(tmp_path), "--offline-check", "-v"])
    assert "INFO  .mcp.json mcpServers.s: [runs_automatically]" in capsys.readouterr().out

    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"s": {"command": "npx", "args": ["-y", "some-server"]}}})
    )
    assert main(["audit", str(tmp_path), "--offline-check"]) == 1  # unpinned launcher: warn
    assert "WARN  .mcp.json mcpServers.s: [unpinned_package]" in capsys.readouterr().out
    assert main(["audit", str(tmp_path), "--offline-check", "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["worst"] == "warn"

    assert main(["audit", str(tmp_path / "missing")]) == 2
    assert "no such file or directory" in capsys.readouterr().err


def test_cli_audit_of_a_clean_directory_is_quiet_and_exits_0(tmp_path: Path, capsys) -> None:
    assert main(["audit", str(tmp_path), "--offline-check"]) == 0
    assert "0 command(s) run automatically, 0 finding(s)" in capsys.readouterr().out


def _scan_args(tmp_path: Path, proj: Path, hist: Path) -> list[str]:
    return [
        "scan", str(proj), "--offline", str(tmp_path / "osv"), "--no-signals", "--no-registry",
        "--fail-on", "never", "--history", str(hist),
    ]  # fmt: skip


def _lock_with_parser(proj: Path, version: str) -> None:
    (proj / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"parser": "1"}},
                    "node_modules/parser": {"version": version},
                },
            }
        ),
        encoding="utf-8",
    )


def test_cli_history_records_scans_and_answers_when_exposure_began(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    base = _project(tmp_path)  # writes osv/ and proj/ with parser@1.2.0 (vulnerable)
    proj, hist = tmp_path / "proj", tmp_path / "hist"
    monkeypatch.chdir(tmp_path)
    args = _scan_args(tmp_path, proj, hist)
    assert base[0] == "scan" and main(args) == 0
    assert "3 exposure(s) opened, 0 closed" in capsys.readouterr().err  # 2 advisories, 1 alias

    assert main(["history", str(hist), "--advisory", "CVE-2024-0001"]) == 1  # still exposed
    out = capsys.readouterr().out
    assert "1 exposure episode(s)" in out and "proj/package-lock.json" in out
    assert "still exposed" in out and "not when the code became vulnerable" in out

    _lock_with_parser(proj, "1.3.0")  # fixed
    main(args)
    assert "0 exposure(s) opened, 3 closed" in capsys.readouterr().err
    assert main(["history", str(hist), "--advisory", "CVE-2024-0001"]) == 0  # no longer exposed
    assert "no longer an alert" in capsys.readouterr().out


def test_cli_history_receipt_verify_and_check(tmp_path: Path, monkeypatch, capsys) -> None:
    _project(tmp_path)
    proj, hist, receipt = tmp_path / "proj", tmp_path / "hist", tmp_path / "r.json"
    monkeypatch.chdir(tmp_path)
    main(_scan_args(tmp_path, proj, hist))
    capsys.readouterr()
    main(["history", str(hist), "--advisory", "GHSA-aaaa", "--receipt", str(receipt), "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["advisory"] == "GHSA-aaaa" and len(doc["episodes"]) == 1
    assert main(["history", str(hist), "--check", str(receipt)]) == 0
    assert "receipt verified" in capsys.readouterr().out
    assert main(["history", str(hist), "--verify"]) == 0
    assert "chain intact" in capsys.readouterr().out
    log = hist / "log.jsonl"
    log.write_text(log.read_text().replace("lockfile:proj/", "lockfile:xxxx/"))
    assert main(["history", str(hist), "--verify"]) == 2  # tampering: an error, not a pass
    assert "scgraph:" in capsys.readouterr().err


def test_cli_history_refuses_incident_mode_and_a_missing_ledger(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    _project(tmp_path)
    monkeypatch.chdir(tmp_path)
    args = _scan_args(tmp_path, tmp_path / "proj", tmp_path / "hist")
    assert main([*args, "--advisory", "GHSA-aaaa"]) == 2  # a subset would close other exposures
    assert "cannot be combined with --advisory" in capsys.readouterr().err
    assert not (tmp_path / "hist").exists()
    assert main(["history", str(tmp_path / "nope"), "--verify"]) == 2
    assert "not a scan history" in capsys.readouterr().err


def test_cli_scan_html_report(tmp_path: Path, capsys) -> None:
    base = _project(tmp_path)
    out = tmp_path / "report.html"
    assert main([*base, "-f", "html", "-o", str(out), "--fail-on", "never"]) == 0
    page = out.read_text()
    assert page.startswith("<!doctype html>") and "CVE-2024-0001" in page
    assert "<script" not in page
    assert main([*base, "-f", "html"]) == 1  # the exit code still follows --fail-on
    assert capsys.readouterr().out.startswith("<!doctype html>")


def test_cli_imports_hint_marks_alerts_but_never_suppresses_them(tmp_path: Path, capsys) -> None:
    base = _project(tmp_path)
    proj = tmp_path / "proj"
    (proj / "index.js").write_text("const p = require('parser');\n", encoding="utf-8")
    assert main([*base, "--imports", "-f", "json"]) == 1  # still alerts, exit code unchanged
    doc = json.loads(capsys.readouterr().out)["results"][0]
    assert doc["summary"]["alerts"] == 2
    assert {a["imported"] for a in doc["alerts"]} == {"imported"}
    main([*base, "--imports"])
    assert "imported" in capsys.readouterr().out

    (proj / "index.js").write_text("const p = require('something-else');\n", encoding="utf-8")
    assert main([*base, "--imports", "-f", "json"]) == 1  # not imported is a hint, not a pass
    doc = json.loads(capsys.readouterr().out)["results"][0]
    assert doc["summary"]["alerts"] == 2
    assert {a["imported"] for a in doc["alerts"]} == {"not_imported"}
    main([*base, "--imports"])
    assert "not imported" in capsys.readouterr().out

    main([*base, "-f", "json"])  # without the flag the field stays empty
    assert {a["imported"] for a in json.loads(capsys.readouterr().out)["results"][0]["alerts"]} == {
        ""
    }
