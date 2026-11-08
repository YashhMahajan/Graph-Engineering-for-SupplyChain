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
