"""The `scgraph scan` command line: exit codes, formats, summaries, incident mode."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from tests.unit.test_scan_engine import RECORDS

from scgraph.cli import main


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
