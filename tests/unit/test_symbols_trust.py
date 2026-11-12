"""Ledger claims, dataset signing, OSV export and the grounded `ask` command."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from scgraph.cli import main
from scgraph.scan.ask import Sentence, answer, render
from scgraph.symbols import claims, signing
from scgraph.symbols.dataset import write
from scgraph.symbols.export import bundle, osv_patch

REC = {
    "id": "GHSA-aaaa-bbbb-cccc",
    "aliases": ["CVE-2024-0001"],
    "ecosystem": "PyPI",
    "package": "pyyaml",
    "symbol": "yaml.constructor.construct",
    "entry_points": ["yaml.load"],
    "method": "fix-diff+llm",
    "verified": "verified",
    "confidence": 0.8,
    "evidence": {"fix": "https://github.com/yaml/pyyaml/commit/abc"},
    "llm": {"model": "m:free", "prompt_hash": "h" * 8},
    "affected_version": "5.3",
    "fixed_version": "5.4",
}


def test_a_claim_is_recorded_once_and_replaced_when_the_symbol_changes(tmp_path: Path) -> None:
    led = claims.open_claims(tmp_path / "led")
    assert claims.record_claims(led, [REC]) == {"added": 2, "unchanged": 0, "superseded": 0}
    assert claims.record_claims(led, [REC]) == {"added": 0, "unchanged": 2, "superseded": 0}
    assert claims.claims_for(led, "CVE-2024-0001")[0][0]["symbol"] == REC["symbol"]  # by alias
    rows, receipt = claims.claims_for(led, REC["id"])
    assert rows == [
        {
            "symbol": "yaml.constructor.construct",
            "confidence": 0.8,
            "source": "method=fix-diff+llm; evidence=https://github.com/yaml/pyyaml/commit/abc; "
            "verified=verified; model=m:free; prompt=hhhhhhhh",
        }
    ]
    assert claims.check_receipt(led, receipt)
    newer = {**REC, "symbol": "yaml.loader.load", "confidence": 0.9}
    assert claims.record_claims(led, [newer]) == {"added": 2, "unchanged": 0, "superseded": 2}
    assert [r["symbol"] for r in claims.claims_for(led, REC["id"])[0]] == ["yaml.loader.load"]
    assert led.verify() > 0  # the chain is intact


def test_a_tampered_ledger_fails_verification(tmp_path: Path) -> None:
    led = claims.open_claims(tmp_path / "led")
    claims.record_claims(led, [REC])
    log = tmp_path / "led" / "log.jsonl"
    log.write_text(log.read_text().replace("0.8", "0.99"))
    with pytest.raises(Exception):  # noqa: B017 (the ledger raises its own error type)
        claims.open_claims(tmp_path / "led").verify()


def test_verify_command_needs_no_key_option(capsys) -> None:
    assert main(["symbols", "verify"]) in (0, 1)  # runs without an AttributeError
    assert capsys.readouterr().out


def test_osv_patch_adds_affected_functions_and_provenance() -> None:
    p = osv_patch(REC)
    a = p["affected"][0]
    assert a["package"] == {"ecosystem": "PyPI", "name": "pyyaml"}
    assert a["ecosystem_specific"]["affected_functions"] == ["yaml.constructor.construct"]
    assert p["database_specific"]["scgraph"]["evidence"].endswith("/commit/abc")


def test_bundle_copies_data_and_writes_one_patch_per_advisory(tmp_path: Path) -> None:
    data = tmp_path / "data"
    write([REC, {**REC, "id": "GHSA-dddd-eeee-ffff"}], data / "pypi.jsonl")
    out = tmp_path / "out"
    files = bundle(data, out)
    names = {f.name for f in files}
    assert {"pypi.jsonl", "pypi.manifest.json", "GHSA-aaaa-bbbb-cccc.json"} <= names
    assert json.loads((out / "osv-patches" / "GHSA-dddd-eeee-ffff.json").read_text())["id"]


@pytest.mark.skipif(
    pytest.importorskip("cryptography", reason="needs the sign extra") is None, reason="x"
)
def test_signature_round_trip_and_tamper_detection(tmp_path: Path) -> None:
    data = tmp_path / "pypi.jsonl"
    write([REC], data)
    priv, pub = tmp_path / "k.key", tmp_path / "k.pub"
    signing.generate_key(priv, pub)
    if os.name == "posix":  # Windows has no Unix file modes
        assert oct(priv.stat().st_mode)[-3:] == "600"
    with pytest.raises(signing.SigningError, match="refusing"):
        signing.generate_key(priv, pub)  # a key is never replaced
    signing.sign(data, priv)
    signing.verify(data, pub)
    data.write_text(data.read_text().replace("0.8", "0.9"))
    with pytest.raises(signing.SigningError, match="does not match"):
        signing.verify(data, pub)
    other = tmp_path / "other.pub"
    signing.generate_key(tmp_path / "o.key", other)
    write([REC], data)
    signing.sign(data, priv)
    with pytest.raises(signing.SigningError, match="signature"):
        signing.verify(data, other)  # signed by a different key


SCAN = {
    "results": [
        {
            "alerts": [
                {
                    "id": "CVE-2021-33503",
                    "ids": ["CVE-2021-33503"],
                    "aliases": [],
                    "package": "urllib3",
                    "version": "1.26.4",
                    "score": 7.5,
                    "path": ["app", "requests@2.25.0", "urllib3@1.26.4"],
                    "reachability": "reachable",
                    "symbols_source": "inferred",
                    "reach_hops": 2,
                    "fix": "upgrade urllib3 to 1.26.5",
                },
                {
                    "id": "CVE-2023-37920",
                    "ids": [],
                    "aliases": [],
                    "package": "certifi",
                    "version": "2020.12.5",
                    "score": None,
                    "path": ["app", "certifi@2020.12.5"],
                    "reachability": "not_analyzed",
                    "fix": "",
                },
            ]
        }
    ]
}


def test_every_sentence_has_a_citation_and_names_only_scan_facts() -> None:
    out = answer("why am I exposed to CVE-2021-33503?", SCAN)
    text = render(out)
    assert all(s.cite for s in out)
    assert "enters your project through app > requests@2.25.0 > urllib3@1.26.4" in text
    assert "Your code calls the vulnerable function through 2 packages" in text
    assert "[claim:CVE-2021-33503 (inferred from the fix commit)]" in text
    assert "certifi" not in text  # the question did not name it
    assert "does not close the alert" in text


def test_ask_by_package_and_without_a_match_and_without_alerts() -> None:
    assert "certifi 2020.12.5 is affected" in render(answer("is certifi a problem?", SCAN))
    general = answer("what should I look at first?", SCAN)
    assert general[0].cite == "scan:summary" and len(general) == 3
    assert render(answer("anything?", {"results": [{"alerts": []}]})) == (
        "The scan found no alert.  [scan:summary]"
    )
    with pytest.raises(ValueError):
        Sentence("an uncited claim", "")


def test_ask_command_runs_the_scan_and_cites(tmp_path: Path, capsys) -> None:
    import zipfile

    proj = tmp_path / "p"
    proj.mkdir()
    (proj / "requirements.txt").write_text("pyyaml==5.3\n")
    osv = tmp_path / "osv"
    osv.mkdir()
    rec = {
        "id": "GHSA-yaml",
        "summary": "unsafe load",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "pyyaml"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.4"}]}
                ],
            }
        ],
    }
    with zipfile.ZipFile(osv / "pypi.zip", "w") as z:
        z.writestr("GHSA-yaml.json", json.dumps(rec))
    code = main(
        [
            "ask",
            "is pyyaml a problem?",
            str(proj),
            "--offline",
            str(osv),
            "--no-signals",
            "--no-registry",
        ]
    )
    out = capsys.readouterr().out
    assert (
        code == 0 and "pyyaml 5.3 is affected by GHSA-yaml" in out and "[advisory:GHSA-yaml]" in out
    )
