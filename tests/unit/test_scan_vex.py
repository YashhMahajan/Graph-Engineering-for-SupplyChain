"""OpenVEX input: strict parsing, purl matching, and newest-statement-wins."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scgraph.scan.vex import VexError, VexIndex, load_vex, parse_vex, purl_key

CTX = "https://openvex.dev/ns/v0.2.0"


def stmt(vuln="CVE-1", purl="pkg:npm/lodash@4.17.20", status="not_affected", **kw):
    s = {
        "vulnerability": {"name": vuln},
        "products": [{"@id": purl}],
        "status": status,
        **kw,
    }
    if status == "not_affected":
        s.setdefault("justification", "component_not_present")
    if status == "affected":
        s.setdefault("action_statement", "upgrade")
    return s


def doc(*stmts, ts="2026-01-01T00:00:00Z"):
    return {"@context": CTX, "timestamp": ts, "statements": list(stmts)}


def test_purl_key_normalises_scope_encoding_and_drops_qualifiers() -> None:
    assert purl_key("pkg:npm/%40a/b@1.0.0") == purl_key("pkg:npm/@a/b@1.0.0?x=y#sub")
    assert purl_key("pkg:npm/@a/b@1.0.0") == ("npm", "@a/b", "1.0.0")
    assert purl_key("pkg:npm/@a/b") == ("npm", "@a/b", None)  # leading @ is the scope
    assert purl_key("pkg:PyPI/Django@4.2") == ("pypi", "Django", "4.2")


@pytest.mark.parametrize("bad", ["npm/lodash", "pkg:npm", "pkg:/x"])
def test_purl_key_rejects_non_purls(bad: str) -> None:
    with pytest.raises(VexError):
        purl_key(bad)


def test_not_affected_matches_exact_version_and_alias() -> None:
    d = doc(
        {
            "vulnerability": {"name": "GHSA-x", "aliases": ["CVE-1"]},
            "products": [{"@id": "pkg:npm/lodash@4.17.20"}],
            "status": "not_affected",
            "impact_statement": "we never call _.template",
        }
    )
    idx = VexIndex(parse_vex(d))
    assert idx.match({"CVE-1"}, "pkg:npm/lodash@4.17.20").status == "not_affected"
    assert idx.match({"CVE-1"}, "pkg:npm/lodash@4.17.21") is None  # different version
    assert idx.match({"CVE-2"}, "pkg:npm/lodash@4.17.20") is None  # different vulnerability


def test_versionless_purl_covers_every_version() -> None:
    idx = VexIndex(parse_vex(doc(stmt(purl="pkg:npm/lodash"))))
    assert idx.match({"CVE-1"}, "pkg:npm/lodash@1.0.0") is not None
    assert idx.match({"CVE-1"}, "pkg:npm/lodash@9.9.9") is not None


def test_subcomponents_are_the_packages_not_the_product() -> None:
    s = stmt()
    s["products"] = [
        {"@id": "pkg:generic/app", "subcomponents": [{"@id": "pkg:npm/lodash@4.17.20"}]}
    ]
    idx = VexIndex(parse_vex(doc(s)))
    assert idx.match({"CVE-1"}, "pkg:npm/lodash@4.17.20") is not None
    assert idx.match({"CVE-1"}, "pkg:generic/app") is None


def test_only_not_affected_and_fixed_suppress() -> None:
    for status, expect in [
        ("not_affected", True),
        ("fixed", True),
        ("affected", False),
        ("under_investigation", False),
    ]:
        idx = VexIndex(parse_vex(doc(stmt(status=status))))
        assert (idx.match({"CVE-1"}, "pkg:npm/lodash@4.17.20") is not None) is expect, status


def test_newest_statement_wins_so_affected_can_revoke() -> None:
    old = stmt(timestamp="2026-01-01T00:00:00Z")
    new = stmt(status="affected", timestamp="2026-03-01T00:00:00Z")
    idx = VexIndex(parse_vex(doc(old, new)))
    assert idx.match({"CVE-1"}, "pkg:npm/lodash@4.17.20") is None
    # the order in the file does not matter, the timestamp does
    idx = VexIndex(parse_vex(doc(new, old)))
    assert idx.match({"CVE-1"}, "pkg:npm/lodash@4.17.20") is None


def test_equal_timestamps_fall_back_to_file_order() -> None:
    a = stmt(status="affected")
    b = stmt()
    assert VexIndex(parse_vex(doc(a, b))).match({"CVE-1"}, "pkg:npm/lodash@4.17.20")
    assert not VexIndex(parse_vex(doc(b, a))).match({"CVE-1"}, "pkg:npm/lodash@4.17.20")


def test_statement_timestamp_overrides_document_timestamp() -> None:
    s = parse_vex(doc(stmt(timestamp="2027-05-05T00:00:00+02:00"), ts="2026-01-01T00:00:00Z"))[0]
    assert s.timestamp.year == 2027


@pytest.mark.parametrize(
    "bad",
    [
        {"statements": []},  # no @context
        {"@context": "https://example.com", "statements": []},
        {"@context": CTX},  # no statements
        doc(stmt(status="maybe")),
        doc(
            {
                "vulnerability": "CVE-1",
                "products": [{"@id": "pkg:npm/a@1"}],
                "status": "not_affected",
            }
        ),
        doc({"vulnerability": "CVE-1", "products": [{"@id": "pkg:npm/a@1"}], "status": "affected"}),
        doc({"vulnerability": {}, "products": [{"@id": "pkg:npm/a@1"}], "status": "fixed"}),
        doc({"vulnerability": "CVE-1", "products": [], "status": "fixed"}),
        doc({"vulnerability": "CVE-1", "products": [{"@id": "https://x"}], "status": "fixed"}),
    ],
)
def test_invalid_documents_raise_instead_of_suppressing(bad: dict) -> None:
    with pytest.raises(VexError):
        parse_vex(bad)


def test_bare_string_vulnerability_from_older_openvex() -> None:
    s = {"vulnerability": "CVE-9", "products": [{"@id": "pkg:npm/a@1"}], "status": "fixed"}
    assert parse_vex(doc(s))[0].vulns == {"CVE-9"}


def test_load_vex_merges_files_and_reports_bad_ones(tmp_path: Path) -> None:
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(json.dumps(doc(stmt(vuln="CVE-1"))), encoding="utf-8")
    b.write_text(json.dumps(doc(stmt(vuln="CVE-2", purl="pkg:npm/x@1"))), encoding="utf-8")
    assert len(load_vex([a, b])) == 2
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(VexError, match="cannot read VEX file"):
        load_vex([bad])
    with pytest.raises(VexError, match="cannot read VEX file"):
        load_vex([tmp_path / "missing.json"])
