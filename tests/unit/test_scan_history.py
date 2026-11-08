"""Scan history in the ledger: first exposure, fix, regression, receipts and tampering."""

from __future__ import annotations

import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from scgraph.scan.engine import Policy, scan_graph
from scgraph.scan.history import (
    LedgerError,
    check_receipt,
    episodes,
    open_history,
    record_scan,
    verify,
)
from scgraph.scan.lockfiles import parse
from scgraph.scan.sources import OSVOffline, Signals

CRIT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def at(month: int, day: int = 1, sec: int = 0) -> datetime:
    return datetime(2026, month, day, 0, 0, sec, tzinfo=UTC)


@pytest.fixture
def source(tmp_path: Path) -> OSVOffline:
    rec = {
        "id": "GHSA-aaaa",
        "aliases": ["CVE-2024-0001"],
        "summary": "s",
        "severity": [{"type": "CVSS_V3", "score": CRIT}],
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "parser"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.3.0"}]}],
            }
        ],
    }
    osv = tmp_path / "osv"
    osv.mkdir()
    with zipfile.ZipFile(osv / "npm.zip", "w") as z:
        z.writestr("GHSA-aaaa.json", json.dumps(rec))
    return OSVOffline(osv)


def write_lock(path: Path, parser_version: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"parser": "1"}},
                    "node_modules/parser": {"version": parser_version},
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def scan(lock: Path, source):
    return scan_graph(parse(lock), source, Signals(enabled=False), Policy())


def test_first_exposure_fix_and_regression_are_separate_episodes(tmp_path: Path, source) -> None:
    lock = tmp_path / "proj" / "package-lock.json"
    h = open_history(tmp_path / "hist", at(1))
    root = tmp_path

    write_lock(lock, "1.2.0")  # vulnerable
    assert record_scan(h, [scan(lock, source)], root, at(1, 5)) == {"opened": 2, "closed": 0}
    assert record_scan(h, [scan(lock, source)], root, at(2)) == {"opened": 0, "closed": 0}

    write_lock(lock, "1.3.0")  # fixed
    assert record_scan(h, [scan(lock, source)], root, at(3)) == {"opened": 0, "closed": 2}

    write_lock(lock, "1.2.0")  # regressed
    assert record_scan(h, [scan(lock, source)], root, at(4)) == {"opened": 2, "closed": 0}

    for adv in ("CVE-2024-0001", "GHSA-aaaa"):  # any alias answers
        eps, _ = episodes(h, adv)
        assert [e.to_dict() for e in eps] == [
            {
                "lockfile": "proj/package-lock.json",
                "exposed_from": "2026-01-05T00:00:00+00:00",
                "exposed_until": "2026-03-01T00:00:00+00:00",
            },
            {
                "lockfile": "proj/package-lock.json",
                "exposed_from": "2026-04-01T00:00:00+00:00",
                "exposed_until": None,
            },
        ]
    assert episodes(h, "CVE-9999-0000")[0] == []  # never exposed


def test_two_lockfiles_exposed_to_the_same_advisory_are_two_episodes(
    tmp_path: Path, source
) -> None:
    a = write_lock(tmp_path / "a" / "package-lock.json", "1.2.0")
    b = write_lock(tmp_path / "b" / "package-lock.json", "1.2.0")
    h = open_history(tmp_path / "hist", at(1))
    record_scan(h, [scan(a, source), scan(b, source)], tmp_path, at(2))
    eps, _ = episodes(h, "GHSA-aaaa")
    assert [e.lockfile for e in eps] == ["a/package-lock.json", "b/package-lock.json"]


def test_an_exposure_that_opens_and_closes_in_one_second_is_not_erased(
    tmp_path: Path, source
) -> None:
    lock = tmp_path / "package-lock.json"
    h = open_history(tmp_path / "hist", at(1))
    write_lock(lock, "1.2.0")
    record_scan(h, [scan(lock, source)], tmp_path, at(2, sec=7))
    write_lock(lock, "1.3.0")
    record_scan(h, [scan(lock, source)], tmp_path, at(2, sec=7))  # the very same second
    (e,) = episodes(h, "GHSA-aaaa")[0]
    assert e.exposed_from == "2026-02-01T00:00:07+00:00"
    assert e.exposed_until == "2026-02-01T00:00:08+00:00"  # bumped, so the episode survives


def test_a_clock_that_runs_backwards_does_not_break_the_ledger(tmp_path: Path, source) -> None:
    lock = write_lock(tmp_path / "package-lock.json", "1.2.0")
    h = open_history(tmp_path / "hist", at(6))
    record_scan(h, [scan(lock, source)], tmp_path, at(6, 10))
    write_lock(lock, "1.3.0")
    record_scan(h, [scan(lock, source)], tmp_path, at(1))  # earlier than the ledger head
    (e,) = episodes(h, "GHSA-aaaa")[0]
    assert e.exposed_until is not None and e.exposed_until > e.exposed_from


def test_a_lockfile_outside_the_root_is_stored_by_name_only(tmp_path: Path, source) -> None:
    root = tmp_path / "root"
    root.mkdir()
    lock = write_lock(tmp_path / "elsewhere" / "package-lock.json", "1.2.0")
    h = open_history(tmp_path / "hist", at(1))
    record_scan(h, [scan(lock, source)], root, at(2))
    (e,) = episodes(h, "GHSA-aaaa")[0]
    assert e.lockfile == "package-lock.json" and str(tmp_path) not in e.lockfile


def test_a_receipt_verifies_and_survives_reopening_the_ledger(tmp_path: Path, source) -> None:
    lock = write_lock(tmp_path / "package-lock.json", "1.2.0")
    h = open_history(tmp_path / "hist", at(1))
    record_scan(h, [scan(lock, source)], tmp_path, at(2))
    _, receipt = episodes(h, "GHSA-aaaa")
    assert check_receipt(h, receipt)
    assert check_receipt(open_history(tmp_path / "hist"), receipt)
    assert verify(h) == 5  # 1 lockfile + 2 advisory ids as nodes, and 2 edges


def test_a_receipt_for_an_answer_that_has_since_changed_does_not_verify(
    tmp_path: Path, source
) -> None:
    lock = write_lock(tmp_path / "package-lock.json", "1.2.0")
    h = open_history(tmp_path / "hist", at(1))
    record_scan(h, [scan(lock, source)], tmp_path, at(2))
    _, receipt = episodes(h, "GHSA-aaaa")
    write_lock(lock, "1.3.0")
    record_scan(h, [scan(lock, source)], tmp_path, at(3))
    # the receipt pins the log head it was computed from: it still checks out, as-then
    assert check_receipt(h, receipt)
    forged = type(receipt)(**{**receipt.__dict__, "result_hash": "0" * 64})
    assert not check_receipt(h, forged)


def test_editing_a_past_scan_breaks_verification(tmp_path: Path, source) -> None:
    lock = write_lock(tmp_path / "package-lock.json", "1.2.0")
    h = open_history(tmp_path / "hist", at(1))
    record_scan(h, [scan(lock, source)], tmp_path, at(2))
    log = tmp_path / "hist" / "log.jsonl"
    tampered = log.read_text().replace("lockfile:package-lock.json", "lockfile:other.json")
    assert tampered != log.read_text()  # the edit really changed the log
    log.write_text(tampered)
    with pytest.raises(LedgerError):
        verify(open_history(tmp_path / "hist"))


def test_a_receipt_that_is_not_a_history_receipt_is_refused(tmp_path: Path, source) -> None:
    lock = write_lock(tmp_path / "package-lock.json", "1.2.0")
    h = open_history(tmp_path / "hist", at(1))
    record_scan(h, [scan(lock, source)], tmp_path, at(2))
    _, receipt = h.answer({"op": "something_else"}, lambda g, t: [])
    with pytest.raises(LedgerError, match="not a scgraph history receipt"):
        check_receipt(h, receipt)
