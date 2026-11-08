"""Release anomalies from a package's own registry document: no network, plain fixtures."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from scgraph.scan.anomaly import npm_release_anomalies

NOW = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)


def iso(hours_ago: float) -> str:
    return (NOW - timedelta(hours=hours_ago)).isoformat().replace("+00:00", "Z")


def vdoc(user="alice", maintainers=("alice",), attested=False, scripts=None):
    d = {
        "_npmUser": {"name": user},
        "maintainers": [{"name": m} for m in maintainers],
        "dist": {"attestations": {"url": "https://x"}} if attested else {},
    }
    if scripts:
        d["scripts"] = scripts
    return d


def packument(*releases):
    """releases: (version, hours_ago, vdoc) in any order."""
    return {
        "versions": {v: d for v, _, d in releases},
        "time": {v: iso(h) for v, h, _ in releases},
    }


def codes(doc, version, **kw):
    return [c for c, _ in npm_release_anomalies(doc, version, NOW, **kw)]


def test_a_quiet_release_by_the_same_publisher_raises_nothing() -> None:
    doc = packument(("1.0.0", 100, vdoc()), ("1.0.1", 50, vdoc()))
    assert codes(doc, "1.0.1") == []


def test_publisher_changed_names_both_accounts() -> None:
    doc = packument(("1.0.0", 100, vdoc("alice")), ("1.0.1", 50, vdoc("mallory")))
    ((code, msg),) = npm_release_anomalies(doc, "1.0.1", NOW)
    assert code == "publisher_changed" and "'mallory'" in msg and "'alice'" in msg


def test_maintainer_added_lists_only_the_new_names() -> None:
    doc = packument(
        ("1.0.0", 100, vdoc(maintainers=("alice",))),
        ("1.0.1", 50, vdoc(maintainers=("alice", "bob", "carol"))),
    )
    ((code, msg),) = npm_release_anomalies(doc, "1.0.1", NOW)
    assert code == "maintainer_added" and "bob, carol" in msg and "alice" not in msg


def test_a_removed_maintainer_is_not_an_anomaly() -> None:
    doc = packument(
        ("1.0.0", 100, vdoc(maintainers=("alice", "bob"))),
        ("1.0.1", 50, vdoc(maintainers=("alice",))),
    )
    assert codes(doc, "1.0.1") == []


def test_provenance_dropped_only_when_the_previous_release_had_it() -> None:
    dropped = packument(("1.0.0", 100, vdoc(attested=True)), ("1.0.1", 50, vdoc(attested=False)))
    assert codes(dropped, "1.0.1") == ["provenance_dropped"]
    never = packument(("1.0.0", 100, vdoc()), ("1.0.1", 50, vdoc()))
    assert codes(never, "1.0.1") == []
    kept = packument(("1.0.0", 100, vdoc(attested=True)), ("1.0.1", 50, vdoc(attested=True)))
    assert codes(kept, "1.0.1") == []


def test_install_script_added_but_not_when_it_was_already_there() -> None:
    scripts = {"postinstall": "node setup.js", "test": "jest"}
    added = packument(("1.0.0", 100, vdoc()), ("1.0.1", 50, vdoc(scripts=scripts)))
    ((code, msg),) = npm_release_anomalies(added, "1.0.1", NOW)
    assert code == "install_script_added" and "postinstall: node setup.js" in msg
    assert "jest" not in msg  # only lifecycle scripts that run at install
    had = packument(("1.0.0", 100, vdoc(scripts=scripts)), ("1.0.1", 50, vdoc(scripts=scripts)))
    assert codes(had, "1.0.1") == []


def test_backport_published_after_a_higher_stable_version() -> None:
    doc = packument(("2.0.0", 100, vdoc()), ("1.9.9", 30, vdoc()))
    assert codes(doc, "1.9.9") == ["backport_published"]
    assert codes(doc, "2.0.0") == []


def test_a_prerelease_of_the_next_major_does_not_make_a_patch_a_backport() -> None:
    doc = packument(("2.0.0-beta.1", 100, vdoc()), ("1.9.9", 30, vdoc()))
    assert codes(doc, "1.9.9") == []


def test_publish_burst_needs_five_versions_in_fifteen_minutes() -> None:
    burst = [(f"1.0.{i}", 10 - i / 60, vdoc()) for i in range(5)]  # one per minute
    assert "publish_burst" in codes(packument(*burst), "1.0.4")
    four = packument(*burst[:4])
    assert "publish_burst" not in codes(four, "1.0.3")
    spread = packument(*[(f"1.0.{i}", 10 + i, vdoc()) for i in range(5)])  # hours apart
    assert "publish_burst" not in codes(spread, "1.0.0")


def test_an_old_release_is_not_examined_at_all() -> None:
    doc = packument(("1.0.0", 900, vdoc("alice")), ("1.0.1", 800, vdoc("mallory")))
    assert codes(doc, "1.0.1") == []  # 800h is past the 14-day window
    assert codes(doc, "1.0.1", recent_hours=1000) == ["publisher_changed"]


def test_the_first_release_and_unknown_versions_raise_nothing() -> None:
    doc = packument(("1.0.0", 5, vdoc(scripts={"postinstall": "x"})))
    assert codes(doc, "1.0.0") == []  # nothing to compare with
    assert codes(doc, "9.9.9") == []


@pytest.mark.parametrize(
    "doc",
    [
        {},
        {"versions": {"1.0.0": {}}},  # no time table
        {"versions": {"1.0.0": {}}, "time": {"1.0.0": "not a date"}},
        {"versions": {"1.0.0": {}, "1.0.1": {}}, "time": {"1.0.0": iso(9), "1.0.1": iso(5)}},
    ],
)
def test_sparse_or_malformed_registry_documents_never_raise(doc: dict) -> None:
    assert isinstance(npm_release_anomalies(doc, "1.0.1", NOW), list)


def test_several_signals_can_fire_together() -> None:
    doc = packument(
        ("1.0.0", 100, vdoc("alice", ("alice",), attested=True)),
        (
            "1.0.1",
            50,
            vdoc("mallory", ("alice", "mallory"), attested=False, scripts={"install": "x"}),
        ),
    )
    assert set(codes(doc, "1.0.1")) == {
        "publisher_changed",
        "maintainer_added",
        "provenance_dropped",
        "install_script_added",
    }
