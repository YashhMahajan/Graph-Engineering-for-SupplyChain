"""scgraph diff: judge a change on what it introduced, not on inherited debt."""

from __future__ import annotations

import json
import os
import subprocess
import zipfile
from pathlib import Path

import pytest

from scgraph.scan.diff import DiffError, diff_lockfile, read_at_ref, resolve_ref
from scgraph.scan.engine import Policy
from scgraph.scan.sources import OSVOffline, Signals

CRIT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def _rec(id_, name, fixed=None, versions=None, aliases=()):
    aff = {"package": {"ecosystem": "npm", "name": name}}
    if versions:
        aff["versions"] = versions
    else:
        aff["ranges"] = [
            {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": fixed}]},
        ]
    return {
        "id": id_,
        "aliases": list(aliases),
        "summary": id_,
        "severity": [{"type": "CVSS_V3", "score": CRIT}],
        "affected": [aff],
    }


RECORDS = [
    _rec("GHSA-aaaa", "parser", fixed="1.3.0", aliases=["CVE-2024-0001"]),
    _rec("MAL-2025-1", "chalk", versions=["5.6.1"]),
    _rec("GHSA-leg", "legacy", fixed="2.0.0"),
]


def lock(deps, pkgs, dev=None):
    root = {"dependencies": deps}
    if dev:
        root["devDependencies"] = dev
    return json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {"": root, **{f"node_modules/{n}": v for n, v in pkgs.items()}},
        }
    )


def git(cwd: Path, *args: str) -> str:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.com",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.com",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
    }
    r = subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


@pytest.fixture
def source(tmp_path: Path) -> OSVOffline:
    osv = tmp_path / "osv"
    osv.mkdir()
    with zipfile.ZipFile(osv / "npm.zip", "w") as z:
        for r in RECORDS:
            z.writestr(f"{r['id']}.json", json.dumps(r))
    return OSVOffline(osv)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    (r / "package-lock.json").write_text(
        lock(
            {"web": "1", "legacy": "1"},
            {
                "web": {"version": "1.0.0", "dependencies": {"parser": "1"}},
                "parser": {"version": "1.2.0"},
                "legacy": {"version": "1.0.0"},
            },
        ),
        encoding="utf-8",
    )
    git(r, "add", "-A")
    git(r, "commit", "-q", "-m", "base")
    return r


def run(repo: Path, source, ref="HEAD", file="package-lock.json"):
    return diff_lockfile(
        repo / file, resolve_ref(ref, repo), source, Signals(enabled=False), Policy(), cwd=repo
    )


def test_resolve_ref_returns_a_hash_and_refuses_options_and_unknown_refs(repo: Path) -> None:
    assert len(resolve_ref("HEAD", repo)) == 40
    for bad in ("", "-p", "--output=x", "no-such-branch"):
        with pytest.raises(DiffError):
            resolve_ref(bad, repo)


def test_resolve_ref_outside_a_repository_is_a_diff_error(tmp_path: Path) -> None:
    with pytest.raises(DiffError):
        resolve_ref("HEAD", tmp_path)


def test_read_at_ref_gives_the_base_text_or_none_for_a_new_file(repo: Path) -> None:
    commit = resolve_ref("HEAD", repo)
    (repo / "package-lock.json").write_text("changed", encoding="utf-8")
    assert '"parser"' in read_at_ref(commit, repo / "package-lock.json", repo)
    assert read_at_ref(commit, repo / "other" / "package-lock.json", repo) is None


def test_diff_reports_only_what_the_change_introduced(repo: Path, source) -> None:
    (repo / "package-lock.json").write_text(
        lock(
            {"web": "1", "legacy": "1", "chalk": "5"},
            {
                "web": {"version": "1.0.0", "dependencies": {"parser": "1"}},
                "parser": {"version": "1.3.0"},  # bumped: GHSA-aaaa is resolved
                "legacy": {"version": "1.0.0"},  # untouched: inherited debt
                "chalk": {"version": "5.6.1"},  # new and malicious
            },
        ),
        encoding="utf-8",
    )
    d = run(repo, source)
    assert [f.id for f in d.new_alerts] == ["MAL-2025-1"]
    assert [f.id for f in d.resolved] == ["CVE-2024-0001"]  # merged GHSA/CVE: one finding
    assert d.persisting == 1  # legacy: present before, so not blamed on this change
    assert d.added == ["chalk@5.6.1"]
    assert d.changed == [("parser", "1.2.0", "1.3.0")]
    assert d.removed == []
    assert d.to_dict()["summary"] == {"new_alerts": 1, "resolved": 1, "persisting": 1}


def test_an_unchanged_lockfile_has_an_empty_delta(repo: Path, source) -> None:
    d = run(repo, source)
    assert (d.new_alerts, d.resolved, d.added, d.removed, d.changed) == ([], [], [], [], [])
    assert d.persisting == 2 and d.base_exists


def test_a_lockfile_that_is_new_in_the_change_is_entirely_new(repo: Path, source) -> None:
    sub = repo / "svc"
    sub.mkdir()
    (sub / "package-lock.json").write_text(
        lock({"legacy": "1"}, {"legacy": {"version": "1.0.0"}}), encoding="utf-8"
    )
    d = run(repo, source, file="svc/package-lock.json")
    assert not d.base_exists
    assert [f.id for f in d.new_alerts] == ["GHSA-leg"] and d.persisting == 0


def test_moving_a_dependency_from_dev_to_prod_makes_its_alert_new(repo: Path, source) -> None:
    (repo / "package-lock.json").write_text(
        lock({}, {"legacy": {"version": "1.0.0", "dev": True}}, dev={"legacy": "1"}),
        encoding="utf-8",
    )
    git(repo, "commit", "-q", "-am", "make legacy dev-only")
    (repo / "package-lock.json").write_text(
        lock({"legacy": "1"}, {"legacy": {"version": "1.0.0"}}), encoding="utf-8"
    )
    d = run(repo, source)  # base: abstained (dev scope), head: alert
    assert [f.id for f in d.new_alerts] == ["GHSA-leg"]


def test_a_broken_lockfile_at_the_base_is_a_diff_error_not_a_crash(repo: Path, source) -> None:
    (repo / "package-lock.json").write_text("{not json", encoding="utf-8")
    git(repo, "commit", "-q", "-am", "break it")
    (repo / "package-lock.json").write_text(lock({}, {}), encoding="utf-8")
    with pytest.raises(DiffError, match="cannot parse"):
        run(repo, source)
