"""What did this change introduce? Compare a lockfile at a git ref with the working tree.

``scgraph diff --base main`` scans both versions of each lockfile and reports only the
difference: alerts the change adds, alerts it resolves, and the package changes behind
them. An alert that was already present at the base is *not* reported, so a pull request
is judged on what it did, not on the debt it inherited.

Comparison rules:

* alerts are compared with alerts; a finding that was abstained at the base and alerts now
  (for example it moved from a dev to a prod path) is new
* two findings are the same when they name the same package version and the same advisory;
  both sides are scanned against the same advisory data, so merged GHSA/CVE/PYSEC ids give
  one stable display id
* a lockfile that did not exist at the base is entirely new
* a lockfile deleted by the change is not reported (only files in the working tree are scanned)

Git is called with an argument list, never a shell, and a ref that looks like an option is
refused.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from . import lockfiles
from .engine import Finding, Policy, ScanResult, scan_graph
from .lockfiles import DepGraph
from .sources import Signals

__all__ = ["Delta", "DiffError", "compute_delta", "diff_lockfile", "read_at_ref", "resolve_ref"]


class DiffError(ValueError):
    """The ref is unknown, git is unavailable, or a version of a lockfile cannot be read."""


def _git(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["git", *args], cwd=cwd, capture_output=True, check=False, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise DiffError(f"cannot run git: {e}") from e


def resolve_ref(ref: str, cwd: Path) -> str:
    """The commit a ref names, as a full hash. Refuses anything that could be an option."""
    if not ref or ref.startswith("-"):
        raise DiffError(f"not a valid git ref: {ref!r}")
    r = _git(["rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"], cwd)
    if r.returncode != 0:
        raise DiffError(f"unknown git ref {ref!r} (is this a git repository, and is it fetched?)")
    return r.stdout.decode().strip()


def read_at_ref(commit: str, path: Path, cwd: Path) -> str | None:
    """The file's text at ``commit``, or None when the file did not exist there."""
    top = _git(["rev-parse", "--show-toplevel"], cwd)
    if top.returncode != 0:
        raise DiffError("not inside a git repository")
    try:
        rel = path.resolve().relative_to(Path(top.stdout.decode().strip()).resolve()).as_posix()
    except ValueError as e:
        raise DiffError(f"{path} is outside the git repository") from e
    spec = f"{commit}:{rel}"
    if _git(["cat-file", "-e", spec], cwd).returncode != 0:
        return None
    r = _git(["show", spec], cwd)
    if r.returncode != 0:
        raise DiffError(f"cannot read {rel} at {commit[:10]}: {r.stderr.decode().strip()}")
    return r.stdout.decode("utf-8", errors="replace")


@dataclass
class Delta:
    path: str
    base_exists: bool
    new_alerts: list[Finding] = field(default_factory=list)
    resolved: list[Finding] = field(default_factory=list)
    persisting: int = 0
    added: list[str] = field(default_factory=list)  # "name@version", name not present at base
    removed: list[str] = field(default_factory=list)
    changed: list[tuple[str, str, str]] = field(default_factory=list)  # name, before, after

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "base_exists": self.base_exists,
            "summary": {
                "new_alerts": len(self.new_alerts),
                "resolved": len(self.resolved),
                "persisting": self.persisting,
            },
            "packages": {
                "added": self.added,
                "removed": self.removed,
                "changed": [{"name": n, "from": a, "to": b} for n, a, b in self.changed],
            },
            "new_alerts": [f.to_dict() for f in self.new_alerts],
            "resolved": [f.to_dict() for f in self.resolved],
        }


def _key(f: Finding) -> tuple[str, str]:
    return f.purl, f.id


def _split(alerts: list[Finding], others: list[Finding]) -> tuple[list[Finding], int]:
    """(alerts with no counterpart in ``others``, how many have one)."""
    seen = {_key(o) for o in others}
    only = [a for a in alerts if _key(a) not in seen]
    return only, len(alerts) - len(only)


def _versions(dg: DepGraph | None) -> dict[tuple[str, str], set[str]]:
    out: dict[tuple[str, str], set[str]] = {}
    for p in dg.pkgs if dg else []:
        if not p.local:
            out.setdefault((p.ecosystem, p.name), set()).add(p.version)
    return out


def _labels(key: tuple[str, str], versions: set[str]) -> list[str]:
    return [f"{key[1]}@{v}" for v in sorted(versions)]


def compute_delta(
    path: str,
    base_dg: DepGraph | None,
    base: ScanResult | None,
    head_dg: DepGraph,
    head: ScanResult,
) -> Delta:
    base_alerts = base.alerts if base else []
    new, kept = _split(head.alerts, base_alerts)
    resolved, _ = _split(base_alerts, head.alerts)
    d = Delta(path, base is not None, new, resolved, kept)
    before, after = _versions(base_dg), _versions(head_dg)
    for key in sorted(after.keys() - before.keys()):
        d.added += _labels(key, after[key])
    for key in sorted(before.keys() - after.keys()):
        d.removed += _labels(key, before[key])
    for key in sorted(before.keys() & after.keys()):
        if before[key] != after[key]:
            d.changed.append(
                (key[1], ", ".join(sorted(before[key])), ", ".join(sorted(after[key])))
            )
    return d


def diff_lockfile(
    file: Path,
    commit: str,
    source,
    signals: Signals,
    policy: Policy,
    cwd: Path | None = None,
) -> Delta:
    """Scan ``file`` at ``commit`` and in the working tree, and return the difference.

    Both versions are parsed from text, so a lockfile format is read the same way on both
    sides. Registry lookups are skipped: a diff does not plan direct-dependency bumps."""
    cwd = cwd or file.resolve().parent
    head_text = file.read_text(encoding="utf-8", errors="replace")
    base_text = read_at_ref(commit, file, cwd)
    try:
        head_dg = lockfiles.parse(file, content=head_text)
    except Exception as e:
        raise DiffError(f"cannot parse {file}: {type(e).__name__}: {e}") from e
    head = scan_graph(head_dg, source, signals, policy)
    if base_text is None:
        return compute_delta(str(file), None, None, head_dg, head)
    try:
        base_dg = lockfiles.parse(file, content=base_text)
    except Exception as e:
        raise DiffError(f"cannot parse {file} at {commit[:10]}: {type(e).__name__}: {e}") from e
    base = scan_graph(base_dg, source, signals, policy)
    return compute_delta(str(file), base_dg, base, head_dg, head)
