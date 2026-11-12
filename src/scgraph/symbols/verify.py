"""The verifier: a symbol is recorded only if released source supports it (no model).

verified            present in the last affected release, and in the first fixed release
                    it was removed, its body changed, or a function it calls changed
present_only        present in the affected release; the fixed release could not be read
not_in_affected     the affected release has no such function (a wrong guess, or a path
                    that never shipped): abstain
unchanged_in_fix    present in both and nothing it calls changed: abstain
source_unavailable  the affected release could not be read: abstain
"""

from __future__ import annotations

from dataclasses import dataclass

from .source import Release

__all__ = ["ACCEPT", "Verdict", "release_diff", "verify"]

ACCEPT = frozenset({"verified", "present_only"})


@dataclass
class Verdict:
    status: str
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status in ACCEPT


def release_diff(affected: Release, fixed: Release) -> set[tuple[str, str]]:
    """(module, qualname) of functions removed or changed between two releases."""
    after = {(m, f.qualname): f.body_hash for m, _, f in fixed.functions()}
    return {
        (m, f.qualname)
        for m, _, f in affected.functions()
        if after.get((m, f.qualname)) != f.body_hash
    }


def verify(affected: Release | None, fixed: Release | None, module: str, qualname: str) -> Verdict:
    if affected is None:
        return Verdict("source_unavailable", "the affected release could not be downloaded")
    fa = affected.find(module, qualname)
    if fa is None:
        return Verdict("not_in_affected", f"no {qualname} in {affected.package} {affected.version}")
    if fixed is None:
        return Verdict(
            "present_only", f"in {affected.package} {affected.version}; fixed release unreadable"
        )
    ff = fixed.find(module, qualname)
    if ff is None:
        return Verdict("verified", f"removed in {fixed.version}")
    if ff.body_hash != fa.body_hash:
        return Verdict("verified", f"changed in {fixed.version}")
    changed = {q.rsplit(".", 1)[-1] for _, q in release_diff(affected, fixed)}
    hit = sorted(fa.calls & changed)
    if hit:
        return Verdict("verified", f"calls {hit[0]}, which changed in {fixed.version}")
    return Verdict("unchanged_in_fix", f"identical in {fixed.version} and calls nothing changed")
