"""Does this release behave differently from the one before it?

The 2025-2026 npm worms (Shai-Hulud and its successors) shipped malicious versions of real
packages, some with *valid* Sigstore provenance, because the attacker ran the build inside
the maintainers' own CI. Provenance proves where a package was built, not who asked for the
build, so these checks compare a release with its predecessor using only fields the npm
registry already returns for the package (no extra request):

  publisher_changed     published by a different account than the previous release
  maintainer_added      the maintainer list gained a name since the previous release
  provenance_dropped    the previous release had a provenance attestation and this one has none
  install_script_added  this release has an install script and the previous one had none
  backport_published    published after a higher version already existed (a patch on an old
                        line that still has users, which attackers use)
  publish_burst         five or more versions of the package within fifteen minutes

Only a *recent* release is examined (default 14 days). A release that has survived for
months is not interesting because of who published it. Each signal is a warning with the
evidence in the message, never a block: all of them have innocent causes, and the guard
prints the cause so a person can judge.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ..versions import compare

__all__ = ["BURST_MINUTES", "BURST_VERSIONS", "RECENT_HOURS", "npm_release_anomalies"]

RECENT_HOURS = 14 * 24
BURST_MINUTES = 15
BURST_VERSIONS = 5
_INSTALL = ("preinstall", "install", "postinstall")


def _when(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        t = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=UTC)


def _publisher(vdoc: dict) -> str | None:
    name = (vdoc.get("_npmUser") or {}).get("name")
    return name if isinstance(name, str) and name else None


def _maintainers(vdoc: dict) -> set[str] | None:
    ms = vdoc.get("maintainers")
    if not isinstance(ms, list):
        return None
    return {m["name"] for m in ms if isinstance(m, dict) and isinstance(m.get("name"), str)}


def _has_provenance(vdoc: dict) -> bool:
    return bool((vdoc.get("dist") or {}).get("attestations"))


def _install_scripts(vdoc: dict) -> dict[str, str]:
    scripts = vdoc.get("scripts") or {}
    return {k: str(scripts[k]) for k in _INSTALL if k in scripts}


def _timeline(doc: dict) -> list[tuple[datetime, str]]:
    times = doc.get("time") or {}
    out = []
    for v in doc.get("versions") or {}:
        t = _when(times.get(v))
        if t:
            out.append((t, v))
    return sorted(out)


def npm_release_anomalies(
    doc: dict, version: str, now: datetime, recent_hours: float = RECENT_HOURS
) -> list[tuple[str, str]]:
    """``(code, message)`` pairs for how ``version`` differs from the release before it.
    Empty when the release is old, unknown, or the first one."""
    timeline = _timeline(doc)
    pos = next((i for i, (_, v) in enumerate(timeline) if v == version), None)
    if pos is None:
        return []
    published = timeline[pos][0]
    if now - published > timedelta(hours=recent_hours):
        return []
    versions = doc["versions"]
    cur = versions[version]
    out: list[tuple[str, str]] = []

    if pos > 0:
        prev_v = timeline[pos - 1][1]
        prev = versions[prev_v]
        a, b = _publisher(cur), _publisher(prev)
        if a and b and a != b:
            out.append(
                (
                    "publisher_changed",
                    f"published by {a!r}, but {prev_v} was published by {b!r}",
                )
            )
        ma, mb = _maintainers(cur), _maintainers(prev)
        if ma is not None and mb is not None and ma - mb:
            out.append(
                (
                    "maintainer_added",
                    f"maintainer(s) {', '.join(sorted(ma - mb))} were added since {prev_v}",
                )
            )
        if _has_provenance(prev) and not _has_provenance(cur):
            out.append(
                (
                    "provenance_dropped",
                    f"{prev_v} had a provenance attestation and {version} has none: "
                    "it may have been published from outside the CI that normally builds it",
                )
            )
        now_scripts, was_scripts = _install_scripts(cur), _install_scripts(prev)
        if now_scripts and not was_scripts:
            shown = ", ".join(f"{k}: {v[:60]}" for k, v in now_scripts.items())
            out.append(
                (
                    "install_script_added",
                    f"adds an install script that {prev_v} did not have ({shown})",
                )
            )

    higher = None
    if _stable(version):  # a prerelease of the next major is routinely published first
        higher = next(
            (v for _, v in timeline[:pos] if _stable(v) and _safe_compare(v, version) > 0), None
        )
    if higher:
        out.append(
            (
                "backport_published",
                f"{version} was published after the higher version {higher}: attackers patch "
                "old lines that still have users, so confirm it is a real backport",
            )
        )

    window = timedelta(minutes=BURST_MINUTES)
    burst = sum(1 for t, _ in timeline if abs(t - published) <= window)
    if burst >= BURST_VERSIONS:
        out.append(
            (
                "publish_burst",
                f"{burst} versions were published within {BURST_MINUTES} minutes, "
                "the pattern of a worm republishing a package",
            )
        )
    return out


def _stable(version: str) -> bool:
    return "-" not in version.split("+", 1)[0]


def _safe_compare(a: str, b: str) -> int:
    try:
        return compare(a, b, "npm")
    except Exception:  # an unparseable version string must not break the guard
        return 0
