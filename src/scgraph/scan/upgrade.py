"""Fix transitive vulnerabilities by bumping the direct dependency that pulls them in.

A transitive package cannot be upgraded directly: the direct dependency's declared range
decides which version gets installed. So for each direct dependency ``D`` whose children
are vulnerable, walk ``D``'s published versions upward and take the first one whose
declared range for every vulnerable child resolves (highest satisfying version, the npm
rule, via ``scgraph.resolve``) to a version no alerting advisory affects. A child that
the new ``D`` no longer depends on counts as cleared.

This is the "upgrade express, not body-parser" answer that lockfile bots miss when the
parent pins the child. It needs registry metadata, so it runs online and only for npm,
where one registry document carries every version's dependencies. When no version of
``D`` clears everything, the best partial bump is returned with what it leaves behind,
and the remaining children get an ``overrides`` suggestion.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from ..resolve import resolve
from ..versions import affected as _affected
from ..versions import compare, sort_versions

__all__ = ["parent_upgrades"]

_PRE = re.compile(r"-|[a-zA-Z]")


def _stable(v: str) -> bool:
    return not _PRE.search(v)


def _major(v: str) -> str:
    head = v.split(".")[0]
    return v.split(".")[1] if head == "0" and "." in v else head


def parent_upgrades(
    dg,
    findings,
    hits: dict[int, list[dict]],
    fetch: Callable[[str], dict | None],
) -> list[dict]:
    if dg.ecosystem != "npm":
        return []
    idx = {(p.name, p.version): i for i, p in enumerate(dg.pkgs)}
    # direct dependency label -> child name -> (child version, alerting advisory ids)
    plan: dict[str, dict[str, tuple[str, set[str], set[str]]]] = {}
    for f in findings:
        if not f.alert or f.malicious or not f.path or len(f.path) != 3:
            continue
        d = f.path[1]
        cur = plan.setdefault(d, {}).setdefault(f.package, (f.version, set(), set()))
        cur[1].update(f.ids)  # OSV ids, to find the records
        cur[2].add(f.id)  # display ids, one per finding
    out = []
    docs: dict[str, dict | None] = {}

    def doc(name: str) -> dict | None:
        if name not in docs:
            try:
                docs[name] = fetch(f"https://registry.npmjs.org/{name.replace('/', '%2F')}")
            except Exception:
                docs[name] = None
        return docs[name]

    for dlabel, kids in sorted(plan.items()):
        dname, _, dver = dlabel.rpartition("@")
        ddoc = doc(dname)
        if not ddoc:
            continue
        entries: dict[str, list[dict]] = {}
        kid_versions: dict[str, list[str]] = {}
        for k, (kv, ids, _) in kids.items():
            recs = [r for r in hits.get(idx.get((k, kv), -1), []) if r["id"] in ids]
            entries[k] = [
                a
                for r in recs
                for a in r.get("affected") or []
                if (a.get("package") or {}).get("name") == k
            ]
            kd = doc(k)
            kid_versions[k] = list((kd or {}).get("versions") or {})
        cands = [
            v
            for v in sort_versions(list((ddoc.get("versions") or {}).keys()), "npm")
            if _stable(v)
            and compare(v, dver, "npm") > 0
            and not ddoc["versions"][v].get("deprecated")
        ]
        best: tuple[str, list[str]] | None = None
        for v in cands:
            deps = {
                **(ddoc["versions"][v].get("optionalDependencies") or {}),
                **(ddoc["versions"][v].get("dependencies") or {}),
            }
            cleared = []
            for k in kids:
                rng = deps.get(k)
                if rng is None:
                    cleared.append(k)
                    continue
                got = resolve(rng, kid_versions[k], "npm") if kid_versions[k] else None
                if got and not any(_affected(got, a, "npm") for a in entries[k]):
                    cleared.append(k)
            if best is None or len(cleared) > len(best[1]):
                best = (v, cleared)
            if len(cleared) == len(kids):
                break
        if not best or not best[1]:
            continue
        v, cleared = best
        out.append(
            {
                "direct": dname,
                "from": dver,
                "to": v,
                "major": _major(v) != _major(dver),
                "clears_packages": sorted(cleared),
                "clears": sorted({i for k in cleared for i in kids[k][2]}),
                "remaining": sorted(set(kids) - set(cleared)),
            }
        )
    out.sort(key=lambda r: (-len(r["clears"]), str(r["direct"])))  # type: ignore[arg-type]
    return out
