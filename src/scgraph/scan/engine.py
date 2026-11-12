"""Scan a lockfile graph: every alert carries its path, everything else abstains with a reason.

The lockfile becomes a ``scgraph.core.TypedGraph`` (a root node, ``direct_prod`` and
``direct_dev`` edges to the direct dependencies, ``depends_on`` edges published by the
lockfile), so exposure search is ``scgraph.core.find_paths`` and the verdict is a
``scgraph.core.Ladder``: the same engine that runs over the 82.8M-edge ecosystem graph.

Gates, in order (the first one that empties the evidence names the abstention):

  withdrawn   the advisory was withdrawn upstream
  path        no dependency path from a declared root reaches the package
  scope       reachable only through dev dependencies (malicious code is never
              exempt: install scripts run in CI and on laptops)
  vex         a supplied OpenVEX statement says not_affected or fixed (never for malware)
  severity    below the severity floor (actively exploited or malicious is never exempt)
  ignored     suppressed by an ignore entry that has not expired

Advisories that are the same issue under different ids (GHSA, PYSEC, CVE) are merged by
alias before gating, so one bug is one finding. Survivors are ranked:

  P0 malicious   P1 actively exploited (CISA KEV)   P2 critical or EPSS >= 0.1
  P3 high        P4 everything else
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from datetime import date
from pathlib import Path as FsPath

from ..core.gates import Gate, Ladder
from ..core.graph import EdgeBatch, TypedGraph
from ..core.paths import find_paths
from ..cvss import band, base_score
from ..versions import affected as _affected
from ..versions import compare
from .lockfiles import DepGraph, lockfile_project, pep503
from .reachability import symbols_of
from .sources import Signals
from .vex import VexIndex

__all__ = ["Finding", "Ignore", "Policy", "ScanResult", "load_ignores", "scan_graph"]

_LABEL_SCORE = {"CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.5, "MEDIUM": 5.5, "LOW": 2.5}
_CMP_ECO = {"PyPI": "pypi", "Maven": "maven", "crates.io": "cargo", "Go": "go", "npm": "npm"}


@dataclass(frozen=True)
class Ignore:
    id: str
    reason: str = ""
    until: date | None = None

    def active(self, today: date) -> bool:
        return self.until is None or today <= self.until


def load_ignores(path: str | FsPath) -> list[Ignore]:
    """``.scgraph-ignore``: one advisory id per line, optional ``until=YYYY-MM-DD`` and a
    ``# reason``. An expired entry stops suppressing, so ignores cannot rot silently."""
    out: list[Ignore] = []
    p = FsPath(path)
    if not p.exists():
        return out
    for n, raw in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
        body, _, reason = raw.partition("#")
        parts = body.split()
        if not parts:
            continue
        until = None
        for tok in parts[1:]:
            if tok.startswith("until="):
                try:
                    until = date.fromisoformat(tok[6:])
                except ValueError:
                    raise ValueError(
                        f"{p}:{n}: bad date {tok[6:]!r} in {tok!r}; use until=YYYY-MM-DD"
                    ) from None
        out.append(Ignore(parts[0], reason.strip(), until))
    return out


@dataclass
class Policy:
    min_severity: float = 0.0
    include_dev: bool = False
    ignores: list[Ignore] = field(default_factory=list)
    only: set[str] = field(default_factory=set)  # incident mode: these advisory ids only
    vex: VexIndex | None = None  # supplier statements that suppress findings
    parent_fix: bool = True  # plan direct-dependency bumps for transitive alerts (npm, online)
    today: date = field(default_factory=date.today)


@dataclass
class Finding:
    id: str  # display id: the MAL id, else a CVE alias, else the first OSV id
    ids: list[str]  # every OSV id merged into this finding
    aliases: list[str]
    summary: str
    package: str
    version: str
    ecosystem: str
    purl: str
    score: float | None
    severity: str
    malicious: bool
    withdrawn: bool
    kev: bool
    epss: float | None
    epss_percentile: float | None
    path: list[str] | None  # root, direct dependency, ..., the affected package
    dev_only: bool
    fixed_in: str | None
    fix: str
    alert: bool = False
    reason: str = ""  # "alert", or the gate that abstained
    detail: str = ""
    priority: str = ""
    imported: str = ""  # import-level hint: imported | not_imported | unknown | "" (not run)
    symbols: list[str] = field(default_factory=list)  # vulnerable functions the advisory names
    reachability: str = ""  # reachable | class_used | not_called | not_analyzed | "" (not run)
    symbols_source: str = ""  # "osv" (the advisory names them) | "inferred" (scgraph.symbols)
    symbol_evidence: str = ""  # for inferred symbols: the fix commit or "code search"
    reach_hops: int = 0  # >1 when reachability followed a transitive dependency path

    @property
    def depth(self) -> int:
        return len(self.path) - 1 if self.path else -1

    @property
    def direct(self) -> bool:
        return self.depth == 1

    def all_ids(self) -> set[str]:
        return {*self.ids, *self.aliases, self.id}

    def to_dict(self) -> dict:
        d = asdict(self)
        d["depth"] = self.depth
        return d


@dataclass
class ScanResult:
    path: str
    format: str
    ecosystem: str
    n_packages: int
    n_direct: int
    findings: list[Finding]
    remediation: list[dict]
    unpinned: list[str]
    source: str
    signals: dict[str, str]
    merged_duplicates: int
    seconds: float
    parent_upgrades: list[dict] = field(default_factory=list)

    @property
    def alerts(self) -> list[Finding]:
        return [f for f in self.findings if f.alert]

    @property
    def abstentions(self) -> list[Finding]:
        return [f for f in self.findings if not f.alert]

    def abstention_counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.abstentions:
            out[f.reason] = out.get(f.reason, 0) + 1
        return out

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "format": self.format,
            "ecosystem": self.ecosystem,
            "packages": self.n_packages,
            "direct": self.n_direct,
            "source": self.source,
            "signals": self.signals,
            "merged_duplicates": self.merged_duplicates,
            "seconds": round(self.seconds, 4),
            "summary": {
                "alerts": len(self.alerts),
                "abstained": self.abstention_counts(),
                "unpinned": len(self.unpinned),
            },
            "alerts": [f.to_dict() for f in self.alerts],
            "abstentions": [f.to_dict() for f in self.abstentions],
            "remediation": self.remediation,
            "parent_upgrades": self.parent_upgrades,
            "unpinned": self.unpinned,
        }


# ------------------------------------------------------------------------ helpers
def _score(recs: list[dict]) -> float | None:
    best = None
    for r in recs:
        s = base_score(r.get("severity") or [])
        if not s:
            lab = str((r.get("database_specific") or {}).get("severity", "")).upper()
            s = _LABEL_SCORE.get(lab, 0.0)
            for a in r.get("affected") or []:
                lab = str((a.get("ecosystem_specific") or {}).get("severity", "")).upper()
                s = max(s, _LABEL_SCORE.get(lab, 0.0))
        if s:
            best = max(best or 0.0, s)
    return best


def _group(recs: list[dict]) -> list[list[dict]]:
    """Union OSV records that name each other (id or alias): one issue, one finding."""
    parent = list(range(len(recs)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    owner: dict[str, int] = {}
    for i, r in enumerate(recs):
        for k in [r.get("id", ""), *(r.get("aliases") or []), *(r.get("upstream") or [])]:
            if not k:
                continue
            if k in owner:
                parent[find(i)] = find(owner[k])
            else:
                owner[k] = i
    groups: dict[int, list[dict]] = {}
    for i, r in enumerate(recs):
        groups.setdefault(find(i), []).append(r)
    return list(groups.values())


def _entries(recs: list[dict], eco: str, name: str) -> list[dict]:
    norm = (lambda n: pep503(n)) if eco == "PyPI" else (lambda n: n.lower())
    out = []
    for r in recs:
        for a in r.get("affected") or []:
            pk = a.get("package") or {}
            if pk.get("ecosystem", "").split(":")[0] == eco and norm(pk.get("name", "")) == norm(
                name
            ):
                out.append(a)
    return out


def _fix_version(entries: list[dict], version: str, eco: str) -> str | None:
    """Smallest published fixed version above ``version`` that no entry still affects."""
    ce = _CMP_ECO.get(eco, "npm")
    cands: set[str] = set()
    need_fix = False
    for a in entries:
        if not _affected(version, a, ce):
            continue
        need_fix = True
        fixed = [
            e["fixed"]
            for rng in a.get("ranges") or []
            for e in rng.get("events") or []
            if "fixed" in e and compare(e["fixed"], version, ce) > 0
        ]
        if not fixed:
            return None
        cands.update(fixed)
    if not need_fix and not cands:
        return None
    for c in sorted(cands, key=_key(ce)):
        if not any(_affected(c, a, ce) for a in entries):
            return c
    return None


def _key(ce: str):
    from functools import cmp_to_key

    return cmp_to_key(lambda a, b: compare(a, b, ce))


# --------------------------------------------------------------------------- scan
def _to_typed(dg: DepGraph) -> tuple[TypedGraph, int]:
    nodes = [(f"root:{dg.path}", "root")]
    nodes += [
        (f"pkg:{p.ecosystem}/{p.name}@{p.version}#{i}", "package") for i, p in enumerate(dg.pkgs)
    ]
    prod = sorted(i for i, s in dg.direct.items() if s == "prod")
    dev = sorted(i for i, s in dg.direct.items() if s == "dev")
    es = sorted((a, b) for a, b in dg.edges if a != b)
    g = TypedGraph.build(
        nodes,
        {
            "direct_prod": EdgeBatch([0] * len(prod), [i + 1 for i in prod], source="manifest"),
            "direct_dev": EdgeBatch([0] * len(dev), [i + 1 for i in dev], source="manifest"),
            "depends_on": EdgeBatch(
                [a + 1 for a, _ in es], [b + 1 for _, b in es], source=dg.format
            ),
        },
        meta={"adapter": "lockfile", "path": dg.path},
    )
    return g, 0


def _paths(dg: DepGraph, targets: set[int]) -> dict[int, list[int]]:
    """Package index -> shortest path of package indices from a direct dependency.
    Prod paths are preferred: a dev path is only used when no prod path exists."""
    if not targets:
        return {}
    g, root = _to_typed(dg)
    tnodes = {t + 1 for t in targets}
    out: dict[int, list[int]] = {}
    for first in ("direct_prod", "direct_dev"):
        left = tnodes - {t + 1 for t in out}
        if not left:
            break
        found, _ = find_paths(
            g,
            [root],
            [first, "depends_on"],
            left.__contains__,
            max_depth=256,
            max_paths=10**7,
        )
        for p in found:
            out.setdefault(p.terminal - 1, [n - 1 for n in p.nodes[1:]])
    return out


def _gates(policy: Policy) -> Ladder:
    def not_ignored(f: Finding, ctx: dict) -> bool:
        ids = f.all_ids()
        return not any(i.id in ids and i.active(policy.today) for i in policy.ignores)

    def not_vex_suppressed(f: Finding, ctx: dict) -> bool:
        return f.malicious or policy.vex is None or policy.vex.match(f.all_ids(), f.purl) is None

    return Ladder(
        [
            Gate("withdrawn", "advisory withdrawn upstream", lambda f, c: not f.withdrawn),
            Gate(
                "path", "no dependency path from a declared root", lambda f, c: f.path is not None
            ),
            Gate(
                "scope",
                "reachable only through dev dependencies (--include-dev to alert)",
                lambda f, c: policy.include_dev or not f.dev_only or f.malicious,
            ),
            Gate("vex", "a supplied VEX statement says not_affected or fixed", not_vex_suppressed),
            Gate(
                "severity",
                f"below the severity floor {policy.min_severity}",
                lambda f, c: (
                    f.malicious or f.kev or f.score is None or f.score >= policy.min_severity
                ),
            ),
            Gate("ignored", "suppressed by an ignore entry", not_ignored),
        ]
    )


def _priority(f: Finding) -> str:
    if f.malicious:
        return "P0"
    if f.kev:
        return "P1"
    if (f.score or 0) >= 9.0 or (f.epss or 0) >= 0.1:
        return "P2"
    if (f.score or 0) >= 7.0:
        return "P3"
    return "P4"


def scan_graph(
    dg: DepGraph,
    source,
    signals: Signals | None = None,
    policy: Policy | None = None,
    registry=None,
) -> ScanResult:
    """Scan one lockfile graph. ``registry`` is a JSON fetcher (``url -> dict | None``)
    used to plan direct-dependency bumps for transitive alerts; None skips that step."""
    t0 = time.perf_counter()
    policy = policy or Policy()
    signals = signals or Signals(enabled=False)
    hits = source.query(dg.pkgs)
    paths = _paths(dg, set(hits))
    root_label = lockfile_project(dg.path)

    raw: list[tuple[int, list[dict]]] = []
    merged = 0
    for i, recs in hits.items():
        groups = _group(recs)
        merged += len(recs) - len(groups)
        raw.extend((i, grp) for grp in groups)

    kev = signals.kev() if raw else set()
    cves = {
        a
        for _, grp in raw
        for r in grp
        for a in [r.get("id", ""), *(r.get("aliases") or [])]
        if a.startswith("CVE-")
    }
    epss = signals.epss(cves) if cves else {}

    findings: list[Finding] = []
    for i, grp in raw:
        p = dg.pkgs[i]
        ids = sorted({r["id"] for r in grp})
        aliases = sorted({a for r in grp for a in (r.get("aliases") or [])} - set(ids))
        all_ids = [*ids, *aliases]
        mal = [x for x in ids if x.startswith("MAL-")]
        cve = sorted(x for x in all_ids if x.startswith("CVE-"))
        disp = mal[0] if mal else cve[0] if cve else ids[0]
        e = max((epss[c] for c in cve if c in epss), default=None)
        entries = _entries(grp, p.ecosystem, p.name)
        fixed = None if mal else _fix_version(entries, p.version, p.ecosystem)
        if mal:
            fix = (
                f"remove {p.label}: it is a malicious release. Pin the last clean version "
                "and rotate every secret the install could read"
            )
        elif fixed:
            fix = f"upgrade {p.name} to {fixed}"
        else:
            fix = "no fixed version is published; consider replacing the package"
        idx = paths.get(i)
        score = _score(grp)
        summ = next((r.get("summary") for r in grp if r.get("summary")), "") or ""
        findings.append(
            Finding(
                id=disp,
                ids=ids,
                aliases=aliases,
                summary=summ.strip()[:300],
                package=p.name,
                version=p.version,
                ecosystem=p.ecosystem,
                purl=p.purl,
                score=score,
                severity="malicious" if mal else band(score) if score is not None else "unknown",
                malicious=bool(mal),
                withdrawn=all(r.get("withdrawn") for r in grp),
                kev=any(c in kev for c in cve),
                epss=e[0] if e else None,
                epss_percentile=e[1] if e else None,
                path=[root_label, *[dg.pkgs[k].label for k in idx]] if idx is not None else None,
                dev_only=p.dev,
                fixed_in=fixed,
                fix=fix,
                symbols=[] if mal else symbols_of(entries),
            )
        )
    if policy.only:
        findings = [f for f in findings if f.all_ids() & policy.only]

    ladder = _gates(policy)
    for f in findings:
        v = ladder.evaluate([f])
        f.alert, f.reason, f.detail = v.alert, v.reason, v.detail
        f.priority = _priority(f) if f.alert else ""
    rank = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4, "": 9}
    findings.sort(key=lambda f: (rank[f.priority], -(f.score or 0), f.depth, f.package, f.id))

    remediation = _remediation(dg, findings, hits)
    bumps: list[dict] = []
    if registry is not None and policy.parent_fix:
        from .upgrade import parent_upgrades

        bumps = parent_upgrades(dg, findings, hits, registry)
    return ScanResult(
        path=dg.path,
        format=dg.format,
        ecosystem=dg.ecosystem,
        n_packages=sum(1 for p in dg.pkgs if not p.local),
        n_direct=sum(1 for i in dg.direct if not dg.pkgs[i].local),
        findings=findings,
        remediation=remediation,
        unpinned=dg.unpinned,
        source=getattr(source, "name", type(source).__name__),
        signals=dict(signals.status),
        merged_duplicates=merged,
        seconds=time.perf_counter() - t0,
        parent_upgrades=bumps,
    )


def _remediation(dg: DepGraph, findings: list[Finding], hits: dict[int, list[dict]]) -> list[dict]:
    """One action per vulnerable package: the smallest upgrade that clears every alerting
    advisory on it, and which direct dependencies pull it in."""
    by_pkg: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        if f.alert:
            by_pkg.setdefault((f.package, f.version), []).append(f)
    idx = {(p.name, p.version): i for i, p in enumerate(dg.pkgs)}
    out = []
    for (name, ver), fs in by_pkg.items():
        i = idx[(name, ver)]
        ids = {x for f in fs for x in f.ids}
        recs = [r for r in hits.get(i, []) if r["id"] in ids]
        eco = dg.pkgs[i].ecosystem
        mal = any(f.malicious for f in fs)
        target = None if mal else _fix_version(_entries(recs, eco, name), ver, eco)
        via = sorted({f.path[1] for f in fs if f.path and len(f.path) > 1})
        out.append(
            {
                "package": name,
                "from": ver,
                "to": target,
                "action": "remove" if mal else "upgrade" if target else "replace",
                "clears": sorted(f.id for f in fs),
                "direct": any(f.direct for f in fs),
                "via": via,
                "top_priority": min(f.priority for f in fs),
            }
        )
    out.sort(key=lambda r: (r["top_priority"], -len(r["clears"]), r["package"]))  # type: ignore[arg-type]
    return out
