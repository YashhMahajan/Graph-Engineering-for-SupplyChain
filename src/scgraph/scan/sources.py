"""Where advisories and exploit signals come from.

``OSVApi``      the live OSV API: ``/v1/querybatch`` then ``/v1/vulns/{id}``, with records
                cached on disk keyed by ``id`` and ``modified``, so a re-scan only fetches
                what changed upstream.
``OSVOffline``  the per-ecosystem OSV ``all.zip`` dumps (``scgraph scan --offline DIR``),
                matched locally with ``scgraph.versions.affected``: the same range
                semantics the ecosystem-scale graph is validated with.
Set ``SCGRAPH_OSV_DIR`` to make every entry point (scan, check, hook, MCP) use the dumps.

``Signals``     CISA KEV (actively exploited) and FIRST EPSS (exploit probability), each
                cached for a day. A signal that cannot be fetched is reported as
                unavailable, never silently treated as "not exploited".

Malicious packages need no extra feed: OSV carries the OpenSSF malicious-packages
dataset as ``MAL-*`` records, so a malicious release arrives as an advisory.
"""

from __future__ import annotations

import contextlib
import gzip
import json
import os
import time
import urllib.error
import urllib.request
import zipfile
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .. import __version__
from ..versions import affected as _affected
from .lockfiles import Pkg, pep503

__all__ = ["OSVApi", "OSVOffline", "Signals", "cache_dir", "default_osv", "http_json"]

UA = f"scgraph/{__version__} (+https://github.com/YashhMahajan/Graph-Engineering-for-SupplyChain)"
OSV_API = os.environ.get("SCGRAPH_OSV_URL", "https://api.osv.dev")
KEV_URLS = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
)
EPSS_API = "https://api.first.org/data/v1/epss"
DAY = 86_400

# OSV ecosystem name -> the file name ``scgraph.acquire.fetch_osv`` saves it under
_ZIP_NAME = {
    "npm": "npm",
    "PyPI": "pypi",
    "Maven": "maven",
    "crates.io": "cargo",
    "Go": "go",
    "RubyGems": "rubygems",
    "Packagist": "packagist",
    "NuGet": "nuget",
}
_CMP_ECO = {"PyPI": "pypi", "Maven": "maven", "crates.io": "cargo", "Go": "go", "npm": "npm"}


def cache_dir() -> Path:
    base = os.environ.get("SCGRAPH_CACHE") or os.environ.get("XDG_CACHE_HOME")
    d = Path(base) / "scgraph" if base else Path.home() / ".cache" / "scgraph"
    return d


def http_json(url: str, body: dict | None = None, timeout: float = 30, tries: int = 3):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"User-Agent": UA, "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    last: Exception | None = None
    for i in range(tries):
        try:
            req = urllib.request.Request(url, data=data, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
                if r.headers.get("Content-Encoding") == "gzip" or url.endswith(".gz"):
                    raw = gzip.decompress(raw)
                return json.loads(raw)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            last = e
            if e.code < 500 and e.code != 429:
                break
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            last = e
        time.sleep(0.5 * 2**i)
    assert last is not None
    raise last


def _norm(eco: str, name: str) -> str:
    return pep503(name) if eco == "PyPI" else name.lower() if eco == "Packagist" else name


class OSVApi:
    """The live OSV API with an on-disk record cache."""

    name = "osv-api"

    def __init__(self, url: str = OSV_API, cache: Path | None = None, workers: int = 8):
        self.url = url.rstrip("/")
        self.cache = (cache or cache_dir()) / "osv"
        self.workers = workers

    def query(self, pkgs: list[Pkg]) -> dict[int, list[dict]]:
        """Package index -> full OSV records affecting that exact version."""
        targets = [(i, p) for i, p in enumerate(pkgs) if not p.local and p.version]
        hits: dict[int, list[tuple[str, str]]] = {}
        for lo in range(0, len(targets), 1000):
            chunk = targets[lo : lo + 1000]
            queries = [
                {"package": {"name": p.name, "ecosystem": p.ecosystem}, "version": p.version}
                for _, p in chunk
            ]
            pending = list(range(len(chunk)))
            while pending:
                res = http_json(
                    f"{self.url}/v1/querybatch", {"queries": [queries[k] for k in pending]}
                )
                nxt = []
                for k, r in zip(pending, (res or {}).get("results", [])):
                    for v in r.get("vulns") or []:
                        hits.setdefault(chunk[k][0], []).append((v["id"], v.get("modified", "")))
                    if r.get("next_page_token"):
                        queries[k] = {**queries[k], "page_token": r["next_page_token"]}
                        nxt.append(k)
                pending = nxt
        ids = {vid: mod for vs in hits.values() for vid, mod in vs}
        with ThreadPoolExecutor(self.workers) as ex:
            recs = dict(zip(ids, ex.map(lambda kv: self._record(*kv), ids.items())))
        return {i: [r for v, _ in vs if (r := recs.get(v))] for i, vs in hits.items()}

    def _record(self, vid: str, modified: str) -> dict | None:
        f = self.cache / f"{vid}.json"
        if f.exists():
            try:
                rec = json.loads(f.read_text(encoding="utf-8"))
                if not modified or rec.get("modified") == modified:
                    return rec
            except ValueError:
                pass
        rec = http_json(f"{self.url}/v1/vulns/{vid}")
        if rec:
            self.cache.mkdir(parents=True, exist_ok=True)
            f.write_text(json.dumps(rec), encoding="utf-8")
        return rec

    def get(self, vid: str) -> dict | None:
        return self._record(vid, "")


class OSVOffline:
    """OSV ``all.zip`` dumps on disk, matched locally. Reads ``<dir>/<eco>.zip`` (the
    layout ``scgraph.acquire.fetch_osv`` writes) or ``<dir>/<OSV ecosystem>/all.zip``."""

    name = "osv-offline"

    def __init__(self, directory: str | Path):
        self.dir = Path(directory)
        self._index: dict[str, dict[str, list[str]]] = {}
        self._zips: dict[str, zipfile.ZipFile] = {}

    def _zip(self, eco: str) -> Path | None:
        for p in (self.dir / f"{_ZIP_NAME.get(eco, eco)}.zip", self.dir / eco / "all.zip"):
            if p.exists():
                return p
        return None

    def _load(self, eco: str) -> dict[str, list[str]]:
        """Package name -> zip members that mention it. Built once per dump and saved next
        to it as JSON (keyed by the dump's size and mtime), so later scans read only the
        records they need instead of parsing every record in the dump."""
        if eco in self._index:
            return self._index[eco]
        zp = self._zip(eco)
        if zp is None:
            raise FileNotFoundError(
                f"no OSV dump for {eco} in {self.dir}; fetch it with "
                f"`scgraph fetch-osv --dir {self.dir} {_ZIP_NAME.get(eco, eco)}`"
            )
        st = zp.stat()
        stamp = f"{st.st_size}:{int(st.st_mtime)}"
        ixf = zp.with_name(zp.name + ".index.json")
        idx: dict[str, list[str]] | None = None
        if ixf.exists():
            try:
                doc = json.loads(ixf.read_text(encoding="utf-8"))
                idx = doc["names"] if doc.get("stamp") == stamp else None
            except (ValueError, KeyError):
                idx = None
        z = self._zips.setdefault(eco, zipfile.ZipFile(zp))
        if idx is None:
            idx = {}
            for n in z.namelist():
                if not n.endswith(".json"):
                    continue
                try:
                    rec = json.loads(z.read(n))
                except ValueError:
                    continue
                for a in rec.get("affected") or []:
                    pk = a.get("package") or {}
                    if pk.get("ecosystem", "").split(":")[0] == eco:
                        lst = idx.setdefault(_norm(eco, pk.get("name", "")), [])
                        if not lst or lst[-1] != n:
                            lst.append(n)
            with contextlib.suppress(OSError):
                ixf.write_text(json.dumps({"stamp": stamp, "names": idx}), encoding="utf-8")
        self._index[eco] = idx
        return idx

    def query(self, pkgs: list[Pkg]) -> dict[int, list[dict]]:
        out: dict[int, list[dict]] = {}
        cache: dict[tuple[str, str], dict] = {}
        for i, p in enumerate(pkgs):
            if p.local or not p.version:
                continue
            key = _norm(p.ecosystem, p.name)
            members = self._load(p.ecosystem).get(key, [])
            z = self._zips[p.ecosystem]
            for m in dict.fromkeys(members):
                rec = cache.get((p.ecosystem, m))
                if rec is None:
                    rec = cache[(p.ecosystem, m)] = json.loads(z.read(m))
                for a in rec.get("affected") or []:
                    pk = a.get("package") or {}
                    if pk.get("ecosystem", "").split(":")[0] != p.ecosystem:
                        continue
                    if _norm(p.ecosystem, pk.get("name", "")) != key:
                        continue
                    if _affected(p.version, a, _CMP_ECO.get(p.ecosystem, "npm")):
                        out.setdefault(i, []).append(rec)
                        break
        return out

    def get(self, vid: str) -> dict | None:
        for eco in list(_ZIP_NAME):
            zp = self._zip(eco)
            if zp is None:
                continue
            z = self._zips.setdefault(eco, zipfile.ZipFile(zp))
            try:
                return json.loads(z.read(f"{vid}.json"))
            except KeyError:
                continue
        return None


def default_osv(offline: str | Path | None = None):
    """``OSVOffline`` when a dump directory is given or ``SCGRAPH_OSV_DIR`` is set (air-gapped
    CI, or a network that blocks api.osv.dev), else the live API."""
    d = offline or os.environ.get("SCGRAPH_OSV_DIR")
    return OSVOffline(d) if d else OSVApi()


def fetch_osv_dumps(ecosystems: Iterable[str], dest: str | Path) -> dict[str, int]:
    """Download OSV ``all.zip`` for each ecosystem (scgraph or OSV names)."""
    from ..acquire import fetch_osv

    rev = {v: k for k, v in _ZIP_NAME.items()}
    names = [e if e in rev else _ZIP_NAME.get(e, e.lower()) for e in ecosystems]
    return fetch_osv(names, str(dest))


class Signals:
    """CISA KEV and FIRST EPSS, cached for a day. ``status`` records what was available."""

    def __init__(self, cache: Path | None = None, enabled: bool = True):
        self.cache = (cache or cache_dir()) / "signals"
        self.enabled = enabled
        self.status: dict[str, str] = {}
        self._kev: set[str] | None = None
        self._epss: dict[str, tuple[float, float]] = {}

    def _cached(self, name: str, ttl: int = DAY):
        f = self.cache / name
        if f.exists() and time.time() - f.stat().st_mtime < ttl:
            try:
                return json.loads(f.read_text(encoding="utf-8"))
            except ValueError:
                return None
        return None

    def _store(self, name: str, obj) -> None:
        self.cache.mkdir(parents=True, exist_ok=True)
        (self.cache / name).write_text(json.dumps(obj), encoding="utf-8")

    def kev(self) -> set[str]:
        if self._kev is not None:
            return self._kev
        if not self.enabled:
            self.status["kev"] = "disabled"
            self._kev = set()
            return self._kev
        ids = self._cached("kev.json")
        if ids is None:
            for url in KEV_URLS:
                try:
                    doc = http_json(url, timeout=30, tries=2)
                    ids = sorted({v["cveID"] for v in (doc or {}).get("vulnerabilities", [])})
                    if ids:
                        self._store("kev.json", ids)
                        break
                except Exception:
                    continue
        if ids:
            self.status["kev"] = f"ok ({len(ids)} CVEs)"
            self._kev = set(ids)
        else:
            self.status["kev"] = "unavailable"
            self._kev = set()
        return self._kev

    def epss(self, cves: Iterable[str]) -> dict[str, tuple[float, float]]:
        """CVE -> (probability of exploitation in 30 days, percentile)."""
        want = sorted({c for c in cves if c.startswith("CVE-")} - set(self._epss))
        if not self.enabled:
            self.status["epss"] = "disabled"
            return self._epss
        cached = self._cached("epss.json") or {}
        missing = [c for c in want if c not in cached]
        ok = True
        for lo in range(0, len(missing), 100):
            batch = missing[lo : lo + 100]
            try:
                doc = http_json(f"{EPSS_API}?cve={','.join(batch)}", timeout=30, tries=2)
                for row in (doc or {}).get("data", []):
                    cached[row["cve"]] = [float(row["epss"]), float(row.get("percentile", 0))]
                for c in batch:
                    cached.setdefault(c, None)
            except Exception:
                ok = False
                break
        if missing and ok:
            self._store("epss.json", cached)
        for c in want:
            if cached.get(c):
                self._epss[c] = (cached[c][0], cached[c][1])
        if want or "epss" not in self.status:
            self.status["epss"] = "ok" if ok else "unavailable"
        return self._epss
