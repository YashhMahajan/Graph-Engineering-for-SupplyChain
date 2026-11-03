"""Pre-install guard: should this package be installed at all?

Built for the moment an AI coding agent (or a tired human) types ``npm install x``.
About one in five package names that code models suggest do not exist, and attackers
register the predictable ones ("slopsquatting", USENIX Security 2025). Recent worms
spread through fresh releases of real packages, caught within hours. So the questions
asked, in order of how hard they stop an install:

  block   the package does not exist in the registry (hallucinated name)
          the version is a known malicious release (OSV ``MAL-*``)
  warn    the version was published less than ``cooldown`` hours ago
          the package itself is less than 30 days old
          the name is one edit away from a popular package (typosquat)
          npm install scripts, or a PyPI version with no wheel (setup.py runs)
          deprecated or yanked
          known vulnerabilities at this version
  allow   none of the above

A registry or OSV lookup that fails is a ``warn`` with code ``unverified``: the guard
never turns "could not check" into "safe".
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime

from .lockfiles import Pkg, pep503
from .sources import default_osv, http_json

__all__ = ["ECOSYSTEMS", "Check", "check_package", "normalize_ecosystem", "parse_spec"]

ECOSYSTEMS = {
    "npm": "npm",
    "node": "npm",
    "pypi": "PyPI",
    "pip": "PyPI",
    "python": "PyPI",
    "cargo": "crates.io",
    "crates": "crates.io",
    "crates.io": "crates.io",
    "rust": "crates.io",
    "go": "Go",
    "golang": "Go",
    "gem": "RubyGems",
    "rubygems": "RubyGems",
    "composer": "Packagist",
    "packagist": "Packagist",
}

# Names attackers imitate. A short list on purpose: the check is "one edit from one of
# these", and every name here is a fact about the ecosystem, not a model's guess.
POPULAR = {
    "npm": """react react-dom vue angular express lodash axios moment chalk commander debug
    request async underscore uuid dotenv webpack babel-core typescript eslint prettier jest
    mocha next nuxt vite rollup esbuild jquery bluebird yargs minimist glob rimraf mkdirp
    semver colors cross-env nodemon socket.io mongoose sequelize redis pg mysql ws
    body-parser cors helmet jsonwebtoken bcrypt passport classnames styled-components
    tailwindcss postcss autoprefixer sass node-fetch cheerio puppeteer playwright zod
    rxjs immer redux react-redux react-router react-router-dom date-fns dayjs inquirer ora
    fs-extra execa got superagent qs ms graphql apollo-server electron three d3 chart.js
    lodash.merge event-stream ua-parser-js coa rc node-ipc eslint-scope""",
    "PyPI": """requests numpy pandas scipy matplotlib django flask fastapi pydantic sqlalchemy
    boto3 botocore urllib3 setuptools wheel pip six python-dateutil pyyaml certifi idna
    charset-normalizer cryptography pytest tox black isort mypy ruff jinja2 click attrs
    packaging typing-extensions pillow scikit-learn tensorflow torch keras transformers
    openai anthropic langchain httpx aiohttp celery redis psycopg2 psycopg2-binary pymongo
    beautifulsoup4 lxml selenium scrapy tqdm rich colorama pyjwt paramiko fabric docker
    kubernetes google-cloud-storage azure-core gunicorn uvicorn starlette werkzeug jsonschema
    protobuf grpcio networkx sympy opencv-python seaborn plotly dash streamlit gradio
    huggingface-hub tokenizers datasets accelerate xgboost lightgbm pyspark pyarrow polars
    duckdb nltk spacy gensim""",
    "crates.io": """serde serde_json tokio rand regex clap anyhow thiserror log env_logger
    reqwest hyper futures chrono lazy_static once_cell syn quote proc-macro2 itertools
    bytes tracing axum actix-web diesel sqlx uuid base64 libc bitflags cfg-if""",
}
_POP = {eco: set(v.split()) for eco, v in POPULAR.items()}


def normalize_ecosystem(eco: str) -> str:
    e = ECOSYSTEMS.get(eco.lower())
    if e is None:
        raise ValueError(f"unknown ecosystem {eco!r}; one of: {', '.join(sorted(set(ECOSYSTEMS)))}")
    return e


def parse_spec(spec: str, eco: str) -> tuple[str, str | None]:
    """``name@1.2.3`` / ``name==1.2.3`` / ``mod@v1.2`` -> (name, version or None)."""
    spec = spec.strip()
    if eco == "PyPI":
        m = re.match(
            r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(?:(===?)\s*([^\s;,]+))?", spec
        )
        if not m:
            return spec, None
        return pep503(m.group(1)), m.group(3)
    at = spec.find("@", 1)
    if at > 0:
        ver = spec[at + 1 :].lstrip("v=^~") or None
        if ver in ("latest", "*"):
            ver = None
        return spec[:at], ver if ver and re.match(r"^\d", ver) else None
    return spec, None


@dataclass
class Check:
    ecosystem: str
    name: str
    version: str | None
    verdict: str = "allow"  # allow | warn | block
    reasons: list[dict] = field(default_factory=list)
    facts: dict = field(default_factory=dict)

    def add(self, level: str, code: str, message: str) -> None:
        self.reasons.append({"level": level, "code": code, "message": message})
        order = {"allow": 0, "warn": 1, "block": 2}
        if order[level] > order[self.verdict]:
            self.verdict = level

    def to_dict(self) -> dict:
        return asdict(self)

    def line(self) -> str:
        head = f"{self.verdict.upper():5}  {self.ecosystem}/{self.name}" + (
            f"@{self.version}" if self.version else ""
        )
        return "\n".join([head, *[f"       [{r['level']}] {r['message']}" for r in self.reasons]])


def _edits1(a: str, b: str) -> bool:
    """Damerau-Levenshtein distance exactly 1 (one insert, delete, substitute or swap)."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        return (
            len(diff) == 2
            and diff[1] == diff[0] + 1
            and a[diff[0]] == b[diff[1]]
            and a[diff[1]] == b[diff[0]]
        )
    s, t = (a, b) if len(a) < len(b) else (b, a)
    i = 0
    while i < len(s) and s[i] == t[i]:
        i += 1
    return s[i:] == t[i + 1 :]


def typosquat_of(name: str, eco: str) -> str | None:
    pop = _POP.get(eco, set())
    n = name.lower()
    if n in pop or len(n) < 4:
        return None
    squash = re.sub(r"[-_.]", "", n)
    for p in sorted(pop):
        if len(p) < 4:
            continue
        if _edits1(n, p) or (squash == re.sub(r"[-_.]", "", p)):
            return p
        parts = re.split(r"[-_.]", n)
        if len(parts) == 2 and f"{parts[1]}-{parts[0]}" == p:
            return p
    return None


def _ts(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def _age_hours(t: datetime | None, now: datetime) -> float | None:
    return None if t is None else (now - t).total_seconds() / 3600


def _registry(eco: str, name: str, version: str | None, fetch) -> dict:
    """Facts from the package registry. ``exists`` is True, False or None (unknown)."""
    q = urllib.parse.quote
    if eco == "npm":
        doc = fetch(f"https://registry.npmjs.org/{name.replace('/', '%2F')}")
        if doc is None:
            return {"exists": False}
        times = doc.get("time") or {}
        ver = version or (doc.get("dist-tags") or {}).get("latest")
        vdoc = (doc.get("versions") or {}).get(ver or "", {})
        scripts = {
            k: v
            for k, v in (vdoc.get("scripts") or {}).items()
            if k in ("preinstall", "install", "postinstall")
        }
        return {
            "exists": True,
            "version": ver,
            "version_exists": bool(vdoc) if ver else None,
            "created": times.get("created"),
            "published": times.get(ver or ""),
            "install_scripts": scripts,
            "deprecated": vdoc.get("deprecated"),
            "maintainers": len(doc.get("maintainers") or []),
            "versions": len(doc.get("versions") or {}),
        }
    if eco == "PyPI":
        doc = fetch(f"https://pypi.org/pypi/{q(name)}/json")
        if doc is None:
            return {"exists": False}
        rel = doc.get("releases") or {}
        ver = version or (doc.get("info") or {}).get("version")
        files = rel.get(ver or "", [])
        uploads = sorted(
            f.get("upload_time_iso_8601", "")
            for fs in rel.values()
            for f in fs
            if f.get("upload_time_iso_8601")
        )
        return {
            "exists": True,
            "version": ver,
            "version_exists": ver in rel if ver else None,
            "created": uploads[0] if uploads else None,
            "published": min((f.get("upload_time_iso_8601", "") for f in files), default=None),
            "sdist_only": bool(files)
            and not any(f.get("packagetype") == "bdist_wheel" for f in files),
            "yanked": bool(files) and all(f.get("yanked") for f in files),
            "versions": len(rel),
        }
    if eco == "crates.io":
        doc = fetch(f"https://crates.io/api/v1/crates/{q(name)}")
        if doc is None:
            return {"exists": False}
        crate = doc.get("crate") or {}
        ver = version or crate.get("max_stable_version") or crate.get("newest_version")
        vrow: dict = next((v for v in doc.get("versions") or [] if v.get("num") == ver), {})
        return {
            "exists": True,
            "version": ver,
            "version_exists": bool(vrow) if ver else None,
            "created": crate.get("created_at"),
            "published": vrow.get("created_at"),
            "yanked": bool(vrow.get("yanked")),
            "versions": len(doc.get("versions") or []),
        }
    if eco == "Go":
        doc = fetch(f"https://proxy.golang.org/{q(name.lower())}/@latest")
        if doc is None:
            return {"exists": False}
        return {
            "exists": True,
            "version": version or str(doc.get("Version", "")).lstrip("v"),
            "published": doc.get("Time"),
        }
    if eco == "RubyGems":
        doc = fetch(f"https://rubygems.org/api/v1/gems/{q(name)}.json")
        if doc is None:
            return {"exists": False}
        return {
            "exists": True,
            "version": version or doc.get("version"),
            "published": doc.get("version_created_at"),
        }
    if eco == "Packagist":
        doc = fetch(f"https://repo.packagist.org/p2/{q(name.lower(), safe='/')}.json")
        if doc is None:
            return {"exists": False}
        vs = (doc.get("packages") or {}).get(name.lower()) or []
        ver = version or (str(vs[0].get("version", "")).lstrip("v") if vs else None)
        row: dict = next((v for v in vs if str(v.get("version", "")).lstrip("v") == ver), {})
        return {
            "exists": True,
            "version": ver,
            "version_exists": bool(row) if ver else None,
            "published": row.get("time"),
        }
    return {"exists": None}


def check_package(
    ecosystem: str,
    name: str,
    version: str | None = None,
    *,
    osv=None,
    fetch=http_json,
    cooldown_hours: float = 48.0,
    now: datetime | None = None,
) -> Check:
    eco = normalize_ecosystem(ecosystem)
    if eco == "PyPI":
        name = pep503(name)
    now = now or datetime.now(UTC)
    c = Check(eco, name, version)

    try:
        reg = _registry(eco, name, version, fetch)
    except Exception as e:  # network, proxy, malformed registry answer
        reg = {"exists": None, "error": f"{type(e).__name__}: {e}"}
    c.facts["registry"] = reg
    if reg.get("exists") is False:
        c.add(
            "block",
            "nonexistent",
            f"{name} does not exist in the {eco} registry: a hallucinated or "
            "not-yet-registered name, exactly what slopsquatting attacks claim",
        )
        sq = typosquat_of(name, eco)
        if sq:
            c.add("block", "typosquat", f"did you mean {sq}?")
        return c
    if reg.get("exists") is None:
        c.add(
            "warn",
            "unverified",
            "registry could not be checked" + (f" ({reg['error']})" if reg.get("error") else ""),
        )
    ver = version or reg.get("version")
    c.version = ver
    if version and reg.get("version_exists") is False:
        c.add(
            "block",
            "no_such_version",
            f"{name}@{version} is not in the registry (unpublished, or never released)",
        )

    sq = typosquat_of(name, eco)
    if sq:
        c.add(
            "warn",
            "typosquat",
            f"one edit away from the popular package {sq!r}: check the spelling",
        )
    pub_age = _age_hours(_ts(reg.get("published")), now)
    if pub_age is not None and pub_age < cooldown_hours:
        c.add(
            "warn",
            "fresh_release",
            f"{name}@{ver} was published {pub_age:.0f}h ago; compromised releases "
            f"are usually caught within hours, so wait out a {cooldown_hours:.0f}h cooldown "
            "or pin the previous version",
        )
    created_age = _age_hours(_ts(reg.get("created")), now)
    if created_age is not None and created_age < 30 * 24:
        c.add(
            "warn",
            "new_package",
            f"the package was first published {created_age / 24:.0f} days ago",
        )
    if reg.get("install_scripts"):
        c.add(
            "warn",
            "install_scripts",
            "runs code at install: "
            + ", ".join(f"{k}: {v[:60]}" for k, v in reg["install_scripts"].items()),
        )
    if reg.get("sdist_only"):
        c.add(
            "warn",
            "sdist_only",
            f"{name}@{ver} ships no wheel, so its setup.py executes at install",
        )
    if reg.get("deprecated"):
        c.add("warn", "deprecated", f"deprecated: {str(reg['deprecated'])[:120]}")
    if reg.get("yanked"):
        c.add("warn", "yanked", f"{name}@{ver} is yanked")

    if ver:
        try:
            recs = (osv or default_osv()).query([Pkg(name, ver, eco)]).get(0, [])
        except Exception as e:
            recs = []
            c.add("warn", "unverified", f"advisory lookup failed ({type(e).__name__})")
        mal = [r["id"] for r in recs if r.get("id", "").startswith("MAL-")]
        vulns = [r["id"] for r in recs if not r.get("id", "").startswith("MAL-")]
        c.facts["advisories"] = [r["id"] for r in recs]
        if mal:
            c.add(
                "block",
                "malicious",
                f"{name}@{ver} is a known malicious release ({', '.join(mal)})",
            )
        if vulns:
            c.add(
                "warn",
                "vulnerable",
                f"{len(vulns)} known vulnerabilit{'y' if len(vulns) == 1 else 'ies'} "
                f"at {ver}: {', '.join(vulns[:5])}",
            )
    return c
