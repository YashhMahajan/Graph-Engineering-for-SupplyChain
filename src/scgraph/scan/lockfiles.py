"""Lockfiles to dependency graphs, with no resolver and no network.

A lockfile already records the resolved tree, so every edge here is a field somebody
published: the same zero-model principle as the ecosystem graph. Each parser returns a
``DepGraph``: the packages, the edges between them, and the root's direct dependencies
tagged ``prod`` or ``dev``. A package is ``dev`` when no path from a ``prod`` direct
dependency reaches it, so a dev-only finding is a property of the graph, not a guess.

Supported (detected by file name):

    package-lock.json, npm-shrinkwrap.json   npm      v1 nested tree, v2/v3 flat packages
    yarn.lock                                npm      classic v1 and Berry
    requirements*.txt                        PyPI     pinned ``==`` lines; -r is followed
    Pipfile.lock                             PyPI
    poetry.lock                              PyPI     with pyproject.toml for direct deps
    uv.lock                                  PyPI
    Cargo.lock                               crates.io
    go.mod                                   Go       flat: go.mod has no edges
    Gemfile.lock                             RubyGems
    composer.lock                            Packagist

Ecosystem names are OSV's, so a ``Pkg`` can be queried as is.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

__all__ = [
    "LOCKFILE_NAMES",
    "DepGraph",
    "Pkg",
    "find_lockfiles",
    "is_lockfile",
    "lockfile_kind",
    "lockfile_project",
    "parse",
]


@dataclass
class Pkg:
    name: str
    version: str
    ecosystem: str
    local: bool = False  # a workspace member or the project itself: not a registry package
    dev_hint: bool = False  # the lockfile's own dev flag, used only when roots are unknown
    dev: bool = False  # computed: unreachable from every prod direct dependency

    @property
    def label(self) -> str:
        return f"{self.name}@{self.version}"

    @property
    def purl(self) -> str:
        typ = {
            "npm": "npm",
            "PyPI": "pypi",
            "crates.io": "cargo",
            "Go": "golang",
            "RubyGems": "gem",
            "Packagist": "composer",
        }.get(self.ecosystem, self.ecosystem.lower())
        name = self.name.replace("@", "%40") if typ == "npm" else self.name
        return f"pkg:{typ}/{name}@{self.version}"


@dataclass
class DepGraph:
    path: str
    format: str
    ecosystem: str
    pkgs: list[Pkg] = field(default_factory=list)
    edges: set[tuple[int, int]] = field(default_factory=set)
    direct: dict[int, str] = field(default_factory=dict)  # pkg index -> "prod" | "dev"
    unpinned: list[str] = field(default_factory=list)  # requirements we cannot pin
    _ix: dict[tuple[str, ...], int] = field(default_factory=dict, repr=False)

    def add(self, name: str, version: str, ecosystem: str | None = None, **kw) -> int:
        """Add a package, or return the index of the one already there. ``ecosystem`` is only
        for graphs that mix several (an SBOM); the rest take the graph's own."""
        eco = ecosystem or self.ecosystem
        k = (name, version) if eco == self.ecosystem else (eco, name, version)
        i = self._ix.get(k)
        if i is None:
            i = len(self.pkgs)
            self._ix[k] = i
            self.pkgs.append(Pkg(name, version, eco, **kw))
        else:  # a package seen as prod anywhere is not a dev package
            p = self.pkgs[i]
            p.dev_hint = p.dev_hint and kw.get("dev_hint", False)
            p.local = p.local or kw.get("local", False)
        return i

    def add_direct(self, i: int, scope: str) -> None:
        if self.direct.get(i) != "prod":
            self.direct[i] = scope

    def children(self) -> list[list[int]]:
        out: list[list[int]] = [[] for _ in self.pkgs]
        for a, b in sorted(self.edges):
            if a != b:
                out[a].append(b)
        return out

    def finalize(self) -> DepGraph:
        """Fill in roots when the lockfile does not name them, then compute ``dev``."""
        if not self.direct and self.pkgs:
            indeg = [0] * len(self.pkgs)
            for a, b in self.edges:
                if a != b:
                    indeg[b] += 1
            for i, p in enumerate(self.pkgs):
                if indeg[i] == 0 or p.local:
                    self.direct[i] = "dev" if p.dev_hint else "prod"
        # local packages (workspace members) are expanded through, never reported
        kids = self.children()
        prod = _reach(kids, [i for i, s in self.direct.items() if s == "prod"])
        for i, p in enumerate(self.pkgs):
            p.dev = i not in prod
        return self


def _reach(kids: list[list[int]], start: list[int]) -> set[int]:
    seen = set(start)
    q = deque(start)
    while q:
        u = q.popleft()
        for v in kids[u]:
            if v not in seen:
                seen.add(v)
                q.append(v)
    return seen


def pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


# ------------------------------------------------------------------------------- npm
def _npm_name_from_key(key: str) -> str:
    i = key.rfind("node_modules/")
    return key[i + len("node_modules/") :] if i >= 0 else key


def _parse_package_lock(path: Path, data: dict) -> DepGraph:
    g = DepGraph(str(path), "package-lock.json", "npm")
    if "packages" in data:  # lockfileVersion 2 and 3
        pk: dict[str, dict] = data["packages"]

        def target(key: str) -> str:
            e = pk.get(key, {})
            return e["resolved"] if e.get("link") and e.get("resolved") in pk else key

        def lookup(base: str, dep: str) -> str | None:
            while True:
                cand = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
                if cand in pk:
                    return target(cand)
                if not base:
                    return None
                j = base.rfind("/node_modules/")
                base = base[:j] if j >= 0 else ""

        idx: dict[str, int] = {}
        for key, e in pk.items():
            if key == "" or e.get("link"):
                continue
            name = e.get("name") or _npm_name_from_key(key)
            local = not key.startswith("node_modules/") and "/node_modules/" not in key
            idx[key] = g.add(
                name, str(e.get("version", "")), local=local, dev_hint=bool(e.get("dev"))
            )

        def deps_of(e: dict, with_dev: bool) -> list[tuple[str, str]]:
            out = [(d, "prod") for d in (e.get("dependencies") or {})]
            out += [(d, "prod") for d in (e.get("optionalDependencies") or {})]
            out += [(d, "prod") for d in (e.get("peerDependencies") or {})]
            if with_dev:
                out += [(d, "dev") for d in (e.get("devDependencies") or {})]
            return out

        root = pk.get("", {})
        for d, scope in deps_of(root, True):
            t = lookup("", d)
            if t in idx:
                g.add_direct(idx[t], scope)
        for key in idx:  # workspace members are roots of their own
            e = pk[key]
            if g.pkgs[idx[key]].local:
                g.add_direct(idx[key], "prod")
                for d, scope in deps_of(e, True):
                    t = lookup(key, d)
                    if t in idx:
                        if scope == "dev":  # a dev root, not a prod edge
                            g.add_direct(idx[t], "dev")
                        else:
                            g.edges.add((idx[key], idx[t]))
                continue
            for d, _ in deps_of(e, False):
                t = lookup(key, d)
                if t in idx:
                    g.edges.add((idx[key], idx[t]))
        return g

    # lockfileVersion 1: a nested tree with ``requires``
    def walk(deps: dict, scopes: list[dict[str, int]]) -> None:
        here: dict[str, int] = {}
        for name, e in deps.items():
            here[name] = g.add(name, str(e.get("version", "")), dev_hint=bool(e.get("dev")))
        chain = [*scopes, here]
        for e in deps.values():
            if e.get("dependencies"):
                walk(e["dependencies"], chain)
        for name, e in deps.items():
            inner = [*chain]
            if e.get("dependencies"):
                inner.append(
                    {n: g._ix[(n, str(x.get("version", "")))] for n, x in e["dependencies"].items()}
                )
            for req in e.get("requires") or {}:
                for sc in reversed(inner):
                    if req in sc:
                        g.edges.add((here[name], sc[req]))
                        break

    top = data.get("dependencies") or {}
    walk(top, [])
    pj = _read_json(path.parent / "package.json")
    if pj:
        for scope, keys in (
            ("prod", ("dependencies", "optionalDependencies")),
            ("dev", ("devDependencies",)),
        ):
            for k in keys:
                for d in pj.get(k) or {}:
                    if d in top:
                        g.add_direct(g._ix[(d, str(top[d].get("version", "")))], scope)
    return g


_YARN_KEY = re.compile(r'^"?(.+?)"?:\s*$')


def _yarn_split_spec(spec: str) -> tuple[str, str]:
    spec = spec.strip().strip('"')
    at = spec.find("@", 1)
    if at < 0:
        return spec, ""
    name, rng = spec[:at], spec[at + 1 :]
    return name, rng.removeprefix("npm:")


def _parse_yarn(path: Path, text: str) -> DepGraph:
    g = DepGraph(str(path), "yarn.lock", "npm")
    entries: list[tuple[list[tuple[str, str]], dict]] = []
    cur: dict | None = None
    section = ""
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        if indent == 0:
            m = _YARN_KEY.match(line)
            if not m or line.startswith("__metadata"):
                cur = None
                continue
            specs = [_yarn_split_spec(s) for s in m.group(1).split(", ")]
            cur = {"version": "", "deps": []}
            entries.append((specs, cur))
            section = ""
            continue
        if cur is None:
            continue
        if indent == 2:
            section = ""
            if line.endswith(":") and " " not in line.rstrip(":"):
                section = line.rstrip(":")
            elif line.startswith("version"):
                cur["version"] = line.split(None, 1)[1].lstrip(":").strip().strip('"')
            continue
        if indent >= 4 and section in ("dependencies", "optionalDependencies"):
            if line.startswith('"'):
                end = line.index('"', 1)
                dname, rest = line[1:end], line[end + 1 :]
            else:
                dname, _, rest = line.partition(" ")
            dname = dname.rstrip(":")
            cur["deps"].append(
                (dname, rest.strip().lstrip(":").strip().strip('"').removeprefix("npm:"))
            )

    by_spec: dict[tuple[str, str], int] = {}
    for specs, e in entries:
        name = specs[0][0]
        local = any(r.startswith("workspace:") for _, r in specs)
        i = g.add(name, e["version"], local=local)
        for s in specs:
            by_spec[s] = i
    for specs, e in entries:
        i = by_spec[specs[0]]
        for d in e["deps"]:
            j = by_spec.get(d)
            if j is not None:
                g.edges.add((i, j))
    pj = _read_json(path.parent / "package.json")
    if pj:
        for scope, keys in (
            ("prod", ("dependencies", "optionalDependencies")),
            ("dev", ("devDependencies",)),
        ):
            for k in keys:
                for d, rng in (pj.get(k) or {}).items():
                    j = by_spec.get((d, str(rng).removeprefix("npm:")))
                    if j is not None:
                        g.add_direct(j, scope)
    return g


# ------------------------------------------------------------------------------ PyPI
_REQ = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(===|==)\s*([^\s;#,]+)")


def _parse_requirements(
    path: Path, seen: set[Path] | None = None, g: DepGraph | None = None
) -> DepGraph:
    g = g or DepGraph(str(path), "requirements.txt", "PyPI")
    seen = seen or set()
    if path.resolve() in seen or not path.exists():
        return g
    seen.add(path.resolve())
    text = path.read_text(encoding="utf-8", errors="replace").replace("\\\n", " ")
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r ", "--requirement ", "-c ", "--constraint ")):
            ref = line.split(None, 1)[1].strip()
            _parse_requirements(path.parent / ref, seen, g)
            continue
        if line.startswith("-"):
            continue
        m = _REQ.match(line)
        if m:
            g.add_direct(g.add(pep503(m.group(1)), m.group(3)), "prod")
        elif (
            re.match(r"^[A-Za-z0-9]", line) and "://" not in line and "/" not in line.split(";")[0]
        ):
            g.unpinned.append(line)
    return g


def _parse_pipfile_lock(path: Path, data: dict) -> DepGraph:
    g = DepGraph(str(path), "Pipfile.lock", "PyPI")
    for section, scope in (("default", "prod"), ("develop", "dev")):
        for name, e in (data.get(section) or {}).items():
            v = str(e.get("version", "")).lstrip("=")
            if v:
                g.add_direct(g.add(pep503(name), v, dev_hint=scope == "dev"), scope)
            else:
                g.unpinned.append(name)
    return g


def _pyproject_direct(path: Path) -> tuple[set[str], set[str]]:
    pp = path.parent / "pyproject.toml"
    if not pp.exists():
        return set(), set()
    try:
        d = tomllib.loads(pp.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError):
        return set(), set()

    def names(reqs) -> set[str]:
        out = set()
        for r in reqs or []:
            m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", str(r))
            if m:
                out.add(pep503(m.group(1)))
        return out

    prod = names(d.get("project", {}).get("dependencies"))
    for extra in (d.get("project", {}).get("optional-dependencies") or {}).values():
        prod |= names(extra)
    dev: set[str] = set()
    for grp in (d.get("dependency-groups") or {}).values():
        dev |= names(g for g in grp if isinstance(g, str))
    poetry = d.get("tool", {}).get("poetry", {})
    prod |= {pep503(k) for k in poetry.get("dependencies", {}) if k.lower() != "python"}
    dev |= {pep503(k) for k in poetry.get("dev-dependencies", {})}
    for grp in (poetry.get("group") or {}).values():
        dev |= {pep503(k) for k in grp.get("dependencies", {})}
    dev |= names(d.get("tool", {}).get("uv", {}).get("dev-dependencies"))
    return prod, dev - prod


def _parse_poetry_lock(path: Path, data: dict) -> DepGraph:
    g = DepGraph(str(path), "poetry.lock", "PyPI")
    pkgs = data.get("package") or []
    by_name: dict[str, int] = {}
    for p in pkgs:
        n = pep503(p["name"])
        by_name.setdefault(n, g.add(n, str(p["version"]), dev_hint=p.get("category") == "dev"))
    for p in pkgs:
        i = by_name[pep503(p["name"])]
        for d in p.get("dependencies") or {}:
            j = by_name.get(pep503(d))
            if j is not None:
                g.edges.add((i, j))
    prod, dev = _pyproject_direct(path)
    for names, scope in ((prod, "prod"), (dev, "dev")):
        for n in names:
            if n in by_name:
                g.add_direct(by_name[n], scope)
    return g


def _parse_uv_lock(path: Path, data: dict) -> DepGraph:
    g = DepGraph(str(path), "uv.lock", "PyPI")
    pkgs = data.get("package") or []
    by_name: dict[str, list[int]] = {}
    for p in pkgs:
        src = p.get("source") or {}
        local = any(k in src for k in ("editable", "virtual", "directory", "path"))
        n = pep503(p["name"])
        by_name.setdefault(n, []).append(g.add(n, str(p.get("version", "0")), local=local))

    def find(d: dict) -> int | None:
        cands = by_name.get(pep503(d["name"]), [])
        if len(cands) > 1 and "version" in d:
            cands = [c for c in cands if g.pkgs[c].version == d["version"]] or cands
        return cands[0] if cands else None

    for p in pkgs:
        i = find(p)
        assert i is not None
        local = g.pkgs[i].local
        groups: list[tuple[list, str]] = [(p.get("dependencies") or [], "prod")]
        groups += [(v, "prod") for v in (p.get("optional-dependencies") or {}).values()]
        groups += [(v, "dev") for v in (p.get("dev-dependencies") or {}).values()]
        for deps, scope in groups:
            for d in deps:
                j = find(d)
                if j is None:
                    continue
                if local:  # a dev group is a root of its own, not a prod edge
                    g.add_direct(j, scope)
                    if scope == "dev":
                        continue
                g.edges.add((i, j))
        if local:
            g.add_direct(i, "prod")
    return g


# ------------------------------------------------------------------------- the rest
def _parse_cargo_lock(path: Path, data: dict) -> DepGraph:
    g = DepGraph(str(path), "Cargo.lock", "crates.io")
    pkgs = data.get("package") or []
    by_name: dict[str, list[int]] = {}
    for p in pkgs:
        i = g.add(p["name"], str(p["version"]), local="source" not in p)
        by_name.setdefault(p["name"], []).append(i)
    for p in pkgs:
        i = g._ix[(p["name"], str(p["version"]))]
        for d in p.get("dependencies") or []:
            parts = d.split()
            cands = by_name.get(parts[0], [])
            if len(parts) > 1:
                cands = [c for c in cands if g.pkgs[c].version == parts[1]] or cands
            if cands:
                g.edges.add((i, cands[0]))
    for i, p in enumerate(g.pkgs):
        if p.local:
            g.add_direct(i, "prod")
    return g


def _parse_go_mod(path: Path, text: str) -> DepGraph:
    g = DepGraph(str(path), "go.mod", "Go")
    block = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if raw.strip().startswith("require ("):
            block = True
            continue
        if block and line == ")":
            block = False
            continue
        body = (
            line[len("require ") :]
            if line.startswith("require ") and "(" not in line
            else line
            if block
            else ""
        )
        parts = body.split()
        if len(parts) >= 2:
            g.add_direct(g.add(parts[0], parts[1].removeprefix("v")), "prod")
    return g


def _parse_gemfile_lock(path: Path, text: str) -> DepGraph:
    g = DepGraph(str(path), "Gemfile.lock", "RubyGems")
    section, cur = "", None
    pending: list[tuple[int, str]] = []
    by_name: dict[str, int] = {}
    roots: list[str] = []
    spec = re.compile(r"^([^\s(]+)(?: \(([^)]*)\))?")
    for raw in text.splitlines():
        if raw and not raw.startswith(" "):
            section = raw.strip()
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        m = spec.match(raw.strip())
        if not m:
            continue
        if section in ("GEM", "GIT", "PATH") and indent == 4 and m.group(2):
            ver = (
                m.group(2).split("-")[0]
                if re.search(r"-(x86|arm|java|universal|aarch)", m.group(2))
                else m.group(2)
            )
            if m.group(1) not in by_name:
                by_name[m.group(1)] = g.add(m.group(1), ver, local=section != "GEM")
            cur = by_name[m.group(1)]
        elif section in ("GEM", "GIT", "PATH") and indent == 6 and cur is not None:
            pending.append((cur, m.group(1)))
        elif section == "DEPENDENCIES" and indent == 2:
            roots.append(m.group(1).rstrip("!"))
    for i, d in pending:
        if d in by_name:
            g.edges.add((i, by_name[d]))
    for r in roots:
        if r in by_name:
            g.add_direct(by_name[r], "prod")
    return g


def _parse_composer_lock(path: Path, data: dict) -> DepGraph:
    g = DepGraph(str(path), "composer.lock", "Packagist")
    by_name: dict[str, int] = {}
    for section, dev in (("packages", False), ("packages-dev", True)):
        for p in data.get(section) or []:
            v = str(p.get("version", "")).removeprefix("v")
            by_name[p["name"].lower()] = g.add(p["name"].lower(), v, dev_hint=dev)
    for section in ("packages", "packages-dev"):
        for p in data.get(section) or []:
            i = by_name[p["name"].lower()]
            for d in p.get("require") or {}:
                j = by_name.get(d.lower())
                if j is not None:
                    g.edges.add((i, j))
    cj = _read_json(path.parent / "composer.json")
    if cj:
        for key, scope in (("require", "prod"), ("require-dev", "dev")):
            for d in cj.get(key) or {}:
                if d.lower() in by_name:
                    g.add_direct(by_name[d.lower()], scope)
    return g


# ------------------------------------------------------------------------- dispatch
def _read_json(p: Path) -> dict | None:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


LOCKFILE_NAMES = (
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "Pipfile.lock",
    "poetry.lock",
    "uv.lock",
    "Cargo.lock",
    "go.mod",
    "Gemfile.lock",
    "composer.lock",
)
_SKIP_DIRS = {
    "node_modules",
    ".git",
    ".venv",
    "venv",
    "vendor",
    "target",
    "__pycache__",
    ".tox",
    "dist",
}


def lockfile_kind(name: str) -> str | None:
    """The canonical lockfile name for ``name``, or None. A prefixed name such as
    ``api.uv.lock`` or ``web.package-lock.json`` counts too, so a repository can keep
    several lockfiles side by side (and sample lockfiles do not trigger other scanners)."""
    if name in LOCKFILE_NAMES:
        return name
    if name.startswith("requirements") and name.endswith(".txt"):
        return "requirements.txt"
    for k in LOCKFILE_NAMES:
        if name.endswith("." + k):
            return k
    if name.endswith(".requirements.txt"):
        return "requirements.txt"
    return None


def lockfile_project(path: str | Path) -> str:
    """A short project name for the root of the dependency path."""
    p = Path(path)
    kind = lockfile_kind(p.name)
    if kind and p.name != kind and p.name.endswith("." + kind):
        return p.name[: -len(kind) - 1]
    return p.resolve().parent.name or p.name


def is_lockfile(p: Path) -> bool:
    return lockfile_kind(p.name) is not None


def find_lockfiles(root: Path) -> list[Path]:
    """Every lockfile under ``root``, skipping vendored and build directories."""
    if root.is_file():
        return [root]
    out = []
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            entries = sorted(d.iterdir())
        except OSError:
            continue
        for e in entries:
            if e.is_dir():
                if e.name not in _SKIP_DIRS and not e.name.startswith("."):
                    stack.append(e)
            elif is_lockfile(e):
                out.append(e)
    return sorted(out)


def parse(path: str | Path, content: str | None = None) -> DepGraph:
    """Parse one lockfile. ``content`` overrides reading ``path`` (its name still picks
    the format), which is how the MCP server scans a file it was handed as text."""
    p = Path(path)
    n = lockfile_kind(p.name) or p.name
    text = content if content is not None else p.read_text(encoding="utf-8", errors="replace")
    if n in ("package-lock.json", "npm-shrinkwrap.json"):
        g = _parse_package_lock(p, json.loads(text))
    elif n == "yarn.lock":
        g = _parse_yarn(p, text)
    elif n.startswith("requirements") and n.endswith(".txt"):
        if content is not None:
            tmp = DepGraph(str(p), "requirements.txt", "PyPI")
            for raw in text.splitlines():
                m = _REQ.match(raw.strip())
                if m:
                    tmp.add_direct(tmp.add(pep503(m.group(1)), m.group(3)), "prod")
            g = tmp
        else:
            g = _parse_requirements(p)
    elif n == "Pipfile.lock":
        g = _parse_pipfile_lock(p, json.loads(text))
    elif n == "poetry.lock":
        g = _parse_poetry_lock(p, tomllib.loads(text))
    elif n == "uv.lock":
        g = _parse_uv_lock(p, tomllib.loads(text))
    elif n == "Cargo.lock":
        g = _parse_cargo_lock(p, tomllib.loads(text))
    elif n == "go.mod":
        g = _parse_go_mod(p, text)
    elif n == "Gemfile.lock":
        g = _parse_gemfile_lock(p, text)
    elif n == "composer.lock":
        g = _parse_composer_lock(p, json.loads(text))
    else:
        from . import formats  # later formats live in their own module

        parser = formats.PARSERS.get(n)
        if parser is None:
            raise ValueError(
                f"not a supported lockfile: {n} "
                f"(supported: {', '.join(LOCKFILE_NAMES)}, requirements*.txt)"
            )
        g = parser(p, text)
    return g.finalize()
