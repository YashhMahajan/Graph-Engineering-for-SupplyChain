"""Transitive reachability: does project code reach a vulnerable function two or more hops away?

A project calls its *direct* dependency ``D0``. The vulnerable function lives in ``Dn``, reached
through ``D0 -> D1 -> ... -> Dn`` (the dependency path scgraph already proves). The question is
which public names of ``D0`` the project must reference for that to happen. It is answered by
walking the call graph backwards through *released source*, one package at a time:

    S(n)   the vulnerable symbol of Dn and the public entry points above it
    S(i)   public functions of Di that call a name in S(i+1) and whose module imports D(i+1),
           then everything public that calls those inside Di (``climb``)
    S(0)   what project code has to reference, aliases included (``requests.get``)

If some ``S(i)`` is empty, no function of ``Di`` was found calling into ``D(i+1)``'s affected
names: the verdict is ``not_called``, with the same limits as the one-hop analysis (dynamic
dispatch, plugin registries and calls through variables are not seen). The graph is
name-based, so the analysis over-approximates what a call can reach; it never needs a model.

Only the shortest dependency path is analysed. A second path through another direct
dependency is not, so ``not_called`` here means "not through this path".
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from .entry import _COMMON, _imports_name, climb, dotted_names
from .features import ON
from .source import Release

__all__ = ["Hop", "Propagation", "propagate", "top_modules"]

MAX_NAMES = 200


def top_modules(release: Release) -> set[str]:
    """Importable top-level names a release provides (``requests``, ``urllib3``)."""
    out = {release.module_of(p).split(".")[0] for p in release.files}
    return {m for m in out if m and m.isidentifier()}


def _imports_any(text: str, tops: set[str]) -> bool:
    return any(
        re.search(rf"^\s*(?:from|import)\s+{re.escape(t)}\b", text, re.M) is not None for t in tops
    )


def _class_pairs(below: Release, pairs: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """(module, Class) for every method among ``pairs``: a method runs once its class is
    instantiated or referenced, even when the instance is later used without naming it."""
    out: set[tuple[str, str]] = set()
    for mod, qn in pairs:
        f = below.find_any(mod, qn)
        if f is not None and f.owner:
            out.add((mod, f.owner))
    return sorted(out)


def callers_of(
    release: Release, below: Release, pairs: list[tuple[str, str]], tops: set[str]
) -> list[tuple[str, str]]:
    """Functions of ``release`` that reach one of ``pairs`` (functions of ``below``).

    Two kinds of evidence. *Resolved*: the function references the fully resolved dotted name
    (``urllib3.PoolManager``, re-export aliases included) of a pair or of a pair's class: no
    name collision is possible. *By name*: it calls a bare name, from a module importing
    ``below``; very common names (``get``, ``decode``) count only when imported by name from
    the target module, because matching them otherwise would connect everything."""
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(item: tuple[str, str, object]) -> None:
        key = (item[0], item[2].qualname)  # type: ignore[attr-defined]
        if key not in seen:
            seen.add(key)
            out.append(key)

    refs = release.refs_by_dotted()
    real = [(m, q) for m, q in pairs if q != "<module>"]
    cls_pairs = _class_pairs(below, real) if ON["implicit"] else []
    for d in dotted_names(below, [*real, *cls_pairs]) if ON["refs"] else ():
        for item in refs.get(d, []):
            add(item)

    classes = {c for _, c in cls_pairs}
    plain = {qn.rsplit(".", 1)[-1] for _, qn in real} | {c.rsplit(".", 1)[-1] for c in classes}
    safe = {n for n in plain if n not in _COMMON and len(n) > 3}
    exact: dict[str, list[str]] = {}
    for mod, qn in real:
        n = qn.rsplit(".", 1)[-1]
        if n not in safe:
            exact.setdefault(n, []).append(mod)
    for mod, c in cls_pairs:
        n = c.rsplit(".", 1)[-1]
        if n not in safe:
            exact.setdefault(n, []).append(mod)
    imports: dict[str, bool] = {}
    index = release.callers_by_name()
    for name in plain:
        for mod, path, f in index.get(name, []):
            if (mod, f.qualname) in seen:
                continue
            text = release.files.get(path, "")
            if path not in imports:
                imports[path] = _imports_any(text, tops)
            if not imports[path]:
                continue
            if name in safe or any(_imports_name(text, m, name) for m in exact.get(name, [])):
                add((mod, path, f))
    if ON["implicit"]:  # a property of the dependency runs when the parent reads it
        for mod, qn in real:
            prop = below.find_any(mod, qn)
            if prop is None or not prop.is_property or len(prop.name) <= 3:
                continue
            for item in release.readers_of(prop.name):
                path = item[1]
                if path not in imports:
                    imports[path] = _imports_any(release.files.get(path, ""), tops)
                if imports[path]:
                    add(item)
    if ON["module"] and any(q == "<module>" for _, q in pairs):  # the dependency runs on import
        for mod, path, f in release.graph_functions():
            if f.qualname == "<module>" and _imports_any(release.files.get(path, ""), tops):
                add((mod, path, f))
    return out


def _module_imports(body: list[ast.stmt], pkg: str, found: set[str]) -> None:
    """Dotted modules imported by top-level statements of a module in package ``pkg``
    (relative imports resolved; imports inside functions are lazy and ignored)."""
    parts = pkg.split(".")
    for n in body:
        if isinstance(n, ast.Import):
            found.update(a.name for a in n.names)
        elif isinstance(n, ast.ImportFrom):
            if n.level:
                base = ".".join(parts[: max(0, len(parts) - (n.level - 1))])
                root = ".".join(x for x in (base, n.module or "") if x)
            else:
                root = n.module or ""
            found.add(root)
            found.update(f"{root}.{a.name}" for a in n.names)
        elif isinstance(n, ast.If | ast.Try):
            _module_imports(n.body, pkg, found)
            _module_imports(n.orelse, pkg, found)
            if isinstance(n, ast.Try):
                for h in n.handlers:
                    _module_imports(h.body, pkg, found)
                _module_imports(n.finalbody, pkg, found)


def _imported_modules(release: Release, top: str) -> set[str]:
    """Modules of ``top`` that run when ``top`` is imported: the import closure of its
    ``__init__`` through module-level imports."""
    by_mod = {release.module_of(p): p for p in release.files}
    edges: dict[str, set[str]] = {}
    for mod, path in by_mod.items():
        if mod.split(".")[0] != top:
            continue
        try:
            tree = ast.parse(release.files[path])
        except (SyntaxError, ValueError):
            continue
        found: set[str] = set()
        _module_imports(
            tree.body, mod if path.endswith("__init__.py") else mod.rpartition(".")[0], found
        )
        edges[mod] = {m for m in found if m in by_mod}
    out: set[str] = {top} if top in by_mod else set()
    stack = list(out)
    while stack:
        for m in edges.get(stack.pop(), ()):
            if m not in out:
                out.add(m)
                stack.append(m)
    return out


@dataclass
class Hop:
    package: str
    version: str
    callers: int  # functions of this package that call into the next one
    reached: int  # public functions above them


@dataclass
class Propagation:
    names: list[str]  # what project code must reference in the direct dependency
    hops: list[Hop] = field(default_factory=list)
    broke_at: str = ""  # the package where no caller was found ("" when it reached D0)

    @property
    def reached(self) -> bool:
        return bool(self.names)


def propagate(
    chain: list[Release], seeds: list[tuple[str, str]], depth: int = 5, cap: int = 100
) -> Propagation:
    """``chain`` is ordered direct dependency first, vulnerable package last; ``seeds`` are the
    (module, qualname) pairs of the vulnerable symbol and its entry points in ``chain[-1]``."""
    pairs = list(seeds)
    hops: list[Hop] = []
    for i in range(len(chain) - 2, -1, -1):
        below, here = chain[i + 1], chain[i]
        starts = callers_of(here, below, pairs, top_modules(below))
        if not starts:
            hops.append(Hop(here.package, here.version, 0, 0))
            return Propagation([], hops[::-1], broke_at=here.package)
        pairs = climb(here, starts, depth=depth, cap=cap)
        hops.append(Hop(here.package, here.version, len(starts), len(pairs)))
        if not pairs:  # the callers exist but nothing public reaches them
            return Propagation([], hops[::-1], broke_at=here.package)
    head = chain[0]
    regular = [(m, q) for m, q in pairs if q != "<module>"]
    names = dotted_names(head, regular)
    wild = [m for m, q in pairs if q == "<module>"]
    if wild:  # import-time reach: anything that imports the package (or that module) triggers it
        top = next(iter(sorted(top_modules(head))), "")
        loaded = _imported_modules(head, top) if top else set()
        for m in wild:
            token = f"{m.split('.')[0]}.*" if m in loaded else f"{m}.*"
            if token not in names:
                names.append(token)
    return Propagation(names[:MAX_NAMES], hops[::-1])
