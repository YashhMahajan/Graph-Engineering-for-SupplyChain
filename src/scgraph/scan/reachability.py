"""Function-level reachability for Python: does project code call the vulnerable function?

Some advisories name the vulnerable functions (OSV ``ecosystem_specific.affected_functions``,
or ``imports[].symbols`` for Go). For those, and for a *direct* Python dependency, the
project's own source can be searched for a reference to one of them. The result is attached
to the alert and **never suppresses it**:

  reachable     project source references a listed vulnerable function
  class_used    a listed function is a method and project source references its class
  not_called    the advisory lists functions and no reference to any was found
  not_analyzed  nothing can be said, and the reason is one of: not a Python package, the
                advisory lists no functions, or the package is transitive (project code does
                not call it directly, so this analysis has nothing to look at)

Resolution uses ``ast``, so aliases work: ``import yaml as y; y.load(x)``,
``from yaml import load as ld; ld(x)`` and ``import a.b; a.b.f()`` all resolve to the
dotted name an advisory uses. ``not_called`` is *no reference found*, not proof: a call made
through ``getattr``, ``eval``, a plugin registry or another package's wrapper is not seen, and
an advisory's function list can be incomplete. Treat it as a way to order the queue, never as
a reason to close an alert.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from .lockfiles import _SKIP_DIRS

__all__ = [
    "classify",
    "referenced_names",
    "referenced_names_go",
    "scan_go",
    "scan_js",
    "scan_python",
    "symbols_of",
]

_JS_EXT = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".mts", ".cts")
_TS_EXT = (".ts", ".mts", ".cts")
_MAX_FILES = 20_000
_MAX_BYTES = 1_000_000


def symbols_of(entries: list[dict]) -> list[str]:
    """Vulnerable function names an advisory lists for a package, as dotted names."""
    out: set[str] = set()
    for a in entries:
        eco = a.get("ecosystem_specific") or {}
        out.update(f for f in eco.get("affected_functions") or [] if isinstance(f, str) and f)
        for imp in eco.get("imports") or []:  # the Go vulnerability database's layout
            if isinstance(imp, dict) and isinstance(imp.get("path"), str):
                out.update(
                    f"{imp['path']}.{s}" for s in imp.get("symbols") or [] if isinstance(s, str)
                )
    return sorted(out)


def _chain(node: ast.AST) -> list[str] | None:
    """``a.b.c`` -> ``['a', 'b', 'c']`` when the base is a plain name, else None."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return parts[::-1]
    return None


def referenced_names(source: str) -> set[str]:
    """Every dotted name the source refers to, with import aliases resolved. Includes names
    that are only passed around (``map(yaml.load, xs)``), not just called."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return set()
    alias: dict[str, str] = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.asname:
                    alias[a.asname] = a.name
                else:  # `import a.b` binds the name `a`
                    alias[a.name.split(".")[0]] = a.name.split(".")[0]
        elif isinstance(n, ast.ImportFrom) and n.module and n.level == 0:
            for a in n.names:
                if a.name != "*":
                    alias[a.asname or a.name] = f"{n.module}.{a.name}"
    out: set[str] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Attribute | ast.Name) and isinstance(
            getattr(n, "ctx", None), ast.Load
        ):
            chain = _chain(n)
            if chain and chain[0] in alias:
                out.add(".".join([alias[chain[0]], *chain[1:]]))
    return out


def scan_python(root: Path) -> set[str]:
    """Referenced dotted names across ``root``'s Python source (vendored, build and hidden
    directories, huge files and anything past the file cap are skipped)."""
    names: set[str] = set()
    seen = 0
    stack = [root]
    while stack and seen < _MAX_FILES:
        d = stack.pop()
        try:
            entries = sorted(d.iterdir())
        except OSError:
            continue
        for e in entries:
            if e.is_dir():
                if e.name not in _SKIP_DIRS and not e.name.startswith("."):
                    stack.append(e)
            elif e.suffix == ".py":
                seen += 1
                try:
                    if e.stat().st_size <= _MAX_BYTES:
                        names |= referenced_names(e.read_text(encoding="utf-8", errors="replace"))
                except OSError:
                    continue
    return names


def scan_js(root: Path) -> set[str]:
    """Like ``scan_python`` for JavaScript (``.js``, ``.jsx``, ``.mjs``, ``.cjs``) and TypeScript
    (``.ts``). Needs the optional tree-sitter packages; without them the set is empty and
    nothing is claimed."""
    from ..symbols.js import available, referenced_names_js

    names: set[str] = set()
    if not available():
        return names
    seen = 0
    stack = [root]
    while stack and seen < _MAX_FILES:
        d = stack.pop()
        try:
            entries = sorted(d.iterdir())
        except OSError:
            continue
        for e in entries:
            if e.is_dir():
                if e.name not in _SKIP_DIRS and not e.name.startswith("."):
                    stack.append(e)
            elif e.suffix in _JS_EXT and not e.name.endswith((".min.js", ".d.ts")):
                seen += 1
                try:
                    if e.stat().st_size <= _MAX_BYTES:
                        names |= referenced_names_js(
                            e.read_text(encoding="utf-8", errors="replace"), ts=e.suffix in _TS_EXT
                        )
                except OSError:
                    continue
    return names


_GO_SINGLE = re.compile(r'(?m)^\s*import\s+(?:(\w+|\.|_)\s+)?"([^"\n]+)"')
_GO_BLOCK = re.compile(r"(?s)\bimport\s*\((.*?)\)")
_GO_LINE = re.compile(r'(?m)^\s*(?:(\w+|\.|_)\s+)?"([^"\n]+)"\s*$')
_GO_VERSION = re.compile(r"^v\d+$")


def referenced_names_go(source: str) -> set[str]:
    """Every ``importpath.Name`` a Go file uses: ``import "go.etcd.io/etcd/wal"`` followed by
    ``wal.Create(...)`` gives ``go.etcd.io/etcd/wal.Create``. An import alias resolves, and a
    major-version path (``.../v2``) is named by the element before it. A dot import and a
    blank import are not tracked."""
    found = list(_GO_SINGLE.findall(source))
    for body in _GO_BLOCK.findall(source):
        found += _GO_LINE.findall(body)
    imports: dict[str, str] = {}
    for alias, path in found:
        if alias in (".", "_"):
            continue
        parts = path.split("/")
        default = parts[-2] if _GO_VERSION.match(parts[-1]) and len(parts) > 1 else parts[-1]
        imports[alias or default.replace("-", "_")] = path
    code = re.sub(r'`[^`]*`|"(?:\\.|[^"\\\n])*"|//[^\n]*|/\*.*?\*/', '""', source, flags=re.S)
    out: set[str] = set()
    for alias, path in imports.items():
        used = False
        for m in re.finditer(rf"\b{re.escape(alias)}\.([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)", code):
            out.add(f"{path}.{m.group(1)}")
            used = True
        if used:
            out.add(path)
    return out


def scan_go(root: Path) -> set[str]:
    """Like ``scan_python`` for Go source (``.go`` files, tests skipped)."""
    names: set[str] = set()
    seen = 0
    stack = [root]
    while stack and seen < _MAX_FILES:
        d = stack.pop()
        try:
            entries = sorted(d.iterdir())
        except OSError:
            continue
        for e in entries:
            if e.is_dir():
                if e.name not in _SKIP_DIRS and not e.name.startswith("."):
                    stack.append(e)
            elif e.suffix == ".go" and not e.name.endswith("_test.go"):
                seen += 1
                try:
                    if e.stat().st_size <= _MAX_BYTES:
                        names |= referenced_names_go(
                            e.read_text(encoding="utf-8", errors="replace")
                        )
                except OSError:
                    continue
    return names


def _class_of(symbol: str) -> str | None:
    """``pkg.mod.Session.request`` -> ``pkg.mod.Session`` when the second-to-last segment
    looks like a class (CapWords); None for a module-level function."""
    parts = symbol.split(".")
    if len(parts) >= 3 and parts[-2][:1].isupper():
        return ".".join(parts[:-1])
    return None


def classify(
    ecosystem: str,
    path: list[str] | None,
    symbols: list[str],
    names: set[str],
    deep: bool = False,
) -> str:
    """``reachable``, ``class_used``, ``not_called`` or ``not_analyzed`` for one alert.

    A method call through an instance (``s = requests.Session(); s.request()``) is not a
    dotted name the source spells out, so when a listed symbol is a method and the source
    references its class, the verdict is ``class_used``, never ``not_called``."""
    if ecosystem not in ("PyPI", "npm", "Go") or not symbols:
        return "not_analyzed"
    if not path or (len(path) != 2 and not deep):
        # transitive: project code does not call it directly. With ``deep`` the symbols are
        # the direct dependency's names that reach the vulnerable function.
        return "not_analyzed"
    if any(s in names for s in symbols):
        return "reachable"
    for s in symbols:  # "pkg.*": import-time reach, triggered by using anything of pkg
        if s.endswith(".*") and any(n.startswith(s[:-1]) or n == s[:-2] for n in names):
            return "reachable"
    classes = {c for c in map(_class_of, symbols) if c}
    if classes & names:
        return "class_used"
    return "not_called"
