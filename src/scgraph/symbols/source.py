"""Released source: the files of one version of a PyPI project or a Go module.

The verifier and Engine B work on what was actually *published*, not on the repository: a
PyPI wheel holds exactly the importable modules, and the Go module proxy serves the module
zip that ``go get`` downloads. Both are cached by the ``Fetcher``.

  pypi_release(f, "requests", "2.30.0")       -> Release (import-relative paths)
  go_release(f, "go.etcd.io/etcd", "3.4.9")   -> Release (module-relative paths)
  bracket(record, eco, pkg, versions)         -> (last affected version, first fixed version)
"""

from __future__ import annotations

import io
import tarfile
import zipfile
from dataclasses import dataclass, field

from ..versions import affected, compare, sort_versions
from .candidates import go_package, is_test_path, js_module, lang_of, py_module
from .code import Func, functions
from .features import ON
from .fetch import Fetcher

__all__ = [
    "Release",
    "bracket",
    "brackets",
    "go_release",
    "go_versions",
    "pypi_release",
    "pypi_versions",
]

MAX_FILES = 6000
MAX_FILE_BYTES = 1_000_000


@dataclass
class Release:
    ecosystem: str  # "PyPI" | "Go"
    package: str
    version: str
    files: dict[str, str]
    module: str = ""  # Go module path
    main: str = ""  # npm: the package entry file
    _funcs: list[tuple[str, str, Func]] | None = field(default=None, repr=False)
    _index: dict[str, list[tuple[str, str, Func]]] | None = field(default=None, repr=False)
    _graph: list[tuple[str, str, Func]] | None = field(default=None, repr=False)
    _refs: dict[str, list[tuple[str, str, Func]]] | None = field(default=None, repr=False)
    _exact: dict[tuple[str, str], Func] | None = field(default=None, repr=False)
    _readers: dict[str, list[tuple[str, str, Func]]] | None = field(default=None, repr=False)

    @property
    def lang(self) -> str:
        return {"PyPI": "python", "npm": "javascript"}.get(self.ecosystem, "go")

    def module_of(self, path: str) -> str:
        if self.lang == "python":
            return py_module(path)
        if self.lang == "javascript":
            return f"{self.package}/{js_module(path)}"
        return go_package(self.module, path)

    def functions(self) -> list[tuple[str, str, Func]]:
        """(module, path, Func) for every function outside tests."""
        if self._funcs is None:
            out: list[tuple[str, str, Func]] = []
            for path, text in self.files.items():
                if is_test_path(path):
                    continue
                mod = self.module_of(path)
                out.extend((mod, path, f) for f in functions(text, self.lang))
            self._funcs = out
        return self._funcs

    def graph_functions(self) -> list[tuple[str, str, Func]]:
        """``functions()`` plus, for Python and JavaScript, one ``<module>`` pseudo-function per
        file, standing for the code that runs on import. Used by the call graph only."""
        if self._graph is None:
            out = list(self.functions())
            if self.lang in ("python", "javascript") and ON["module"]:
                for path, text in self.files.items():
                    if is_test_path(path):
                        continue
                    mod = self.module_of(path)
                    out.extend(
                        (mod, path, f)
                        for f in functions(text, self.lang, True, path)
                        if f.qualname == "<module>"
                    )
            self._graph = out
        return self._graph

    def callers_by_name(self) -> dict[str, list[tuple[str, str, Func]]]:
        """Functions grouped by the bare names they reach (built once per release): the names
        they call, properties they read, same-module functions passed as values, and methods
        selected by a dynamic ``getattr(self, "prefix_" + x)`` dispatch."""
        if self._index is None:
            items = self.graph_functions()
            props = {f.name for _, _, f in items if f.is_property and len(f.name) > 3}
            plain: dict[str, set[str]] = {}
            methods: set[str] = set()
            for mod, _, f in items:
                if f.qualname == "<module>":
                    continue
                if f.is_method:
                    methods.add(f.name)
                else:
                    plain.setdefault(mod, set()).add(f.name)
            idx: dict[str, list[tuple[str, str, Func]]] = {}
            for item in items:
                mod, _, f = item
                names = set(f.calls)
                if ON["loads"]:
                    names |= f.loads & (props | plain.get(mod, set()))
                for pre in f.dyn if ON["dyn"] else ():
                    names |= {m for m in methods if m.startswith(pre)}
                for n in names:
                    idx.setdefault(n, []).append(item)
            self._index = idx
        return self._index

    def readers_of(self, name: str) -> list[tuple[str, str, Func]]:
        """Functions that read ``name`` as a value (an attribute access or a bare name)."""
        if self._readers is None:
            idx: dict[str, list[tuple[str, str, Func]]] = {}
            for item in self.graph_functions():
                for n in item[2].loads:
                    idx.setdefault(n, []).append(item)
            self._readers = idx
        return self._readers.get(name, [])

    def refs_by_dotted(self) -> dict[str, list[tuple[str, str, Func]]]:
        """Functions grouped by the fully resolved dotted names they reference."""
        if self._refs is None:
            idx: dict[str, list[tuple[str, str, Func]]] = {}
            for item in self.graph_functions():
                for r in item[2].refs:
                    idx.setdefault(r, []).append(item)
            self._refs = idx
        return self._refs

    def locate(self, module: str, qualname: str) -> tuple[str, Func] | None:
        """(the release's own module id, the function) for ``qualname``. A module path from a
        repository may differ from the released one by a leading ``src/`` or a Go
        major-version suffix, or (npm) by the build directory: ``src/x`` vs ``lib/x``."""
        if self._exact is None:
            self._exact = {(m, f.qualname): f for m, _, f in self.functions()}
        hit = self._exact.get((module, qualname))
        if hit is not None:
            return module, hit
        best: tuple[str, Func] | None = None
        cands = [(m, f) for m, _, f in self.functions() if f.qualname == qualname]
        if not cands and self.lang == "javascript":  # `function Range()` became `class Range`
            cands = [
                (m, f) for m, _, f in self.functions() if f.qualname == f"{qualname}.constructor"
            ]
        for mod, f in cands:
            if (
                mod.endswith(module)
                or module.endswith(mod)
                or mod.split("/")[-1] == module.split("/")[-1]
            ):
                best = best or (mod, f)
        if best is None and self.lang == "javascript" and len(cands) == 1:
            best = cands[0]  # a bundled or rebuilt package: the name alone is unambiguous
        return best

    def find(self, module: str, qualname: str) -> Func | None:
        hit = self.locate(module, qualname)
        return hit[1] if hit else None

    def find_any(self, module: str, qualname: str) -> Func | None:
        """Like ``find`` but also resolves the ``<module>`` pseudo-function."""
        if qualname == "<module>":
            return next(
                (f for m, _, f in self.graph_functions() if m == module and f.qualname == qualname),
                None,
            )
        return self.find(module, qualname)


def _keep(path: str, lang: str) -> bool:
    return lang_of(path) == lang and not is_test_path(path)


def pypi_versions(f: Fetcher, name: str) -> list[str]:
    d = f.json(f"https://pypi.org/pypi/{name}/json")
    if not d:
        return []
    rel = d.get("releases") or {}
    return sort_versions([v for v, files in rel.items() if files], "pypi")


def _pick(urls: list[dict]) -> dict | None:
    wheels = [u for u in urls if u.get("packagetype") == "bdist_wheel" and not u.get("yanked")]
    for tag in ("py3-none-any", "py2.py3-none-any"):
        for u in wheels:
            if u.get("filename", "").endswith(f"{tag}.whl"):
                return u
    if wheels:
        return min(wheels, key=lambda u: u.get("size") or 0)
    sd = [u for u in urls if u.get("packagetype") == "sdist"]
    return sd[0] if sd else None


def pypi_release(f: Fetcher, name: str, version: str) -> Release | None:
    return f.memo(("pypi", name, version), lambda: _pypi_release(f, name, version))


def _pypi_release(f: Fetcher, name: str, version: str) -> Release | None:
    d = f.json(f"https://pypi.org/pypi/{name}/{version}/json")
    if not d:
        return None
    u = _pick(d.get("urls") or [])
    if not u:
        return None
    blob = f.bytes(u["url"])
    if blob is None:
        return None
    files: dict[str, str] = {}
    fn = u.get("filename", "")
    try:
        if fn.endswith((".whl", ".zip")):
            with zipfile.ZipFile(io.BytesIO(blob)) as z:
                for info in z.infolist():
                    p = info.filename
                    if fn.endswith(".zip"):
                        p = p.split("/", 1)[1] if "/" in p else p
                    if info.file_size <= MAX_FILE_BYTES and _keep(p, "python"):
                        files[p] = z.read(info).decode("utf-8", errors="replace")
                    if len(files) >= MAX_FILES:
                        break
        else:
            with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as t:
                for m in t.getmembers():
                    if not m.isfile() or m.size > MAX_FILE_BYTES:
                        continue
                    p = m.name.split("/", 1)[1] if "/" in m.name else m.name
                    if _keep(p, "python"):
                        fh = t.extractfile(m)
                        if fh is not None:
                            files[p] = fh.read().decode("utf-8", errors="replace")
                    if len(files) >= MAX_FILES:
                        break
    except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError):
        return None
    return Release("PyPI", name, version, files)


def _go_escape(module: str) -> str:
    return "".join(f"!{c.lower()}" if c.isupper() else c for c in module)


def _go_v(version: str) -> str:
    return version if version.startswith("v") else f"v{version}"


def go_versions(f: Fetcher, module: str) -> list[str]:
    t = f.text(f"https://proxy.golang.org/{_go_escape(module)}/@v/list")
    if not t:
        return []
    return sort_versions([v.lstrip("v") for v in t.split() if v.strip()], "go")


def go_release(f: Fetcher, module: str, version: str) -> Release | None:
    return f.memo(("go", module, version), lambda: _go_release(f, module, version))


def _go_release(f: Fetcher, module: str, version: str) -> Release | None:
    v = _go_v(version)
    blob = f.bytes(f"https://proxy.golang.org/{_go_escape(module)}/@v/{v}.zip")
    if blob is None:
        return None
    prefix = f"{module}@{v}/"
    files: dict[str, str] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            for info in z.infolist():
                if not info.filename.startswith(prefix) or info.file_size > MAX_FILE_BYTES:
                    continue
                p = info.filename[len(prefix) :]
                if _keep(p, "go"):
                    files[p] = z.read(info).decode("utf-8", errors="replace")
                if len(files) >= MAX_FILES:
                    break
    except (zipfile.BadZipFile, OSError):
        return None
    return Release("Go", module, version.lstrip("v"), files, module=module)


def brackets(
    record: dict, ecosystem: str, package: str, versions: list[str]
) -> list[tuple[str, str]]:
    """Every (last affected, first fixed) pair of ``package``, one per OSV range that names a
    fix. A package maintained on several lines (7.x and 8.x) has one per line, and a fix commit
    belongs to only one of them."""
    eco = {"PyPI": "pypi", "npm": "npm"}.get(ecosystem, "go")
    out: list[tuple[str, str]] = []
    for a in record.get("affected") or []:
        if (a.get("package") or {}).get("name") != package:
            continue
        for r in a.get("ranges") or []:
            fixed = next((e["fixed"] for e in r.get("events") or [] if "fixed" in e), "")
            if not fixed:
                continue
            below = [v for v in versions if compare(v, fixed, eco) < 0 and affected(v, a, eco)]
            pair = (below[-1] if below else "", fixed)
            if pair not in out:
                out.append(pair)
    return out


def bracket(record: dict, ecosystem: str, package: str, versions: list[str]) -> tuple[str, str]:
    """(last affected, first fixed) for ``package``: the first fixed version an OSV range
    names, and the highest published version below it that the record marks affected.
    Either is "" when it cannot be determined."""
    eco = {"PyPI": "pypi", "npm": "npm"}.get(ecosystem, "go")
    for a in record.get("affected") or []:
        if (a.get("package") or {}).get("name") != package:
            continue
        for r in a.get("ranges") or []:
            fixed = next((e["fixed"] for e in r.get("events") or [] if "fixed" in e), "")
            if not fixed:
                continue
            below = [v for v in versions if compare(v, fixed, eco) < 0 and affected(v, a, eco)]
            return (below[-1] if below else "", fixed)
    return "", ""
