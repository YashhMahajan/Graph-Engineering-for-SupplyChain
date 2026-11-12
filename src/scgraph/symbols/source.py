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
from .candidates import go_package, is_test_path, lang_of, py_module
from .code import Func, functions
from .fetch import Fetcher

__all__ = ["Release", "bracket", "go_release", "go_versions", "pypi_release", "pypi_versions"]

MAX_FILES = 6000
MAX_FILE_BYTES = 1_000_000


@dataclass
class Release:
    ecosystem: str  # "PyPI" | "Go"
    package: str
    version: str
    files: dict[str, str]
    module: str = ""  # Go module path
    _funcs: list[tuple[str, str, Func]] | None = field(default=None, repr=False)

    @property
    def lang(self) -> str:
        return "python" if self.ecosystem == "PyPI" else "go"

    def module_of(self, path: str) -> str:
        return py_module(path) if self.lang == "python" else go_package(self.module, path)

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

    def find(self, module: str, qualname: str) -> Func | None:
        """The function ``qualname`` in ``module``; a module path may differ by the leading
        segments a repository adds (``src/``) or by a Go major-version suffix."""
        best = None
        for mod, _, f in self.functions():
            if f.qualname != qualname:
                continue
            if mod == module:
                return f
            if (
                mod.endswith(module)
                or module.endswith(mod)
                or mod.split("/")[-1] == module.split("/")[-1]
            ):
                best = best or f
        return best


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


def bracket(record: dict, ecosystem: str, package: str, versions: list[str]) -> tuple[str, str]:
    """(last affected, first fixed) for ``package``: the first fixed version an OSV range
    names, and the highest published version below it that the record marks affected.
    Either is "" when it cannot be determined."""
    eco = "pypi" if ecosystem == "PyPI" else "go"
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
