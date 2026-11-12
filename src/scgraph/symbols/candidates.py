"""Engine A, step 1: turn a fix diff into candidate vulnerable functions (no model).

For each changed code file (tests, docs, examples and vendored code removed), every change is
mapped to the function that encloses it in the post-fix source. The callers of each changed
function in the same files are added as candidates too: the Go vulnerability database labels
the exported functions that reach a patched helper, and VFArche (2025) measured that 26% of
vulnerable functions are not among the functions a patch modifies.

Each candidate carries the facts the ranker scores: size and share of the change, public or
private, method or function, introduced by the fix or not, how often the fix's own tests name
it, and how much of its name appears in the advisory text.
"""

from __future__ import annotations

import math
import posixpath
import re
from dataclasses import dataclass, field

from .code import Func, enclosing, functions, identifier_tokens
from .diff import FileDiff, Hunk

__all__ = [
    "Candidate",
    "CandidateSet",
    "build_candidates",
    "go_package",
    "is_code",
    "is_test_path",
    "js_module",
    "lang_of",
    "py_module",
]

_EXT = {
    ".ts": "javascript",
    ".mts": "javascript",
    ".cts": "javascript",
    ".py": "python",
    ".go": "go",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
}
_SKIP_SEGMENTS = {
    "test",
    "tests",
    "testing",
    "testdata",
    "test_data",
    "docs",
    "doc",
    "documentation",
    "examples",
    "example",
    "_examples",
    "benchmarks",
    "benchmark",
    "bench",
    "vendor",
    "third_party",
    "_vendor",
    "fixtures",
    "integration_tests",
    "e2e",
    "__tests__",
    "__mocks__",
    "spec",
    "specs",
    "node_modules",
    "coverage",
}
_PY_ROOTS = {"src", "lib", "python", "py", "pysrc", "source"}
_CHECK = re.compile(
    r"\b(if|raise|panic|return\s+(?:nil,\s*)?(?:err|fmt\.Errorf|errors\.)|"
    r"validate|valid|check|sanitize|escape|quote|limit|max|len)\b",
    re.I,
)
_CONTEXT_NAME = re.compile(
    r"^(?:async\s+)?def\s+(\w+)|^func\s*(?:\([^)]*?\*?\s*(\w+)(?:\[[^\]]*\])?\s*\)\s*)?(\w+)"
)


def lang_of(path: str) -> str | None:
    return _EXT.get(posixpath.splitext(path)[1])


def is_test_path(path: str) -> bool:
    segs = path.lower().split("/")
    base = segs[-1]
    if any(s in _SKIP_SEGMENTS for s in segs[:-1]):
        return True
    return (
        base.startswith("test_")
        or base.endswith(
            ("_test.py", "_test.go", "_tests.py", ".test.js", ".spec.js", ".test.mjs", ".spec.mjs")
        )
        or base.endswith((".min.js", ".d.ts", ".test.ts", ".spec.ts"))
        or base in {"conftest.py", "tests.py", "setup.py", "noxfile.py", "fabfile.py"}
    )


def is_code(path: str) -> bool:
    return lang_of(path) is not None and not is_test_path(path)


def py_module(path: str) -> str:
    """``src/pkg/sub/mod.py`` -> ``pkg.sub.mod``; ``pkg/__init__.py`` -> ``pkg``."""
    segs = path.split("/")
    while len(segs) > 1 and segs[0].lower() in _PY_ROOTS:
        segs = segs[1:]
    segs[-1] = segs[-1][:-3] if segs[-1].endswith(".py") else segs[-1]
    if segs[-1] == "__init__":
        segs = segs[:-1]
    return ".".join(s for s in segs if s)


def js_module(path: str) -> str:
    """``lib/utils.js`` -> ``lib/utils`` (a path inside a package, without its extension)."""
    return posixpath.splitext(path)[0]


def go_package(module: str, path: str) -> str:
    d = posixpath.dirname(path)
    return f"{module}/{d}" if d else module


@dataclass
class Candidate:
    qualname: str
    module: str  # Python module or Go package path
    file: str
    lang: str
    added: int = 0
    removed: int = 0
    hunks: list[int] = field(default_factory=list)  # indexes into CandidateSet.hunks
    public: bool = False
    is_method: bool = False
    dunder: bool = False
    new_function: bool = False  # the fix introduced it, so it cannot be the vulnerable code
    via_caller: bool = False  # unchanged, but calls a changed function
    callee: str = ""
    test_refs: int = 0
    name_in_advisory: bool = False
    advisory_overlap: float = 0.0
    adds_check: bool = False
    doc: str = ""
    signature: str = ""
    # set once the whole set is known
    share: float = 0.0
    size_rank: int = 0
    n_changed: int = 0
    score: float = 0.0

    @property
    def symbol(self) -> str:
        return f"{self.module}.{self.qualname}" if self.module else self.qualname

    @property
    def name(self) -> str:
        return self.qualname.rsplit(".", 1)[-1]

    @property
    def changed(self) -> int:
        return self.added + self.removed


@dataclass
class CandidateSet:
    candidates: list[Candidate]
    hunks: list[Hunk]
    code_files: int = 0
    test_files: int = 0
    module_level_changes: int = 0  # changed lines outside any function (constants, imports)
    missing_sources: int = 0

    def excerpt(self, c: Candidate, max_lines: int = 30) -> str:
        if not c.hunks:
            return ""
        out: list[str] = []
        budget = max_lines
        for i in c.hunks:
            if budget <= 0:
                out.append("...")
                break
            t = self.hunks[i].text(max_lines=budget).splitlines()
            out.extend(t)
            budget -= len(t)
        return "\n".join(out)


_STOP = frozenset(
    [
        "a",
        "an",
        "the",
        "of",
        "to",
        "in",
        "on",
        "for",
        "and",
        "or",
        "is",
        "are",
        "be",
        "by",
        "with",
        "via",
        "when",
        "this",
        "that",
        "it",
        "its",
        "as",
        "at",
        "from",
        "can",
        "could",
        "may",
        "might",
        "allow",
        "allows",
        "allowed",
        "which",
        "before",
        "after",
        "use",
        "used",
        "using",
        "user",
        "users",
        "vulnerability",
        "vulnerable",
        "issue",
        "attacker",
        "attackers",
        "remote",
        "arbitrary",
        "version",
        "versions",
        "fixed",
        "fix",
        "prior",
        "through",
        "cause",
        "causes",
        "lead",
        "leads",
        "denial",
        "service",
    ]
)


def _advisory_tokens(text: str) -> set[str]:
    return {t for t in identifier_tokens(text) if len(t) > 2 and t not in _STOP}


def _name_in(text: str, c: Candidate) -> bool:
    if len(c.name) < 4:
        return c.qualname in text
    return re.search(rf"(?<![\w.]){re.escape(c.name)}(?!\w)", text) is not None


def _module_of(lang: str, path: str, go_module: str) -> str:
    if lang == "python":
        return py_module(path)
    if lang == "javascript":
        return js_module(path)
    return go_package(go_module, path)


def _from_context(context: str, lang: str) -> Func | None:
    """A stand-in function from git's hunk header, used when the post-fix file is missing."""
    m = _CONTEXT_NAME.match(context)
    if not m:
        return None
    name = m.group(1) or m.group(3)
    recv = m.group(2)
    q = f"{recv}.{name}" if recv else name
    if lang == "go":
        public = name[:1].isupper() and (recv is None or recv[:1].isupper())
    else:
        public = not name.startswith("_")
    return Func(q, 0, 0, public, bool(recv), "", frozenset(), "", "")


def build_candidates(
    files: list[FileDiff],
    sources: dict[str, str],
    advisory_text: str,
    module: str = "",
    max_callers: int = 8,
) -> CandidateSet:
    """Candidates from a parsed fix. ``sources`` holds post-fix file text by path (a missing
    file falls back to git's hunk-header function name). ``module`` is the Go module path."""
    cs = CandidateSet(candidates=[], hunks=[])
    test_text = []
    by_key: dict[tuple[str, str], Candidate] = {}
    funcs_by_file: dict[str, list[Func]] = {}
    for fd in files:
        lang = lang_of(fd.path)
        if fd.binary or lang is None:
            continue
        if is_test_path(fd.path):
            cs.test_files += 1
            test_text.extend(fd.added_text())
            continue
        if fd.is_deleted:
            continue
        cs.code_files += 1
        mod = _module_of(lang, fd.path, module)
        src = sources.get(fd.path)
        funcs = functions(src, lang, path=fd.path) if src else []
        if src is None:
            cs.missing_sources += 1
        funcs_by_file[fd.path] = funcs
        for h in fd.hunks:
            hi = len(cs.hunks)
            cs.hunks.append(h)
            added = set(h.added)
            removed_at = set(h.removed_anchors)
            touched: dict[str, tuple[Func | None, int, int]] = {}
            changes = [(a, "+") for a in h.added] + [(a, "-") for a in h.removed_anchors]
            for ln, kind in changes:
                f = None
                if funcs:  # a deletion at a function's end anchors one line past it
                    f = enclosing(funcs, ln) or (enclosing(funcs, ln - 1) if kind == "-" else None)
                if f is None and not funcs:
                    f = _from_context(h.context, lang)
                if f is None:
                    cs.module_level_changes += 1
                    continue
                prev = touched.get(f.qualname, (f, 0, 0))
                touched[f.qualname] = (f, prev[1] + (kind == "+"), prev[2] + (kind == "-"))
            for q, (f, a, r) in touched.items():
                assert f is not None
                key = (fd.path, q)
                c = by_key.get(key)
                if c is None:
                    c = Candidate(
                        qualname=q,
                        module=mod,
                        file=fd.path,
                        lang=lang,
                        public=f.public,
                        is_method=f.is_method,
                        dunder=f.dunder,
                        doc=f.doc,
                        signature=f.signature,
                        # new only when the whole span is added and nothing was deleted inside it:
                        # a one-line function that was edited has its first line "added" too
                        new_function=f.start > 0
                        and f.end >= f.start
                        and all(ln in added for ln in range(f.start, f.end + 1))
                        and not any(f.start <= a <= f.end + 1 for a in removed_at),
                    )
                    by_key[key] = c
                c.added += a
                c.removed += r
                if hi not in c.hunks:
                    c.hunks.append(hi)
                body = [ln[1:] for ln in h.lines if ln.startswith("+")]
                if any(_CHECK.search(b) for b in body):
                    c.adds_check = True

    changed = list(by_key.values())
    changed_names = {c.name for c in changed if not c.new_function}
    # callers of changed functions, in the same files (the only post-fix source we hold)
    for path, funcs in funcs_by_file.items():
        lang = lang_of(path) or ""
        mod = _module_of(lang, path, module)
        n = 0
        for f in funcs:
            if (path, f.qualname) in by_key or n >= max_callers * max(1, len(changed_names)):
                continue
            hit = sorted(f.calls & changed_names)
            if hit:
                by_key[(path, f.qualname)] = Candidate(
                    qualname=f.qualname,
                    module=mod,
                    file=path,
                    lang=lang,
                    public=f.public,
                    is_method=f.is_method,
                    dunder=f.dunder,
                    doc=f.doc,
                    signature=f.signature,
                    via_caller=True,
                    callee=hit[0],
                )
                n += 1

    cands = list(by_key.values())
    adv_tokens = _advisory_tokens(advisory_text)
    test_blob = "\n".join(test_text)
    total = sum(c.changed for c in cands) or 1
    order = sorted((c for c in cands if not c.via_caller), key=lambda c: -c.changed)
    rank = {id(c): i + 1 for i, c in enumerate(order)}
    n_changed = len(order)
    for c in cands:
        toks = set(identifier_tokens(c.qualname)) | set(
            identifier_tokens(posixpath.basename(c.file))
        )
        toks = {t for t in toks if len(t) > 2}
        c.advisory_overlap = len(toks & adv_tokens) / len(toks) if toks else 0.0
        c.name_in_advisory = _name_in(advisory_text, c)
        if len(c.name) >= 3:
            c.test_refs = len(re.findall(rf"\b{re.escape(c.name)}\b", test_blob))
        c.share = c.changed / total
        c.size_rank = rank.get(id(c), n_changed + 1)
        c.n_changed = n_changed
    cs.candidates = cands
    return cs


def log1p(x: float) -> float:
    return math.log1p(max(0.0, x))
