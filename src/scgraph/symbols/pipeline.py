"""Advisory -> verified symbol record. Prepare (network, no model), choose (batched LLM, only
where the ranker is unsure), finalize (verifier + entry points).

The split exists for the free-tier budget: ``prepare`` runs for every advisory in parallel,
then all the uncertain ones go to the LLM together, ten or so per request, then each record is
finalized. An advisory never makes its own request.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field

from .candidates import Candidate, CandidateSet
from .entry import dotted_names, entry_points
from .fetch import Fetcher, Fix
from .fixcommit import advisory_text, engine_a
from .llm import OpenRouter
from .rank import Ranker, load_default, rank
from .retrieve import Hit, search
from .select import Choice, Option, Task, choose
from .source import (
    Release,
    brackets,
    go_release,
    go_versions,
    pypi_release,
    pypi_versions,
)
from .verify import Verdict, verify

__all__ = ["Prepared", "SymbolRecord", "finalize", "llm_rerank", "prepare", "task_for"]


@dataclass
class SymbolRecord:
    id: str
    aliases: list[str]
    ecosystem: str
    package: str
    affected_version: str
    fixed_version: str
    symbol: str  # dotted: module.qualname (Python) / package.qualname (Go)
    module: str
    qualname: str
    entry_points: list[str]  # dotted names project code may reference, aliases included
    method: str  # fix-diff | fix-diff+llm | search | search+llm
    confidence: float
    verified: str  # the verifier's status
    verify_detail: str
    evidence: dict = field(default_factory=dict)
    llm: dict | None = None
    created: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Prepared:
    record: dict
    ecosystem: str
    package: str
    mode: str  # "fix" | "search" | "none"
    reason: str = ""
    fix: Fix | None = None
    cset: CandidateSet | None = None
    ranked: list[Candidate] = field(default_factory=list)
    hits: list[Hit] = field(default_factory=list)
    affected: Release | None = None
    fixed: Release | None = None
    versions: tuple[str, str] = ("", "")
    alt_pairs: list[tuple[str, str]] = field(default_factory=list)  # other affected ranges
    loader: Callable[[tuple[str, str]], tuple[Release | None, Release | None]] | None = None

    @property
    def id(self) -> str:
        return self.record["id"]

    def margin(self) -> float:
        if self.mode == "fix":
            s = [c.score for c in self.ranked]
        else:
            s = [h.score for h in self.hits]
        if len(s) < 2:
            return 1.0
        return s[0] - s[1]


def _plan(
    f: Fetcher, record: dict, eco: str, pkg: str
) -> tuple[
    Callable[[tuple[str, str]], tuple[Release | None, Release | None]], list[tuple[str, str]]
]:
    """How to read the releases of each (last affected, first fixed) pair, and the pairs."""
    get: Callable[[Fetcher, str, str], Release | None]
    if eco == "PyPI":
        pairs = brackets(record, eco, pkg, pypi_versions(f, pkg))
        get = pypi_release
    elif eco == "npm":
        from .npm import npm_release, npm_versions

        pairs = brackets(record, eco, pkg, npm_versions(f, pkg))
        get = npm_release
    else:
        pairs = brackets(record, eco, pkg, go_versions(f, pkg))
        get = go_release

    def load(pair: tuple[str, str]) -> tuple[Release | None, Release | None]:
        last, fixed = pair
        return (get(f, pkg, last) if last else None, get(f, pkg, fixed) if fixed else None)

    return load, pairs or [("", "")]


def prepare(
    record: dict,
    ecosystem: str,
    package: str,
    fetcher: Fetcher,
    ranker: Ranker | None = None,
    search_k: int = 8,
) -> Prepared:
    """Everything that needs the network and no model."""
    p = Prepared(record, ecosystem, package, "none")
    module = package if ecosystem == "Go" else ""
    a = engine_a(record, fetcher, module=module, workers=2)
    want = {"PyPI": "python", "npm": "javascript"}.get(ecosystem, "go")
    if a.cands is not None:  # an npm advisory can fix Go or Python code in the same repository
        a.cands.candidates = [c for c in a.cands.candidates if c.lang == want]
        if not a.cands.candidates:
            a.cands = None
            a.reason = f"the fix changes no {want} function"
    load, pairs = _plan(fetcher, record, ecosystem, package)
    p.versions = pairs[0]
    p.alt_pairs, p.loader = pairs[1:], load
    p.affected, p.fixed = load(pairs[0])
    if a.cands is not None:
        p.mode, p.fix, p.cset = "fix", a.fix, a.cands
        p.ranked = rank(a.cands.candidates, ranker or load_default())
        return p
    if p.affected is not None:
        p.hits, _ = search(advisory_text(record), p.affected, p.fixed, k=search_k)
        if p.hits:
            p.mode = "search"
            return p
        p.reason = f"{a.reason}; the search found no function"
        return p
    p.reason = f"{a.reason}; the affected release could not be read"
    return p


def _facts(c: Candidate) -> str:
    bits = [f"+{c.added} -{c.removed}", "public" if c.public else "private"]
    if c.new_function:
        bits.append("added by the fix")
    if c.via_caller:
        bits.append(f"unchanged, calls changed {c.callee}")
    if c.test_refs:
        bits.append(f"named {c.test_refs}x in the fix's tests")
    return ", ".join(bits)


def task_for(p: Prepared, top: int = 6) -> Task | None:
    if p.mode == "fix" and p.cset is not None:
        opts = []
        for i, c in enumerate(p.ranked[:top], 1):
            ex = p.cset.excerpt(c) if not c.via_caller else f"{c.signature}\n(calls {c.callee})"
            opts.append(Option(f"C{i}", c.symbol, _facts(c), ex))
        return Task(p.id, p.package, advisory_text(p.record), opts, mode="fix")
    if p.mode == "search" and p.affected is not None:
        opts = [
            Option(
                f"C{i}",
                h.symbol,
                f"search rank {h.rank}, {'changed' if h.changed else 'unchanged'} in the fixed "
                f"release, {'public' if h.func.public else 'private'}",
                h.excerpt(p.affected),
            )
            for i, h in enumerate(p.hits, 1)
        ]
        return Task(p.id, p.package, advisory_text(p.record), opts, mode="search")
    return None


def llm_rerank(
    client: OpenRouter,
    items: Sequence[tuple[dict, CandidateSet, list[Candidate], str]],
    top: int = 6,
    uncertain: float = 0.25,
    batch_size: int = 10,
    max_requests: int | None = None,
    log=None,
) -> tuple[dict[str, Choice], dict, set[str]]:
    """Ask the LLM about the fix-diff advisories whose ranker margin is below ``uncertain``."""
    preps = []
    for record, cs, ranked, module in items:
        p = Prepared(
            record, "Go" if module else "PyPI", module or "", "fix", cset=cs, ranked=ranked
        )
        if len(ranked) >= 2 and p.margin() < uncertain:
            preps.append(p)
    tasks = [t for t in (task_for(p, top) for p in preps) if t is not None]
    choices, report = choose(
        client, tasks, batch_size=batch_size, max_requests=max_requests, log=log
    )
    return choices, report, {t.tid for t in tasks}


def _aliases(record: dict) -> list[str]:
    return sorted({*record.get("aliases", []), *record.get("upstream", [])} - {record["id"]})


def finalize(
    p: Prepared, choice: Choice | None = None, min_llm_confidence: float = 0.0
) -> SymbolRecord | None:
    """Verify the best candidate (the LLM's choice when there is one) and add entry points.
    Falls through the ranked list until one verifies; returns None when nothing does."""
    if p.mode == "none":
        return None
    order: list[tuple[str, str, float, dict]] = []  # module, qualname, confidence, evidence
    if p.mode == "fix":
        assert p.fix is not None and p.cset is not None
        for c in p.ranked:
            ev = {
                "fix": p.fix.ref.url,
                "revision": p.fix.sha,
                "file": c.file,
                "changed_lines": c.changed,
                "via_caller": c.via_caller,
            }
            order.append((c.module, c.qualname, c.score, ev))
    else:
        for h in p.hits:
            ev = {"search_rank": h.rank, "changed_in_fixed_release": h.changed, "file": h.path}
            order.append((h.module, h.func.qualname, min(1.0, h.score / 2), ev))
    llm: dict | None = None
    if choice is not None and choice.symbol and choice.confidence >= min_llm_confidence:
        front = [o for s in choice.ranked for o in order if f"{o[0]}.{o[1]}" == s]
        order = front + [o for o in order if o not in front]
        llm = {
            "model": choice.model,
            "prompt_hash": choice.prompt_hash,
            "confidence": choice.confidence,
            "evidence": choice.evidence,
            "evidence_found": choice.evidence_found,
            "reason": choice.reason,
        }
    elif choice is not None and choice.symbol is None:
        llm = {"model": choice.model, "prompt_hash": choice.prompt_hash, "answer": "none"}
        if p.mode == "search":  # nothing in the short list matched: abstain
            return None

    def attempt(
        aff: Release | None, fixed: Release | None, versions: tuple[str, str]
    ) -> SymbolRecord | None:
        for i, (mod, qn, conf, ev) in enumerate(order[:6]):
            v: Verdict = verify(aff, fixed, mod, qn)
            if not v.ok:
                continue
            if aff is not None:  # use the release's own module id (a repo path may differ)
                loc = aff.locate(mod, qn)
                if loc is not None:
                    mod = loc[0]
            eps: list[str] = []
            if aff is not None:
                eps = dotted_names(aff, entry_points(aff, mod, qn))
            used_llm = llm is not None and "answer" not in llm and i == 0
            method = ("fix-diff" if p.mode == "fix" else "search") + ("+llm" if used_llm else "")
            conf_out = llm["confidence"] if used_llm and llm else conf
            return SymbolRecord(
                id=p.id,
                aliases=_aliases(p.record),
                ecosystem=p.ecosystem,
                package=p.package,
                affected_version=versions[0],
                fixed_version=versions[1],
                symbol=f"{mod}.{qn}" if mod else qn,
                module=mod,
                qualname=qn,
                entry_points=eps,
                method=method,
                confidence=round(float(conf_out), 3),
                verified=v.status,
                verify_detail=v.detail,
                evidence=ev,
                llm=llm if used_llm else None,
                created=time.strftime("%Y-%m-%d"),
            )
        return None

    rec = attempt(p.affected, p.fixed, p.versions)
    if rec is None and p.mode == "fix" and p.loader is not None:
        for pair in p.alt_pairs[:3]:  # a fix commit belongs to one maintained line only
            aff, fixed = p.loader(pair)
            rec = attempt(aff, fixed, pair)
            if rec is not None:
                break
    return rec
