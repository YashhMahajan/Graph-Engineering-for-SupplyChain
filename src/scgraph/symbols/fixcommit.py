"""Engine A end to end: an OSV record -> fix diff -> post-fix sources -> candidates."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from .candidates import CandidateSet, build_candidates, is_code
from .fetch import Fetcher, Fix, fix_refs, get_fix

__all__ = ["EngineAResult", "advisory_text", "engine_a"]

MAX_CODE_FILES = 40


def advisory_text(record: dict) -> str:
    return f"{record.get('summary') or ''}\n{record.get('details') or ''}".strip()


@dataclass
class EngineAResult:
    fix: Fix | None
    cands: CandidateSet | None
    reason: str = ""  # why there are no candidates


def engine_a(record: dict, fetcher: Fetcher, module: str = "", workers: int = 4) -> EngineAResult:
    """Candidates from the first usable fix reference, or the reason there are none."""
    refs = fix_refs(record)
    if not refs:
        return EngineAResult(None, None, "no GitHub fix commit or pull request linked")
    text = advisory_text(record)
    last = "fix diff unavailable"
    for ref in refs[:3]:
        fix = get_fix(fetcher, ref)
        if fix is None:
            continue
        code = [f.path for f in fix.files if is_code(f.path) and not f.is_deleted]
        if not code:
            last = "the fix changes no Python or Go source outside tests"
            continue
        code = code[:MAX_CODE_FILES]
        with ThreadPoolExecutor(max_workers=workers) as ex:
            texts = list(ex.map(lambda p, fx=fix: fetcher.text(fx.raw_url(p)), code))
        sources = {p: t for p, t in zip(code, texts) if t is not None}
        cs = build_candidates(fix.files, sources, text, module=module)
        if not cs.candidates:
            last = "the fix changes no function (module-level code only)"
            continue
        return EngineAResult(fix, cs)
    return EngineAResult(None, None, last)
