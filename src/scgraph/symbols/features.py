"""Switches for the call-graph mechanisms, so an ablation can measure what each one buys.

All are on in normal use. ``scripts/symbols/eval_transitive.py --ablation`` turns them off one
at a time. They are read at call time, and a ``Release`` caches its indexes, so build a fresh
``Release`` after changing one.
"""

from __future__ import annotations

ON: dict[str, bool] = {
    "refs": True,  # match fully resolved dotted references (urllib3.PoolManager)
    "implicit": True,  # dunders and properties are reached through their class
    "dyn": True,  # getattr(self, "visit_" + x) dispatch reaches the visit_* methods
    "loads": True,  # properties read and same-module functions passed as values
    "module": True,  # code that runs when a module is imported
}
