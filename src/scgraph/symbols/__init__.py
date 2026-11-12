"""Vulnerable-symbol inference: which function does an advisory actually concern?

Function-level reachability needs the name of the vulnerable function. The Go vulnerability
database publishes it; for PyPI, Maven, Cargo and npm advisories it is almost always missing
(0% of the PyPI, Maven and Cargo records in the local OSV snapshot). This package recovers it,
at *build* time, so that a scan still makes zero model calls.

Two engines, one verifier:

  Engine A  (``fixcommit``)  the advisory links a fix commit or pull request. The diff is
            mapped to the functions it changes (``code``, ``diff``), the callers of those
            functions are added (a vulnerable function is often the public caller, not the
            patched helper), and the candidates are ranked (``rank``). An LLM chooses among
            the top candidates only when the ranker is unsure (``select``).
  Engine B  (``retrieve``)   no fix link. The functions of the affected release are indexed
            and the advisory text is the query (BM25 over identifiers and docstrings). The
            release diff between the last affected and the first fixed version is a second,
            model-free signal. An LLM re-ranks the short list and may answer "none".
  Verifier  (``verify``)     the chosen symbol must exist in the affected release and must be
            changed, removed, or calling something changed in the fixed release. Anything
            that fails abstains.

The LLM is never asked an open question. It picks an id from a list the code built, it must
cite the evidence it used, and its answer is checked against released source before it is
recorded. Every record names the method, the model, and the hash of the prompt.
"""

from __future__ import annotations
