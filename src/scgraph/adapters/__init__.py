"""Domain adapters: map a domain's records onto ``scgraph.core``.

    software   the open-source dependency graph (packages, versions, OSV advisories)

Writing an adapter for another domain means three things: choose node types and stable
keys, choose relations and what each edge's confidence / validity / source mean, and
express the domain's alert rules as ``scgraph.core.Gate`` predicates.
"""

from . import software

__all__ = ["software"]
