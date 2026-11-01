# The core engine: `scgraph.core`

`scgraph` answers one question for software: *are we exposed, by what path, and what
is the fix?* The method underneath is not specific to software. `scgraph.core` is that
method with the domain taken out, so you can point it at any graph where a claim has to
be backed by a path: vendor networks, service dependencies, data lineage, ownership
chains, infrastructure.

It has four parts. None of them know what a package is.

| module | gives you |
|---|---|
| `graph`  | `TypedGraph`: typed nodes, named relations, a CSR index in both directions, and per-edge **confidence**, **validity window** and **source**. Content-addressed (`fingerprint()`), memory-mapped, no pickle. |
| `paths`  | `find_paths`: a BFS whose output is evidence. Every hop names its edge; a path's confidence is the product of its edges' confidences. It reports `truncated` instead of passing off "stopped looking" as "no path". |
| `gates`  | `Ladder`: raise an alert only when evidence survives every gate, and otherwise abstain, naming the gate that emptied the evidence. |
| `ledger` | `Ledger`: a bitemporal, hash-chained change log over a base snapshot. As-of views, compaction, and **receipts** that let anyone recompute and verify an answer. |

## 1. Build a graph

```python
from scgraph.core import TypedGraph, EdgeBatch

g = TypedGraph.build(
    nodes=[("svc:checkout", "service"), ("svc:payments", "service"), ("db:ledger", "datastore")],
    edges={
        "calls": EdgeBatch(
            src=[0, 1],
            dst=[1, 2],
            confidence=[1.0, 0.7],  # 0.7: inferred from traces, not declared
            valid_from=[0, 1_700_000_000],  # epoch seconds; omit for "always"
            source=["manifest", "otel-traces"],
        )
    },
)
g.save("graphs/prod")  # returns the fingerprint
g = TypedGraph.load("graphs/prod")  # mmap; verifies the fingerprint
```

What edge attributes mean is up to you, but each has a single job:

- **confidence**: 1.0 for something someone published (a lockfile pin, a contract, a
  registry entry), and lower for something you inferred. It is the probability the edge
  is real, so calibrate it.
- **valid_from / valid_to**: when the edge is true in the world. `valid_to` is exclusive.
- **source**: where the edge came from. It ends up in every evidence record.

## 2. Find evidence and decide

```python
from scgraph.core import find_paths, Ladder, Gate, min_confidence_gate

target = g.node("db:ledger")
paths, truncated = find_paths(
    g, [g.node("svc:checkout")], ["calls"], is_target=lambda v: v == target, as_of=1_750_000_000
)

ladder = Ladder(
    [
        Gate("too_deep", "only paths deeper than 5 hops", lambda p, ctx: p.depth <= 5),
        min_confidence_gate(0.8),
    ]
)
v = ladder.evaluate(paths)
v.alert, v.reason  # (False, "below_confidence_floor"): the only path is 0.7
paths[0].evidence(g)  # one provenance record per hop
```

A gate never raises an exception and never silently drops evidence. Either evidence
survives every gate, or the verdict names the gate that emptied it and keeps the rejected
evidence for review.

## 3. Change over time, with receipts

```python
from scgraph.core import Ledger

L = Ledger.create("ledgers/prod", g, recorded_at="2026-01-01")
L.add_edge(
    "calls",
    "svc:checkout",
    "db:ledger",
    valid_from="2026-02-01",
    source="manifest",
    recorded_at="2026-02-03",
)
L.retire_edge("calls", "svc:payments", "db:ledger", valid_to="2026-03-01", recorded_at="2026-03-02")
L.retract_edge(
    "calls", "svc:checkout", "svc:payments", reason="bad parse", recorded_at="2026-03-05"
)


def exposed(g, as_of):  # any pure function of (graph, valid time)
    ...


result, receipt = L.answer(
    {"q": "exposed", "root": "svc:checkout"}, exposed, valid_at="2026-02-15", known_at="2026-03-01"
)
L.check(receipt, exposed)  # True: recomputed from the ledger, hash matches
```

There are two clocks:

- **valid time** (`valid_at`): when the fact holds in the world.
- **recorded time** (`known_at`): when the ledger learned it.

"Were we exposed on Feb 15?" and "what did we *know* on Mar 1 about Feb 15?" are
different questions, and auditors ask the second one. A later `retract_edge` changes
answers for later `known_at` values only. Every earlier answer, and every receipt issued
for one, stays reproducible.

Integrity guarantees:

- Each delta hashes the previous one. Editing, reordering or deleting a line makes
  `verify()` fail.
- Writers take a file lock and re-read the head before appending, so two processes cannot
  fork the chain.
- `compact()` folds deltas into a new base snapshot so views stay fast. It keeps the log,
  so history and old receipts remain valid. Receipts name the *genesis* fingerprint, so
  compaction never changes an answer's identity.
- The chain shows edits to history, but it does not stop someone who can rewrite the
  *whole* log and snapshot from forging a consistent new one. For an external guarantee,
  publish `Ledger.head` (seq and hash) somewhere you do not control, such as a signed
  commit, a transparency log or a counterparty, and compare receipts against it.
- Snapshots load with `allow_pickle=False` and are checked against their fingerprint.

Cost: building a view costs one verified snapshot load, plus a rebuild of only the
relations the deltas touched; untouched relations are reused. On 1M nodes and 5M edges,
a view with 1,000 deltas builds in about 2 s, most of it fingerprint verification, and
views are cached per `(base, head)`. Compact periodically, for example nightly, to keep
the replay short.

## 4. Software, as an adapter

`scgraph.adapters.software` maps a built `KGStore` onto the core:

```python
from scgraph.kgstore import KGStore
from scgraph.adapters import software

g, advisories = software.from_kgstore(KGStore("data/graph"))
report = software.audit(
    g, advisories, "ver:maven/com.example:app@1.0.0", as_of="2021-12-10", min_severity=7.0
)
```

Each `affects` edge is valid from its advisory's publish date, so "was this knowable on
date D" is just `as_of=D`, the same mechanism every domain uses. The unit tests check
that this adapter finds exactly the exposures the original `scgraph.paths` finds.

## Writing your own adapter

1. **Nodes.** Pick types and *stable* external keys, because keys are what deltas and
   receipts refer to.
2. **Relations.** For each relation, decide what confidence, validity and source mean,
   and write that down.
3. **Rules.** Express your alert policy as `Gate` predicates over evidence paths. Keep
   them pure, so a verdict can be recomputed from its receipt.
