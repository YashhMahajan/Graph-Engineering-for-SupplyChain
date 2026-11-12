# Architecture

This page describes how scgraph works. It follows the ASD-STE100 rules for Simplified Technical
English.

## Rules that do not change

1. **No model builds the graph.** Every edge is a field that someone published: a `package.json`
   range, a lockfile pin, or an OSV `affected` range.
2. **A scan makes no model call.** A model works at build time only. Its output is a verified,
   signed data file.
3. **A refusal is a result.** An alert has a path. Everything else is an abstention with a reason.
4. **A verdict never hides an alert.** It only orders the queue.

## Layers

```
Data          acquire, acquire_full, parse, osv       edge tables (Parquet)
Graph store   kgstore                                 CSR memmap graph, affected bitsets
Structure     graphshape, centrality, systemic,       degree law, k-core, cycles,
              community, temporal                     articulation points, PageRank
Grounding     ground, paths, ladder                   text to package, exposure paths,
                                                      the alert ladder
Remediation   remediate, report, whatif               smallest patch set, SBOM, graph edit
Scan          scan/*                                  lockfiles, guard, history, audit
Symbols       symbols/*                               vulnerable function, reachability
Core          core/*                                  typed graph, gates, ledger
Model layer   embed, reach, gnn, judge                optional, GPU: research only
```

The package imports only NumPy, PyArrow, SciPy, scikit-learn and the standard library. The model
layer imports PyTorch only when you use it.

## The graph store

`kgstore.py` keeps the graph in compressed sparse row (CSR) arrays. The process maps them
read-only. No database runs. A graph database needs a network round trip of 1 to 5 ms. A full
audit in this store takes less than that.

- Strings are one UTF-8 block plus an offset array. A string is decoded when you read it.
- No array uses pickle. A downloaded graph cannot run code. A 1.0 graph gives an error, not code.
- Loading the store takes 0.020 s. See [PERFORMANCE.md](PERFORMANCE.md).

## Version resolution

`resolve.py` changes a declared range into a concrete version. It uses the range grammar of each
ecosystem (npm: node-semver, PyPI: PEP 440, Maven: intervals). A resolved version is an edge.
The result matches deps.dev for 97.2% of the pairs that exist in the 2020 snapshot.

## The alert ladder

`ladder.py` turns a long list into a short list. Gates 1 to 6 are graph predicates. They run
before any model.

| Gate | The alert stops when |
|---|---|
| 1 | Nothing in the question matches a package or advisory |
| 2 | No resolved path reaches an affected version |
| 3 | The version at the end of the path is not affected |
| 4 | Only a yanked version is affected |
| 5 | Every advisory is withdrawn |
| 6 | No advisory existed when the shipped version was released |
| 7 | The vulnerable function is not on a call path (optional) |

Test: when the graph loses its affected packages in steps, the alert count must fall to zero
at each step. The full run gives 4,084, then 3,691, then 3,545, then 0.

## Scan

`scgraph scan` parses a lockfile into a graph. It asks OSV which versions have advisories and
merges records for the same issue (GHSA, PYSEC, CVE). It finds the shortest path from the root to
each finding, runs the gates, and ranks the alerts (P0 malicious, P1 exploited, P2 critical,
P3 high, P4 other). For npm it also finds the smallest bump of a direct dependency that removes
the vulnerable child. Usage is in [SCAN.md](SCAN.md).

## Symbols: the vulnerable function

Advisories for PyPI and npm almost never name the vulnerable function. `symbols/` recovers it at
build time. [SYMBOLS.md](SYMBOLS.md) gives the details and the measurements.

```
OSV record
  fix link?  yes -> Engine A: fix diff -> changed functions and callers -> ranker
             no  -> Engine B: search the affected release + release diff
  LLM chooses among the top candidates only if the ranker is unsure
  Verifier: the symbol exists in the affected release and changes in the fixed release
  Entry points: public functions of the release that reach it
  Record -> data/<ecosystem>.jsonl + signed manifest -> ledger claim
scan time (offline, no model): project source -> reachable | class_used | not_called
--deep: walk the dependency path backwards through released source
```

## Core engine

`scgraph.core` is the domain-neutral engine. A `TypedGraph` holds nodes and typed edges with
confidence, valid time and source. A `Ledger` records changes as hash-chained deltas. It keeps
two clocks: when a fact is true, and when we learned it. A `Receipt` binds an answer to the
ledger position, so anyone can recompute it. Scan history and symbol claims use the ledger.

## Data flow

Build time: published fields become edge tables, then the CSR store. Query time: a question is
grounded to packages, searched for exposure paths, passed through the ladder, and answered with
paths or a refusal.

## Terms

| Term | Meaning |
|---|---|
| Abstention | A finding that is not an alert, with the gate that stopped it |
| CSR | Compressed sparse row: a compact way to store a graph in arrays |
| Entry point | A public function of a package that reaches a vulnerable function |
| Exposure path | The chain of dependencies from the project to an affected package |
| Ledger | An append-only log in which each change carries the hash of the one before |
| OSV | The open vulnerability database schema and feed |
| PURL | A package URL: `pkg:npm/lodash@4.17.20` |
| Transitive dependency | A dependency of a dependency |
| VEX | A statement that says whether a product is affected by a vulnerability |

## Reproduce

| Tier | What you need | Time |
|---|---|---|
| Read only | The repository. The notebook has all outputs. | 0 |
| Smoke | Network | 3 minutes |
| Full | 25 GB download, or the 550 MB release artifacts | hours |

Smoke run:

```bash
pip install -e ".[notebook]"
python scripts/acquire_smoke.py
python scripts/run_pipeline.py --profile smoke
jupyter lab notebooks/supply_chain_graph_engineering.ipynb
```

Full run: download the release artifacts, then run `python scripts/run_evaluation.py --all`. The
model layer needs a CUDA GPU. Symbol evaluation: `make symbols-eval`. Expected values are in
`results/metrics/` and in `results/run_manifest.json`.

## Research results

The notebook `notebooks/supply_chain_graph_engineering.ipynb` is the research record. It has 11
parts, 142 cells and all outputs. Part XI covers the symbols work. Known limits of every result
are in [ISSUES.md](ISSUES.md).
