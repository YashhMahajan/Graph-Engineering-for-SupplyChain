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

`scgraph scan [PATH ...]` takes a lockfile or a directory. In a directory it finds every lockfile
and skips `node_modules`, `.venv`, `vendor`, `target` and hidden directories. The lockfile formats
are in [DATA-SOURCES.md](DATA-SOURCES.md).

1. Parse the lockfile into a graph. The root has an edge to each direct dependency.
2. Ask OSV which versions have advisories (`MAL-` records are malware). Merge records for the
   same issue (GHSA, PYSEC, CVE) into one finding.
3. Find the shortest path from the root to each finding. A production path wins over a dev path.
4. Run the gates. The first gate that stops a finding gives the reason: `withdrawn`, `path`,
   `scope` (dev only, malware does not stop), `severity` (below `--min-severity`, malware and KEV
   do not stop), `ignored` (entry in `.scgraph-ignore` that has not expired).
5. Rank the alerts: P0 malicious, P1 exploited (CISA KEV), P2 critical (CVSS 9.0 or more, or
   EPSS 0.1 or more), P3 high (CVSS 7.0 or more), P4 other.
6. Find the smallest safe upgrade. For npm, also the smallest bump of a direct dependency that
   removes the vulnerable child.

| Option | Effect |
|---|---|
| `-f, --format` | `text` (default), `json`, `sarif`, `markdown`, `openvex`, `html` |
| `-o, --output FILE` | Write the report to a file |
| `--fail-on LEVEL` | Exit 1 at this priority or worse: `P0` to `P4`, `any` (default), `never` |
| `--min-severity N`, `--include-dev` | CVSS floor. Alert on dev-only dependencies. |
| `--advisory ID` | Incident mode: report only this advisory (repeat for a list) |
| `--ignore-file FILE` | Ignore list. Default `.scgraph-ignore`. `until=YYYY-MM-DD` ends an entry. |
| `--offline DIR` | Use OSV dumps from `scgraph fetch-osv --dir DIR`. `SCGRAPH_OSV_DIR` also serves `check`, `hook` and `mcp`. |
| `--no-signals`, `--no-registry` | Skip CISA KEV and EPSS. Skip registry data for the bump. |
| `--imports` | Hint whether your source imports each dependency (not proof) |
| `--reachability`, `--deep` | Check whether your code calls the vulnerable function. `--deep` adds transitive dependencies (network). |
| `--history DIR` | Record the scan in a hash-chained ledger |
| `--vex FILE` | Use `not_affected` statements from a supplier |
| `-v` | Show each abstention |

Exit codes: `0` no alert at the `--fail-on` level, `1` alerts, `2` error. A new unsupported
format is refused with a message and never read wrongly (pnpm v5 and older, `bun.lockb`).

### Other commands

| Command | Use |
|---|---|
| `scgraph diff --base REF` | Scan each lockfile at `REF` and in the working tree. Report only new alerts, resolved alerts and the package changes behind them. The exit code counts new alerts only. The Markdown output starts with `<!-- scgraph-diff -->` so CI edits one comment. Every string from the lockfile is neutralized, because the pull request author controls it. |
| `scgraph check ECOSYSTEM PKG[@VER] ...` | Before you add a dependency: `ALLOW` (exit 0), `WARN` (1), `BLOCK` (2). |
| `scgraph hook claude-code` | Claude Code `PreToolUse` hook. It reads each shell command that installs or runs a package. `BLOCK` denies it. `WARN` asks you. |
| `scgraph mcp` | MCP server: `check_package`, `scan_lockfile`, `explain_advisory`. |
| `scgraph audit` | Read agent and IDE configuration for code that runs on its own, unpinned launchers and `curl \| sh`. |
| `scgraph history DIR --advisory ID` | First exposure, fix and regression from the ledger. `--receipt` and `--check` verify an answer. |
| `scgraph ask "question" [PATH]` | Answer about the scan. Each sentence has a citation. No model. |

`check` blocks a name that is not in the registry (slopsquatting) and a known malicious or missing
version. It warns for a release younger than `--cooldown` hours (default 48), a package younger
than 30 days, a name one edit from a popular package, install scripts, a PyPI version with no
wheel, a deprecated or yanked version, known vulnerabilities, and a lookup that failed
(`unverified`, never `allow`). For npm it also compares a release with the one before it
(last 14 days only). Each signal is a warning, never a block: `publisher_changed`,
`maintainer_added`, `provenance_dropped`, `install_script_added`, `backport_published`,
`publish_burst` (5 versions in 15 minutes).

CI: the GitHub Action `YashhMahajan/Graph-Engineering-for-SupplyChain@v1.4.0` takes `fail-on`,
`reachability` and `deep`, uploads SARIF and writes a summary. For pull requests add a job with
`mode: diff`. Use `pull_request`, not `pull_request_target`. Never run fork code with a write
token. pre-commit: hook id `scgraph-scan` runs only when a lockfile changes.

Python API: `from scgraph.scan import scan, Policy`.

## Symbols: the vulnerable function

`govulncheck` can say "your code does not call the vulnerable function" because the Go database
names it. In the OSV snapshot used here, 0% of the PyPI, Maven and Cargo records do. `symbols/`
recovers the function at build time, checks it against released source, follows it through the
dependency path and ships the result as a data file. A scan reads that file. A scan makes **no
model call**.

```
OSV record
  fix link?  yes -> Engine A: fix diff -> changed functions and callers -> ranker
             no  -> Engine B: search the affected release + release diff
  LLM chooses among the top candidates only if the ranker is unsure
  Verifier: the symbol exists in the affected release, and it is removed, changed, or calls
            something that changed in the fixed release. Every affected range is tried.
  Entry points: public functions of the release that reach the symbol
  Record -> data/<ecosystem>.jsonl + signed manifest -> ledger claim
scan time (offline, no model): project source -> reachable | class_used | not_called
--deep: walk the dependency path backwards through released source
```

| Step | Module | Model? |
|---|---|---|
| Fix links, diff, cached HTTP | `fetch.py`, `diff.py` | no |
| Function spans (Python, Go, JS, TS) | `code.py`, `js.py` | no |
| Candidates and ranking (hand-set weights) | `candidates.py`, `rank.py` | no |
| Choice among the top candidates | `select.py`, `llm.py` | yes, only if unsure |
| Search when there is no fix link | `retrieve.py` | LLM re-ranks a short list |
| Released source: PyPI, Go, npm | `source.py`, `npm.py` | no |
| Verifier, entry points | `verify.py`, `entry.py` | no |
| Transitive reachability | `transitive.py`, `deep.py` | no |
| Dataset, signature, ledger, export | `dataset.py`, `signing.py`, `claims.py`, `export.py` | no |

`scgraph symbols` has the subcommands `infer`, `show`, `budget`, `ledger`, `verify`, `sign` and
`export`.

**Verdicts.** `reachable`: your source references a vulnerable function or an entry point that
reaches it. `class_used`: it is a method and your source references its class. `not_called`: the
names are known and your source references none. `not_analyzed`: unsupported ecosystem, no names,
or a transitive package without `--deep`. A verdict marked `(inferred)` comes from the dataset.
A verdict **never closes an alert** and never changes the exit code. A call through `getattr`,
`eval`, a plugin registry or a wrapper is not seen. Source is read with `ast` (Python),
tree-sitter (JS and TS, extra `symbols-js`) or a pattern match (Go). An alias resolves.
`--imports` is weaker: a package used through configuration can show `not imported`.

**Rules for the language model.** It never names a function. It answers with an option id from a
list that code built, or `none`. It must quote one line of the excerpt, and code checks the quote.
The verifier checks the choice against released source. If it fails, the next candidate is tried.
Each record keeps the model, the prompt hash and the confidence. A code-search record is kept
only when the model confirmed it: search alone is right less than half the time.

**Transitive reachability (`--deep`).** Your project reaches the function in `Dn` through
`D0 -> ... -> Dn`, and your code references only `D0`. scgraph walks the call graph backwards one
package at a time through released source (shortest path only, so `not_called` means "not through
this path"). Five mechanisms find calls that a name-based graph misses: resolved references with
re-exports, dunders and properties through their class, functions read as values, code that runs
at import, and `getattr(self, "visit_" + name)` dispatch.

**The free-tier LLM client (`llm.py`).** One OpenRouter key gives 50 free requests a day. The
client caches each answer by advisory, splits a failed batch in half, asks about the most
downloaded packages first, tries models in the order of `SCGRAPH_LLM_MODELS`, skips for 24 hours a
model that refuses the key (HTTP 403), waits out a per-minute limit, stops at the daily limit and
keeps every answer. `--llm-cache-only` cannot send a request. `ernie-5.5-flash-preview` must
reason and loops at temperature 0, so the client samples at 0.6.

**Trust.** The ledger stores a claim `advisory -> symbol` under the advisory id and each alias,
with confidence and a source string. It is hash-chained. A better inference retracts a claim and
earlier views keep it. The manifest has the SHA-256 of the data and an Ed25519 signature
(`signing.pub` in the repository, the private key outside it, extra `scgraph-cli[sign]`).
`scgraph symbols export` writes one OSV patch per advisory
(`affected[].ecosystem_specific.affected_functions`, provenance in `database_specific.scgraph`).
scgraph sends nothing anywhere.

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
