# Product requirements

This page states what scgraph must do, for whom, and how we know that it works. It follows the
ASD-STE100 rules for Simplified Technical English.

## Problem

A developer runs `npm install` and gets 1,200 packages. A scanner reports 47 findings. Most
findings are not actionable. Then a new vulnerability becomes public. The team must answer
three questions fast:

1. Are we exposed?
2. Through which dependency path?
3. What is the safe fix?

A flat list of package names cannot answer these questions. A path through a graph can.

## Users

| User | Need |
|---|---|
| Developer | Know which alerts need action, and the smallest safe fix |
| Security engineer | Prove exposure, or prove its absence, across many repositories |
| Maintainer of a CI pipeline | Block new risk in a pull request, not old risk |
| AI coding agent | Check a package before it installs it |
| Auditor | Replay an answer and verify that nobody changed it |

## Goals

1. **Prove each alert with a path.** Every alert shows the dependency path from the project to
   the package. A finding with no proof is an explicit abstention with a reason.
2. **Build the graph with zero language-model calls.** Every edge is a field that someone
   already published.
3. **Answer "do we call the vulnerable function?"** for Python and npm, where advisories do not
   name the function. A scan makes zero model calls.
4. **Use a language model only where it adds evidence.** A model chooses from a list that code
   built. It must quote evidence. A verifier checks its answer against released source.
5. **Keep every answer auditable.** Claims are in a hash-chained ledger. Datasets are signed.
6. **Work on a laptop and in CI.** No server and no account.

## Non-goals

- scgraph does not claim zero false negatives. It claims provenance: each alert has a path.
- scgraph does not hide an alert. A reachability verdict orders the queue. It never closes an alert.
- scgraph does not replace a code scanner. It reads dependencies, not your own code.
- scgraph does not send data to any service, except public advisory and registry lookups.
- scgraph does not open pull requests in other projects.

## Features and status

| Feature | Command | Status |
|---|---|---|
| Scan lockfiles, 15 formats, with proof paths | `scgraph scan` | Done |
| Pull-request review (only new alerts) | `scgraph diff` | Done |
| Guard installs by people and agents | `scgraph check`, `hook`, `mcp` | Done |
| Scan history and receipts | `scgraph scan --history` | Done |
| Audit agent and IDE configuration | `scgraph audit` | Done |
| Vulnerable function, Python, npm, Go | `scgraph scan --reachability` | Done |
| Transitive reachability, Python and npm | `scgraph scan --deep` | Done |
| Symbol claims in the ledger | `scgraph symbols ledger` | Done |
| Signed datasets | `scgraph symbols verify` | Done |
| OSV patch export | `scgraph symbols export` | Done |
| Grounded questions | `scgraph ask` | Done |
| Weekly dataset refresh | GitHub workflow | Done |
| Code-search records for npm | `make symbols-refresh` | Open: needs the daily LLM budget |
| Scan-side support for Maven and Cargo | | Not planned (see [ISSUES.md](ISSUES.md)) |

## Success measures

| Measure | Result |
|---|---|
| Graph size, 8 ecosystems | 82.8M edges |
| Load the graph store | 0.020 s (67x faster than before) |
| Agreement with `osv-scanner` on 150 lockfiles | 96.9% |
| Real project, 20 transitive alerts answered | 12 of 20 (0 before) |
| Functions that ran in a dependency, found by `--deep` | 95.4% of 501 |
| Vulnerable function ranked first, 188 held-out Go advisories | 69.7% (58.5% baseline) |
| LLM calls per scan | 0 |

Sources: [PERFORMANCE.md](PERFORMANCE.md), [SYMBOLS.md](SYMBOLS.md), `results/metrics/`.

## Constraints

- Python 3.11 or later. The core needs NumPy, PyArrow, SciPy and scikit-learn only.
- npm and TypeScript support needs the optional extra `scgraph-cli[symbols-js]`.
- Signing needs the optional extra `scgraph-cli[sign]`.
- The LLM stage must work on a free tier: 50 requests a day. See [SYMBOLS.md](SYMBOLS.md).
