# Vulnerable functions and reachability

This page describes how scgraph finds the vulnerable function of an advisory and checks whether
your code reaches it. It follows the ASD-STE100 rules for Simplified Technical English.

## The problem

`govulncheck` can say "your code does not call the vulnerable function", because the Go
vulnerability database names that function. Advisories for PyPI, npm, Maven and Cargo almost never
name it. In the OSV snapshot used here, 0% of the PyPI, Maven and Cargo records do. Every scanner
then falls back to "the package is present".

scgraph recovers the function at **build time**. It checks the function against released source,
follows it through the dependency path, and ships the result as a data file. A scan reads that file.
A scan makes **no model call**.

## Commands

```bash
scgraph symbols infer GHSA-j8r2-6x86-q33q     # one advisory, end to end (PyPI, npm or Go)
scgraph symbols show  GHSA-j8r2-6x86-q33q     # look it up in the shipped dataset
scgraph symbols budget                        # today's LLM budget
scgraph symbols ledger DIR [--advisory ID]    # record claims in the ledger, or read them
scgraph symbols verify                        # check the signatures of the shipped datasets
scgraph symbols export OUT                    # datasets, signatures, one OSV patch per advisory
scgraph ask "why am I exposed to CVE-X?" .    # an answer with a citation on every sentence
scgraph scan . --reachability                 # use the datasets in a scan
scgraph scan . --deep                         # also transitive dependencies
```

Example output:

```text
GHSA-j8r2-6x86-q33q  requests (affected 2.30.0, fixed 2.31.0)
  vulnerable: requests.sessions.SessionRedirectMixin.rebuild_proxies
  method:     fix-diff   confidence 0.999   verifier: verified
  evidence:   https://github.com/psf/requests/commit/74ea7cf7a6a2...
  entry points: requests.Session.send, requests.Session.request, requests.Session.get, ...
```

## How it works

```
OSV record
  fix link?  yes -> Engine A: fix diff -> changed functions and their callers -> ranker
             no  -> Engine B: search the affected release + release diff
  LLM chooses among the top candidates only if the ranker is unsure
  Verifier: the symbol exists in the affected release, and it is removed, changed, or calls
            something that changed in the fixed release. Every affected range is tried.
  Entry points: public functions of the release that reach the symbol
  Record -> data/<ecosystem>.jsonl, manifest, signature -> ledger claim
```

| Step | Module | Model? |
|---|---|---|
| Fix links, diff, files, cached HTTP | `fetch.py`, `diff.py` | no |
| Function spans (Python, Go, JavaScript, TypeScript) | `code.py`, `js.py` | no |
| Candidates: changed functions and callers | `candidates.py` | no |
| Ranking | `rank.py` | no (hand-set weights) |
| Choice among the top candidates | `select.py`, `llm.py` | yes, only if the ranker is unsure |
| Search, when there is no fix link | `retrieve.py` | no (the LLM re-ranks the short list) |
| Released source: PyPI, Go, npm | `source.py`, `npm.py` | no |
| Verifier | `verify.py` | no |
| Entry points and names | `entry.py`, `npm.py` | no |
| Transitive reachability | `transitive.py`, `deep.py` | no |
| Dataset, signature, ledger, export | `dataset.py`, `signing.py`, `claims.py`, `export.py` | no |

### Rules for the language model

- The model never names a function. It answers with an option id from a list that code built, or
  `none`.
- The model must quote one line of the excerpt as evidence. Code checks the quote.
- The verifier checks the choice against released source. If the check fails, the next candidate
  is tried.
- Each record keeps the model, the prompt hash and the confidence.
- A code-search record is kept only when the model confirmed it. Search alone is right less than
  half the time.

### Transitive reachability (`--deep`)

The vulnerable function is in package `Dn`. Your project reaches it through
`D0 -> D1 -> ... -> Dn`. Your code references only `D0`. scgraph walks the call graph backwards,
one package at a time, through released source. It finds the public names of `D0` that lead to the
function. Five mechanisms find calls that a name-based graph misses:

1. Fully resolved references (`urllib3.PoolManager`, with re-exports)
2. Dunders and properties, reached through their class
3. Properties and functions that code reads as values
4. Code that runs when a module is imported
5. `getattr(self, "visit_" + name)` dispatch

### The free-tier LLM client

One OpenRouter key gives 50 free requests a day. The client (`llm.py`) works under that limit:

- It caches each answer by advisory, not by batch. A new batch size never repays an answer.
- It splits a failed batch in half and retries the halves.
- It asks about the most downloaded packages first.
- It tries models in the order of `SCGRAPH_LLM_MODELS`. Any failure moves to the next model. A
  model that refuses the key (HTTP 403) is skipped for 24 hours.
- It waits out a per-minute limit. It stops at the daily limit and keeps every answer.
- It reads the key's own count of used requests, and checks the budget before each request.
- A replay mode (`--llm-cache-only`) cannot send a request.

The model `ernie-5.5-flash-preview` must reason and loops at temperature 0. The client samples at
0.6. `inkling-2-small:free` answers HTTP 403 to an ordinary key, so it is not a default.

### Trust

- **Ledger.** A claim is an edge `advisory -> symbol`, stored under the advisory id and each alias.
  It has the confidence and a source string (method, evidence, verifier result, model, prompt
  hash). The ledger is hash-chained. A better inference retracts a claim. Earlier views keep it.
- **Signature.** The manifest has the SHA-256 of the data. An Ed25519 signature covers the manifest.
  The public key is `signing.pub`. The private key stays outside the repository
  (`~/.config/scgraph/signing.key`). Needs `pip install "scgraph-cli[sign]"`.
- **Export.** Each OSV patch adds `affected[].ecosystem_specific.affected_functions` and keeps the
  provenance in `database_specific.scgraph`. scgraph sends nothing anywhere.
- **`scgraph ask`.** It scans, selects the findings that the question names, and writes short
  sentences. Each sentence has a citation. No model is used.

## Measurements

Scripts are in `scripts/symbols/`. Results are in `results/metrics/`.

### Engine A: which function does the fix change? (Go, 188 held-out advisories)

The Go database has labelled symbols. The split is by time: the oldest 436 advisories train, the
newest 188 test. A missing diff or candidate counts as a miss.

| Stage | Top-1 | Top-3 | MRR |
|---|---|---|---|
| Largest change first (baseline) | 58.5% | 76.6% | 0.674 |
| **Hand-set ranker (shipped)** | **69.7%** | 78.7% | 0.741 |
| Logistic regression (trained on 436) | 70.7% | 78.7% | 0.746 |
| Hand-set ranker + LLM on the uncertain ones | 70.7% | 78.2% | 0.748 |
| Ceiling: a gold symbol is among the candidates | 80.9% | | |

- Callers matter. Changed functions alone hold a gold symbol for 78.7%. Callers raise it to 80.9%.
- The hand-set ranker ships because it won on a validation slice (MRR 0.834 against 0.822). The
  trained model is 1 point ahead on the test split. That is noise at 188 advisories. Choosing it
  now would use the test split.
- The LLM was asked about the advisories whose top-2 margin was below 0.25. The budget answered
  37 of them with the current prompts. On those, top-1 went from 56.8% to 62.2%. The LLM fixed 3
  top picks and broke 1 (McNemar p = 0.625). This is not significant. Every quote was in the
  excerpt.

### Engine B: no fix link (48 Go advisories, searched as if the link were missing)

| Stage | Top-1 | Top-3 | MRR |
|---|---|---|---|
| BM25 over the affected release | 27.1% | 47.9% | 0.389 |
| + release diff (last affected against first fixed) | **43.8%** | 52.1% | 0.493 |
| + LLM re-rank | **52.1%** | 58.3% | 0.552 |

The release diff is the strongest single signal (+16.7 points, no model). The LLM answered "none"
4 times. Each time the gold symbol was not in the list.

### Entry points (Go, 149 advisories with a readable release)

| Symbol set | Gold symbols covered | Advisories with a gold symbol |
|---|---|---|
| Top symbol only | 22.1% | 69.7% |
| Top symbol + entry points (depth 5) | **40.3%** | **77.1%** |

Precision is 58.6%. A greater depth gives more recall and less precision. Depth 5 is the default,
because a missed entry point gives a false `not_called`.

### Transitive reachability: does the analysis find what runs?

The ground truth is dynamic. Real `requests` and `flask` code ran under a profiler. Each function
that ran inside a dependency is a test: does the parent's public API reach it? A miss is a false
`not_called`. Script: `scripts/symbols/eval_transitive.py`.

| Configuration | Recall on 501 functions that ran | Functions marked reachable |
|---|---|---|
| **All five mechanisms** | **95.4%** | 81.3% |
| Without import-time code | 77.6% | 61.2% |
| Without dunders and properties | 90.2% | 72.8% |
| Without properties and callbacks read as values | 93.2% | 76.1% |
| Without resolved references | 94.4% | 79.5% |
| Without `getattr` dispatch | 95.4% | 80.8% |
| None (bare-name matching only) | 57.1% | 39.6% |

Import-time code is the largest single gain (17.8 points). `getattr` dispatch gave no gain in this
benchmark. It stays, because visitor-style code needs it, and it costs 0.4 points of reach.

Per chain: `requests -> urllib3` 100%, `flask -> werkzeug` 97.2%, `flask -> jinja2` 91.5%,
`flask -> itsdangerous` 96.6%, `flask -> jinja2 -> markupsafe` 100%.

The cost: 81% of a dependency's functions are marked reachable, and the profiler saw 5% to 53% of
them run in one scenario. Part of the difference is real reach that the scenario did not trigger.
Part is over-approximation. The verdict is sound but coarse for large dependencies.

### Shipped datasets

@@DATASETS@@

### A real project

A project pins `requests 2.25.0`. Its `urllib3 1.26.4` has 11 advisories. The project has 20
transitive alerts. Before `--deep`, all 20 were `not_analyzed`.

| Project code | Reachable | Not called | Not analyzed |
|---|---|---|---|
| Calls `requests.get(...)` | **8** | **4** | 8 |
| Declares `requests` and never uses it | 0 | **12** | 8 |

Each verdict has evidence. Example: CVE-2021-33503 (`urllib3.util.url`) is `reachable`, 2 hops, with
the fix commit `2d4a3fee6d...` as evidence. Eight alerts have no record in the dataset. All 20 stay
alerts.

## Reproduce

```bash
make symbols-eval                                          # Go evaluation, model-free
python scripts/symbols/eval_go.py --llm-cache-only         # replay paid answers, spends nothing
python scripts/symbols/build_dataset.py --ecosystem pypi --popular 5000 --fix 1500 --search 150
python scripts/symbols/build_dataset.py --ecosystem npm  --popular 3000 --fix 800 --search 100
python -m venv /tmp/evalenv && /tmp/evalenv/bin/pip install requests flask
/tmp/evalenv/bin/python scripts/symbols/trace_scenarios.py > /tmp/traces.json
python scripts/symbols/eval_transitive.py --env /tmp/evalenv --traces /tmp/traces.json --ablation
make symbols-refresh                                       # after 00:00 UTC: spends LLM requests
```

Limits and open work are in [ISSUES.md](ISSUES.md).
