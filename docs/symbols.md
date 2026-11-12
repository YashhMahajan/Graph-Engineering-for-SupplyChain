# Vulnerable-symbol inference and transitive reachability

**Which function does an advisory actually concern, and does your code reach it?**
`govulncheck` can say "your code does not call the vulnerable function" because the Go
vulnerability database names that function. For PyPI, npm, Maven and Cargo advisories the name
is missing (0% of the PyPI, Maven and Cargo records in the local OSV snapshot), so every scanner
falls back to "the package is present". `scgraph.symbols` recovers the name at **build time**,
checks it against released source, follows it through the dependency path, and ships the result
as a data file. A scan reads that file offline and makes **zero model calls**.

```bash
scgraph symbols infer GHSA-j8r2-6x86-q33q      # one advisory, end to end (PyPI, npm or Go)
scgraph symbols show  GHSA-j8r2-6x86-q33q      # look it up in the shipped dataset
scgraph symbols budget                         # today's free-tier LLM budget
scgraph scan . --reachability                  # direct dependencies, Python and npm
scgraph scan . --deep                          # + transitive Python dependencies
```

```text
GHSA-j8r2-6x86-q33q  requests (affected 2.30.0, fixed 2.31.0)
  vulnerable: requests.sessions.SessionRedirectMixin.rebuild_proxies
  method:     fix-diff   confidence 0.999   verifier: verified
              changed in 2.31.0
  evidence:   https://github.com/psf/requests/commit/74ea7cf7a6a2...  (requests/sessions.py, 4 lines)
  entry points: requests.sessions.SessionRedirectMixin.resolve_redirects, requests.Session.send,
                requests.Session.request, requests.Session.get, ... (+12 more)
```

## How it works

```
OSV record ──► fix link? ──yes──► Engine A: fix diff ─► changed functions + their callers
                  │                                   ─► ranker (model-free features)
                  no                                  ─► LLM only if the ranker is unsure
                  ▼
            Engine B: search the affected release (BM25 over identifiers and docstrings)
                      + release diff (last affected vs first fixed)  ─► LLM re-rank, may say "none"
                  │
                  ▼
            Verifier (no model): present in the affected release, and removed / changed /
                      calling something changed in the fixed release; every affected range is
                      tried, because a fix commit belongs to one maintained line  ─► else abstain
                  │
                  ▼
            Entry points: public functions of the release that reach it (+ re-export aliases)
                  │
                  ▼
            SymbolRecord ─► src/scgraph/symbols/data/<ecosystem>.jsonl + manifest (SHA-256)
                  │
        scan time, offline, no model:  project source ─► reachable | class_used | not_called
                  │
        --deep:  the dependency path, walked backwards through released source (Part 3)
```

| step | module | model? |
|---|---|---|
| fix links, diff, post-fix files, cached HTTP | `fetch.py`, `diff.py` | no |
| function spans: Python `ast`, gofmt'd Go, JavaScript and TypeScript via tree-sitter | `code.py`, `js.py` | no |
| candidates: changed functions, their callers, facts | `candidates.py` | no |
| ranking | `rank.py` | no (hand-set weights; a logistic regression was tried) |
| choosing among the top candidates | `select.py`, `llm.py` | **yes**, only when the ranker's top-2 margin is small |
| code search when there is no fix link | `retrieve.py` | no (the LLM re-ranks the short list) |
| released source: PyPI wheels, Go module zips, npm tarballs | `source.py`, `npm.py` | no |
| verifier | `verify.py` | no |
| entry points, aliases, npm export names | `entry.py`, `npm.py` | no |
| transitive reachability | `transitive.py`, `deep.py` | no |
| dataset and integrity check | `dataset.py` | no |

### The rules the LLM works under

* It never names a function. It answers with an option id from a list the code built, or
  `none`.
* It must quote one line of the excerpt as evidence. The quote is checked against the excerpt it
  was given, and the result is recorded (`evidence_found`).
* Its choice is then verified against released source like any other candidate. A choice that
  fails the verifier is dropped and the next candidate is tried.
* Every record keeps the model, the prompt hash and the confidence, so a reviewer can see which
  records came from a model and replay the exact prompt from the cache.

### Spending a free tier

The LLM client (`llm.py`) is built for OpenRouter's free tier (50 requests a day), so the number
that matters is *verified answers per request*:

* **Per-advisory cache.** An answer is stored under the hash of that advisory's own prompt, not
  of the batch it travelled in, so changing the batch size, the order or the prompt cap never
  repays an answer. Replies cached before this existed are imported automatically.
* **Split on failure.** `ernie-5.5-flash-preview` reasons at length and sometimes loops on a
  long prompt until its token limit. A failed batch is split in half and retried, so one bad
  advisory costs a few requests instead of the whole batch; one that fails alone is dropped for
  the run.
* **Priority.** The advisories of the most-downloaded packages are asked first, code-search
  records before fix-diff ones, smallest ranker margin first.
* **Waterfall.** `SCGRAPH_LLM_MODELS="a:free,b:free"` sets the fallback order. Any failure
  (HTTP error, timeout, empty reply, non-JSON reply, a reply the validator rejects) moves to the
  next model; a model that refuses the key (HTTP 403) is skipped for 24 hours; a per-minute rate
  limit on every model is waited out; the daily cap stops the run and keeps everything answered.
  The default is `baidu/ernie-5.5-flash-preview:free` alone: `thinkingmachines/inkling-2-small:free`
  answers HTTP 403 ("only available on agentic harnesses") to an ordinary API key, so it cannot
  be a default.
* **Budget guard.** The key's own request count is read once (a free endpoint), every attempt
  is subtracted, a reserve is held back, and the guard is checked before every request. Replay
  modes (`--llm-cache-only`) cannot send a request at all.
* `ernie` loops at temperature 0, so the client samples at 0.6; its reasoning cannot be turned off.

## Evaluation

All numbers are produced by scripts in `scripts/symbols/` and stored in `results/metrics/`.

### Part 1. Engine A: which function does the fix change? (Go, 188 held-out advisories)

The Go vulnerability database is the only large set of advisory-to-symbol labels. 624 Go
advisories have labelled symbols and a GitHub fix link; the split is temporal (the oldest 436
train, the newest 188 test). Every rate is over all 188, so an advisory with no diff or no
candidate counts as a miss. Go labels list the patched function *and* the exported functions
that reach it; a prediction matching either counts.
Numbers: [`symbols_eval.json`](../results/metrics/symbols_eval.json).

| stage | top-1 | top-3 | MRR |
|---|---|---|---|
| largest change first (baseline) | 58.5% | 76.6% | 0.674 |
| **heuristic ranker (shipped)** | **69.7%** | 78.7% | 0.741 |
| logistic regression (trained on 436) | 70.7% | 78.7% | 0.746 |
| heuristic + LLM on the uncertain ones | 70.7% | 78.2% | 0.748 |
| ceiling: a gold symbol is among the candidates | 80.9% | | |

* **Callers matter.** Changed functions alone hold a gold symbol for 78.7% of advisories;
  adding their callers raises the ceiling to 80.9%.
* **The hand-set ranker ships because validation said so, not the test set.** On a validation
  slice (the newest 88 training advisories) it scored MRR 0.834 against 0.822 for the fitted
  model. On the test split the fitted model happens to be 1 point ahead; that is within noise
  for 188 advisories, and choosing it after seeing the test split would be peeking.
* **The LLM helps where the ranker is unsure, but the sample is small.** It was asked about the
  112 advisories whose top-2 margin was below 0.25; the free-tier budget answered 37 that still
  match the current prompts (an earlier 54 lost 17 when a fix to the "added by the fix" fact
  changed their prompt text; they are not re-asked, to save requests). On those 37 top-1 went
  from 56.8% to 62.2%. Paired: the LLM fixed 3 top picks and broke 1 (exact McNemar p = 0.625,
  not significant). Every quote it gave as evidence was found in the excerpt it was shown.

### Part 2. Engine B: no fix link (48 test advisories searched as if the link were missing)

| stage | top-1 | top-3 | MRR | abstain |
|---|---|---|---|---|
| BM25 over the affected release | 27.1% | 47.9% | 0.389 | 12.5% |
| + release diff (last affected vs first fixed) | **43.8%** | 52.1% | 0.493 | 12.5% |
| + LLM re-rank | **52.1%** | 58.3% | 0.552 | 18.8% |

The release diff is the strongest single signal (+16.7 points of top-1, no model). The LLM
answered "none" four times, and all four times the gold symbol was indeed not in the short list.
Because model-free search alone is right less than half the time, the shipped datasets keep a
code-search record **only when the LLM confirmed it**.

### Part 3. Transitive reachability: does the analysis reach what actually runs?

Ground truth is dynamic. Real `requests` and `flask` scenarios (GET and POST against a local
server; routes, templates, sessions and JSON through the test client) run under a profiler, and
every function that executed inside a dependency is recorded. For each such function, the
analysis is asked whether the parent's public API reaches it; a miss is a false `not_called`.
Numbers: [`symbols_transitive.json`](../results/metrics/symbols_transitive.json),
script `scripts/symbols/eval_transitive.py`.

| configuration | recall on the 501 functions that ran | dependency functions marked reachable |
|---|---|---|
| **all five mechanisms** | 95.4% | 81.3% |
| without import-time code (`<module>` pseudo-function) | 77.6% | 61.2% |
| without dunders and properties reached through their class | 90.2% | 72.8% |
| without properties and callbacks read as values | 93.2% | 76.1% |
| without resolved dotted references (`urllib3.PoolManager`, re-exports) | 94.4% | 79.5% |
| without `getattr(self, "visit_" + x)` dispatch | 95.4% | 80.8% |
| none: bare-name matching only (the first version) | 57.1% | 39.6% |

Each row removes one mechanism from the full analysis, except the last, which removes all five.
Import-time code is the largest single contributor (17.8 points of recall): a parent that calls a
dependency while it is being imported, as `flask/signals.py` does with `blinker`, is invisible to
any analysis that only looks inside functions. Dunders and properties come next (5.2 points):
`__init__`, `__getitem__` and `@property` run through syntax, never through `name(...)`. Without
`getattr` dispatch recall is unchanged at 95.4% (it costs 0.4 points of reach); it is kept
because visitor-style code (Jinja, `ast.NodeVisitor`, Django) is where it matters, but this
benchmark does not show a gain, and that is reported rather than hidden.

Per chain (`requests`/`flask` as the parent): `requests -> urllib3` 100%, `flask -> werkzeug`
97.2%, `flask -> jinja2` 91.5%, `flask -> itsdangerous` 96.6%, `flask -> blinker` 100%,
`flask -> jinja2 -> markupsafe` 100% (three packages).

**The cost, stated plainly.** 81% of a dependency's functions are marked reachable, against a
profiler that saw 5% to 53% of them run in one scenario. One scenario exercises only part of a
library, so some of the difference is real reach that the scenario did not trigger and some is
over-approximation; the two cannot be separated here. The verdict is sound but coarse for large,
highly connected dependencies and sharp for narrow ones. It orders a queue; it never closes an
alert.

### Entry points (Go, 149 test advisories with a readable release)

| symbol set | share of gold symbols covered | advisories with any gold symbol |
|---|---|---|
| top symbol only | 22.1% | 69.7% |
| top symbol + entry points (depth 5) | **40.3%** | **77.1%** |

Set precision is 58.6% (median set size 3). Depth trades recall for precision (depth 2: 34.1% /
64.4%; depth 8: 42.2% / 56.5%); depth 5 is the default because a missed entry point produces a
false `not called`. The sweep ran on the test split and is reported as such.

### Part 4. The shipped datasets

One file per ecosystem under `src/scgraph/symbols/data/`, each with a SHA-256 manifest, built by
`scripts/symbols/build_dataset.py`. Packages are chosen by download rank (the public top-PyPI
list; last-month npm downloads), most downloaded first, because real projects pin popular
packages and the newest advisories do not cover them. Build reports:
[`symbols_pypi_build.json`](../results/metrics/symbols_pypi_build.json),
[`symbols_npm_build.json`](../results/metrics/symbols_npm_build.json).

| | PyPI | npm |
|---|---|---|
| verified records | **536** | **301** |
| packages covered | 94 | 71 |
| from the fix diff, ranker sure | 485 | 290 |
| from the fix diff, LLM chose | 25 | 11 |
| from code search, LLM confirmed | 26 | 0 |
| records with entry points | 521 | 228 |
| most covered | pypdf, pillow, aiohttp, gitpython | undici, hono, axios, tar |

Everything that did not verify is an abstention with a reason: a fix that changes only a
module-level constant, no candidate present in the affected release, a package shipped only as a
minified bundle, or a code-search guess the LLM did not confirm. npm has no code-search records
because the LLM budget (47 requests in total, all spent) covered 12 npm advisories; search
records need that confirmation, so they wait for the next day's budget.

### End to end

A project that pins `requests 2.25.0`, whose `urllib3 1.26.4` has 11 advisories. All 20 alerts of
the project are transitive, so before `--deep` every one was `not_analyzed`.

| project code | reachable | not called | not analysed |
|---|---|---|---|
| calls `requests.get(...)` | **8** | **4** | 8 |
| declares `requests` but never uses it | 0 | **12** | 8 |

Each verdict carries its evidence, for example CVE-2021-33503 (`urllib3.util.url`, catastrophic
backtracking in the authority parser): `reachable`, 2 hops, evidence
`github.com/urllib3/urllib3/commit/2d4a3fee6d...`. The eight undetermined alerts are advisories
without a dataset record (three of `urllib3`, the rest of `certifi` and `idna`). All 20
remain alerts; the verdict orders the queue.

## Trust: ledger, signature, export, questions

```bash
scgraph symbols ledger DIR                      # record every symbol as a claim in a hash-chained ledger
scgraph symbols ledger DIR --advisory CVE-X     # the claims for one advisory, with a receipt
scgraph symbols verify                          # check the Ed25519 signature of the shipped datasets
scgraph symbols export OUT                      # datasets + signatures + one OSV patch per advisory
scgraph ask "why am I exposed to CVE-X?" .      # an answer where every sentence cites its source
```

* **Ledger.** A claim is an edge `advisory -> symbol` with the confidence and a source string
  (method, evidence, verifier result, model and prompt hash). The ledger is hash-chained, so a
  claim cannot change without `verify()` failing. A better inference replaces a claim with a
  retraction; views made earlier still show the old claim.
* **Signature.** The manifest holds the SHA-256 of the data. An Ed25519 signature covers the
  manifest, and the public key ships as `signing.pub`. The private key stays on the maintainer's
  machine (`~/.config/scgraph/signing.key`). Needs `pip install "scgraph-cli[sign]"`.
* **Export.** Each OSV patch adds `affected[].ecosystem_specific.affected_functions` and keeps the
  provenance in `database_specific.scgraph`. scgraph sends nothing to anyone. A person who
  maintains an advisory database can read a patch and decide.
* **`scgraph ask`.** It scans, selects the findings that the question names, and writes short
  sentences. Each sentence carries a citation (a path, an advisory, a claim or a fix). No model is
  used, so no sentence can state a fact that the scan did not find.

## Limits

* `not called` is "no reference found", never proof. Calls through `getattr`, plugin registries,
  an instance whose class the project never names, and another package's wrapper are not seen.
  For a method whose class the project references, the verdict is `class_used`.
* `--deep` follows the shortest dependency path only, and only for Python. A second path through
  another direct dependency is not analysed.
* The call graph is name-based: it over-approximates (81% reach above) and misses calls through
  variables. Matching by resolved dotted name is exact; matching by bare name is used only for
  names that are not common (`get`, `send`, `decode`) or that the caller imports by name.
* npm: JavaScript has no visibility, so *public* means *exported*. A package shipped only as a
  minified bundle cannot be verified (names are mangled); a TypeScript fix is matched to the
  compiled release by function name, which fails when the build renames or restructures it.
  Transitive reachability for npm is not implemented.
* A fix that changes only a module-level constant (a regex) leaves the function body identical,
  so the verifier abstains.
* Some vulnerabilities are configuration, not a call (the requests example leaks only through an
  HTTPS proxy with credentials). No symbol captures that.
* The manifest is a SHA-256 integrity check, not a signature.
* The LLM stage evidence is a small free-tier sample; its paired test is not significant.

## Reproduce

```bash
make symbols-eval                                         # Go evaluation, model-free (network once)
python scripts/symbols/eval_go.py --llm-cache-only        # replays paid LLM answers: spends nothing
python scripts/symbols/build_dataset.py --ecosystem pypi --popular 2000 --fix 600 --search 100
python scripts/symbols/build_dataset.py --ecosystem npm  --popular 1500 --fix 400 --search 60
python -m venv /tmp/evalenv && /tmp/evalenv/bin/pip install requests flask
/tmp/evalenv/bin/python scripts/symbols/trace_scenarios.py > /tmp/traces.json
python scripts/symbols/eval_transitive.py --env /tmp/evalenv --traces /tmp/traces.json --ablation
```

npm needs the optional extra: `pip install "scgraph-cli[symbols-js]"`.
