# Vulnerable-symbol inference

**Which function does an advisory actually concern?** `govulncheck` can say "your code does not
call the vulnerable function" because the Go vulnerability database names that function. For
PyPI, Maven and Cargo advisories the name is missing (0% of the records in the local OSV
snapshot), so every scanner falls back to "the package is present". `scgraph.symbols` recovers
the name at **build time**, checks it against released source, and ships the result as a data
file. A scan reads that file offline and makes **zero model calls**.

```bash
scgraph symbols infer GHSA-j8r2-6x86-q33q      # one advisory, end to end
scgraph symbols show  GHSA-j8r2-6x86-q33q      # look it up in the shipped dataset
scgraph symbols budget                         # today's free-tier LLM budget
scgraph scan . --reachability                  # uses the dataset when OSV names no function
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
                      calling something changed in the fixed release ─► else abstain
                  │
                  ▼
            Entry points: public functions of the release that reach it (+ re-export aliases)
                  │
                  ▼
            SymbolRecord ─► src/scgraph/symbols/data/pypi.jsonl + manifest.json (SHA-256)
```

| step | module | model? |
|---|---|---|
| fix links, diff, post-fix files | `fetch.py`, `diff.py` | no |
| function spans (Python `ast`, gofmt'd Go) | `code.py` | no |
| candidates: changed functions, their callers, facts | `candidates.py` | no |
| ranking | `rank.py` | no (heuristic weights; a logistic regression was tried, see below) |
| choosing among the top candidates | `select.py`, `llm.py` | **yes**, only when the ranker's top-2 margin is small |
| code search when there is no fix link | `retrieve.py` | no (the LLM re-ranks the short list) |
| verifier | `verify.py` | no |
| entry points and aliases | `entry.py` | no |
| dataset and integrity check | `dataset.py` | no |

### The rules the LLM works under

* It never names a function. It answers with an option id from a list the code built, or
  `none`.
* It must quote one line of the excerpt as evidence. The quote is checked against the
  excerpt it was given, and the result is recorded (`evidence_found`).
* Its choice is then verified against released source like any other candidate. A choice
  that fails the verifier is dropped and the next candidate is tried.
* Every record keeps the model, the prompt hash and the confidence, so a reviewer can see
  which records came from a model and replay the exact prompt from the cache.

### Free-tier operation

The LLM client (`llm.py`) is built for OpenRouter's free tier (50 requests per day):

* **Waterfall.** Models are tried in order (`thinkingmachines/inkling-2-small:free`, then
  `baidu/ernie-5.5-flash-preview:free`). Any failure moves to the next model: HTTP error,
  timeout, empty reply, non-JSON reply, or a reply the validator rejects. A model that refuses
  the key (HTTP 403) is skipped for 24 hours so it costs nothing again.
* **Waits.** When every model is rate-limited for the minute, the client waits for the reset
  and tries again. The daily cap stops the run cleanly; everything answered so far is kept.
* **Cache.** Replies are cached by prompt hash, so a re-run spends nothing.
* **Batching.** Six advisories go in one request; a task the model skipped is retried in a
  later request.
* **Budget guard.** The key's own count is read once (a free endpoint) and every attempt is
  subtracted, with a reserve held back.

Two things the evaluation run taught, both encoded in the client: `inkling-2-small:free` is
served only to apps on OpenRouter's list, so for an ordinary key the waterfall runs on
`ernie`; and `ernie` requires reasoning and loops with greedy decoding (`temperature: 0`), so
the client samples at 0.6 and caps the trace.

## Evaluation

**Ground truth.** The Go vulnerability database is the only large set of advisory-to-symbol
labels. 624 Go advisories have labelled symbols and a GitHub fix link. The split is temporal:
the oldest 436 train, the newest 188 test. Every rate is over all 188 test advisories, so an
advisory with no diff or no candidate counts as a miss. Go labels list the patched function
*and* the exported functions that reach it; a prediction matching either counts.
Numbers: [`results/metrics/symbols_eval.json`](../results/metrics/symbols_eval.json),
[`results/metrics/symbols_entry.json`](../results/metrics/symbols_entry.json).

### Engine A (fix link present), 188 test advisories

| stage | top-1 | top-3 | MRR |
|---|---|---|---|
| largest change first (baseline) | 58.5% | 76.6% | 0.674 |
| heuristic ranker (shipped) | **69.7%** | 79.3% | 0.742 |
| logistic regression (trained on 436) | 68.1% | 79.3% | 0.735 |
| heuristic + LLM on the uncertain ones | **72.3%** | 78.7% | 0.757 |
| ceiling: a gold symbol is among the candidates | 80.9% | | |

* **Callers matter.** Changed functions alone hold a gold symbol for 78.7% of advisories;
  adding their callers raises the ceiling to 80.9%.
* **The learned ranker lost.** On a validation slice (the newest 88 train advisories) the
  heuristic scored MRR 0.845 against 0.804, so the heuristic ships. With a few hundred
  labelled advisories, fifteen hand-set weights generalise better than a fitted model.
* **The LLM helps where the ranker is unsure, but the sample is small.** It was asked about
  the 112 advisories whose top-2 margin was below 0.25; the free-tier budget (10 requests,
  six advisories each, one batch lost to a reasoning loop) got 54 answered. On those 54,
  top-1 went from 53.7% to 63.0% and MRR from 0.619 to 0.673. Paired: the LLM fixed 6 top
  picks and broke 1 (exact McNemar p = 0.125, not significant at 0.05). Every quote it gave
  as evidence was found in the excerpt it was shown.

### Entry points (149 test advisories with a readable release)

| symbol set | share of gold symbols covered | advisories with any gold symbol |
|---|---|---|
| top symbol only | 22.0% | 69.7% |
| top symbol + entry points (depth 5) | **39.8%** | **77.1%** |

Set precision is 58.2% (median set size 2). Depth trades recall for precision (depth 2:
33.8% / 64.5%; depth 8: 41.9% / 56.0%); depth 5 is the default because a missed entry
point produces a false `not called`. The sweep ran on the test split and is reported as such.

### Engine B (no fix link), 48 test advisories searched as if the link were missing

| stage | top-1 | top-3 | MRR | abstain |
|---|---|---|---|---|
| BM25 over the affected release | 27.1% | 47.9% | 0.388 | 12.5% |
| + release diff (last affected vs first fixed) | **43.8%** | 52.1% | 0.496 | 12.5% |
| + LLM re-rank (6 requests, 34 answered) | **52.1%** | 58.3% | 0.556 | 18.8% |

The release diff is the strongest single signal (+16.7 points of top-1, no model). The LLM
answered "none" four times, and all four times the gold symbol was indeed not in the short
list. Because model-free search alone is right less than half the time, the shipped dataset
keeps a code-search record **only when the LLM confirmed it**.

### The shipped PyPI dataset

`scripts/symbols/build_pypi.py` ran on the 250 newest PyPI advisories (200 with a fix link,
50 without; `MAL-` and withdrawn records skipped, GHSA / PYSEC / CVE duplicates merged).
Report: [`results/metrics/symbols_pypi_build.json`](../results/metrics/symbols_pypi_build.json).

| | count |
|---|---|
| verified records shipped | **171** of 250 |
| from the fix diff, ranker sure | 120 |
| from the fix diff, LLM chose | 28 |
| from code search, LLM confirmed | 23 |
| records with entry points | 157 |
| abstained: no candidate passed the verifier | 50 |
| abstained: code search the LLM did not confirm | 16 |
| abstained: no usable fix or release | 13 |
| LLM requests spent (6 advisories each, 2 lost to reasoning loops) | 16 |

190 advisories were uncertain enough to ask about; the day's budget answered 83 of them,
code-search ones first. The rest kept the ranker's verified choice. Re-running the build on
another day spends only on what is still unanswered.

### End to end

Two projects pin `mcp==2.1.1`, which GHSA-5h93-6whr-6q8j affects. The advisory names no
function. One project calls `streamable_http_client`; the other only uses `FastMCP`.

```text
$ scgraph scan calls/  --reachability     ->  reachable (inferred)   evidence: fix 2106335
$ scgraph scan nocall/ --reachability     ->  not_called (inferred)  evidence: fix 2106335
```

Without the dataset both would be `not_analyzed`. Both stay alerts: the verdict orders the
queue, it never closes an alert.

## Limits

* `not called` is "no reference found", never proof. Calls through `getattr`, plugin
  registries, instance methods (`s = Session(); s.request()`) and another package's wrapper
  are not seen. For a method whose class the project references, the verdict is
  `class_used`, never `not_called`.
* Reachability still runs only for **direct** Python dependencies. Transitive reachability
  needs call summaries chained along the dependency path (Phase 3).
* The entry-point call graph is name-based. It over-approximates dynamic dispatch and misses
  calls through variables.
* Some vulnerabilities are configuration, not a call (the requests example only leaks through
  an HTTPS proxy with credentials). No symbol captures that.
* The manifest is a SHA-256 integrity check, not a signature.

## Reproduce

```bash
make symbols-eval                                         # model-free stages (network once)
python scripts/symbols/eval_go.py --llm-requests 10       # adds the LLM stage (free tier)
python scripts/symbols/build_pypi.py --fix 200 --search 50 --llm-requests 12
```
