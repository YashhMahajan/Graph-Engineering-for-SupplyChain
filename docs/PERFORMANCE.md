# Performance

This page gives the measured speed and the security changes. It also tells you how to measure
again. The text follows the ASD-STE100 rules for Simplified Technical English.

## How to measure

Run this command:

```bash
make bench
```

The benchmark makes a synthetic graph. The graph has 2,000,000 versions and
8,000,000 edges. The in-degree of the graph is heavy-tailed, as in the real graph.
The benchmark measures three operations:

- **Build.** The time to change the Parquet tables into the CSR store.
- **Load.** The time to open the store with `KGStore()`.
- **Audit.** The time for one exposure-path search from one root version.

## Results

We ran each version two times on the same machine, in the same session. The table
gives the mean of the two runs.

| Operation | Before (`main`) | After | Change |
|---|---|---|---|
| Build the store | 21.7 s | 7.7 s | **2.8x faster (-65%)** |
| Load the store | 1.34 s | 0.020 s | **67x faster (-98.5%)** |
| Project the store onto the core graph (`from_kgstore`) | 29.0 s | 12.5 s | **2.3x faster (-57%)** |
| First package lookup (`pkg_id`), loaded store | builds a dict of all packages | binary search | **no start-up cost** |
| First core key lookup (`node`), loaded graph | 1.4 s | less than 1 ms | **more than 1,000x faster** |
| Verified load of a core snapshot (1M nodes, 5M edges) | 1.2 s | 0.6 s | **2x faster (-50%)** |
| Access one string by index | 2.9 µs | 0.7 µs | **4x faster** |
| Audit, warm cache, p50 | 0.102 ms | 0.103 ms | no change (in the noise) |

At the full scale of 21.4M versions, the load time was 13 s before the change. The
load time does not increase with the number of strings now, because no string is
decoded at load.

## Security results

| Risk | Before | After |
|---|---|---|
| Load a graph directory from an unknown source | `np.load(allow_pickle=True)` can run code from the file | No pickle on the load path. A 1.0 directory gives an error, not code execution. |
| Download release artifacts | Extracted with no hash check | A pinned sha256 is necessary. HTTPS only. Downloads stop after 120 s with no data. |
| Edit the key index of a core snapshot | Not detected | The fingerprint includes the index. A damaged index gives an error, also with `verify=False`. |

## How I did it

> I removed every pickled array and kept strings as one UTF-8 block plus offsets, so
> the store opens with memory maps and no code runs. I then replaced each per-row
> Python loop on the build and load paths with one NumPy or Arrow operation.

The specific changes:

1. **Strings.** A `StrColumn` keeps a column of strings as one `uint8` array and one
   `int64` offset array. Both arrays are memory-mapped. A string is decoded only when
   you read it. Arrow keeps strings in the same layout, so the encode step copies two
   buffers and does no work per string.
2. **Package to versions.** The build step writes this map as a CSR. Before, the load
   step made the map with a Python loop over all versions.
3. **CSR construction.** `np.bincount` and `np.cumsum` make the index pointer in one
   pass. Before, `np.add.at` did an unbuffered scatter.
4. **Package-pair deduplication.** Each pair becomes one `int64` code, and one 1-D sort
   removes duplicates. Before, `np.unique(axis=0)` sorted structured rows. That sort
   used most of the build time.
5. **Key lookup.** The build step saves the sort order of the keys. A lookup is a binary
   search over that order. No dictionary of all keys is necessary.
6. **Dates.** Arrow parses the date columns in C. Python parses only the rows with a
   time zone offset.

## Known limits

- The benchmark graph is synthetic. Real trees are deeper, so real audit times are
  longer. The comparison between the two versions stays valid.
- Python decodes a string from a `StrColumn` more slowly than it reads an item from an
  object array (0.7 µs against 0.4 µs). The audit time does not change, because an
  audit reads few strings.

## Symbols pipeline

The symbols pipeline runs at build time. A scan only reads its data files.

| Measure | Result | How to measure |
|---|---|---|
| Scan with `--reachability`, added time | Reads 2 small files. Parsing your source costs more. | `scgraph scan . --reachability` |
| Call-index build for one release | Once per release. It is cached in memory. | `scripts/symbols/eval_transitive.py` |
| Transitive evaluation, 12 chains, 3,052 functions | About 30 s per configuration | `eval_transitive.py --ablation` |
| Model requests per scan | 0 | |
| Free-tier requests per answered advisory | 4.3 (47 requests, 204 answers) | `scgraph symbols budget` |
| Repeat build, same advisories | 0 HTTP requests and 0 LLM requests (disk caches) | `build_dataset.py` |

Two caches make a repeat build free. The HTTP cache is `~/.cache/scgraph/http`. The LLM cache
is `~/.cache/scgraph/llm`. The LLM cache is keyed by advisory, not by batch.

## Symbols measurements

Scripts are in `scripts/symbols/`. Results are in `results/metrics/`.

### Engine A: which function does the fix change? (Go, 188 held-out advisories)

The Go database has labelled symbols. The split is by time: the oldest 436 advisories train, the
newest 188 test. A missing diff or candidate counts as a miss.

| Stage | Top-1 | Top-3 | MRR |
|---|---|---|---|
| Largest change first (baseline) | 58.5% | 76.6% | 0.674 |
| **Hand-set ranker (shipped)** | **69.7%** | 78.7% | 0.741 |
| Logistic regression (trained on 436) | 70.7% | 78.7% | 0.746 |
| Hand-set ranker + LLM on the uncertain ones | 71.3% | 78.7% | 0.752 |
| Ceiling: a gold symbol is among the candidates | 80.9% | | |

- Callers matter. Changed functions alone hold a gold symbol for 78.7%. Callers raise it to 80.9%.
- The hand-set ranker ships because it won on a validation slice (MRR 0.834 against 0.822). The
  trained model is 1 point ahead on the test split. That is noise at 188 advisories. Choosing it
  now would use the test split.
- The LLM was asked about the advisories whose top-2 margin was below 0.25. The budget answered
  67 of them. On those, top-1 went from 58.2% to 62.7%. The LLM fixed 5 top picks and broke 2
  (McNemar p = 0.453). This is not significant. Every quote was in the excerpt.

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

Import-time code is the largest single gain (17.8 points). `getattr` dispatch gave no gain here.
It stays, because visitor-style code needs it, and it costs 0.4 points of reach. Per chain:
`requests -> urllib3` 100%, `flask -> werkzeug` 97.2%, `flask -> jinja2` 91.5%,
`flask -> itsdangerous` 96.6%, `flask -> jinja2 -> markupsafe` 100%.

The cost: 81% of a dependency's functions are marked reachable, and the profiler saw 5% to 53% of
them run in one scenario. Part of the difference is real reach that the scenario did not trigger.
Part is over-approximation. The verdict is sound but coarse for large dependencies.

### A real project

A project pins `requests 2.25.0`. Its `urllib3 1.26.4` has 11 advisories. The project has 20
transitive alerts. Before `--deep`, all 20 were `not_analyzed`.

| Project code | Reachable | Not called | Not analyzed |
|---|---|---|---|
| Calls `requests.get(...)` | **8** | **4** | 8 |
| Declares `requests` and never uses it | 0 | **12** | 8 |

Example: CVE-2021-33503 (`urllib3.util.url`) is `reachable`, 2 hops, with the fix commit
`2d4a3fee6d...` as evidence. Eight alerts have no record in the dataset. All 20 stay alerts.

### Reproduce

```bash
make symbols-eval                                          # Go evaluation, model-free
python scripts/symbols/eval_go.py --llm-cache-only         # replay paid answers, spends nothing
python -m venv /tmp/evalenv && /tmp/evalenv/bin/pip install requests flask
/tmp/evalenv/bin/python scripts/symbols/trace_scenarios.py > /tmp/traces.json
python scripts/symbols/eval_transitive.py --env /tmp/evalenv --traces /tmp/traces.json --ablation
```
