# Evaluation

This document tells how we check each headline number, and where each number is weak.
The first part describes the five evaluation modules. The second part gives the metrics
that are partly tautological, the assumptions of the pipeline, and the bugs that gave
good-looking but incorrect results during development.

`scripts/run_evaluation.py` runs the evaluation modules. They write to
[`../results/metrics/`](../results/metrics). The numbers in this document come from the
committed metric files.

## Measurement rules

We measure two claims separately. We never join them into one end-to-end score.

- The **safety** claim is about provenance. Each alert has a resolvable path. Each "not
  affected" is a proven absence in the graph, or an explicit "not verified, review". The
  counterfactual ablation (does the alert rate follow the evidence) and the
  path-materialisation audit (does each alert have a path) check this claim.
- The **quality** claim: does triage through the graph help? Does it decrease review work,
  or find exposures that a flat scanner does not find, with sufficient coverage? The
  comparison with `osv-scanner` and the feature ablation check this claim.

Each layer also has its own ground truth: grounding against a curated name-to-PURL map,
resolution against deps.dev and real lockfiles, advisory match against `osv-scanner`,
reachability against VEX statements. An end-to-end score can hide a layer that is
incorrect in a way that improves the number. The bug list at the end of this document
shows that this risk is real.

---

## 1. Query latency and throughput

**File:** [`timing.json`](../results/metrics/timing.json).

**Measurement.** The cost of the CSR memmap store (not a graph database), in four parts:
the one-time build from Parquet, the load for each process, query latency, and the
run times of the graph algorithms.

**Method.** We time `osv.materialise` and `kgstore.build` on the full corpus. We time
`KGStore.__init__` and sample the peak resident set. We time `exposure_paths` and
`audit_manifest` (ground, then paths, then ladder) over a random sample of real manifest
roots, and give p50, p90, and p99. Throughput is audits each second in one process, with
no inter-process communication. We time the graph algorithms on the package graph (4.46
million packages, 6.68 million edges). `scaling.json` does some of them again on
edge-sampled subgraphs from 2 percent to 100 percent.

**Result.** Build 27.9 s and 140.3 s (approximately 2.3 minutes for the CSR store). Load
13.19 s, 16,047 MB peak. Full-audit latency **p50 0.02 ms, p90 0.97 ms, p99 6.82 ms**.
Throughput **2,546 audits each second**. Reverse PageRank 4.3 s, articulation points and
bridges 7.5 s, k-core 3.8 s, label propagation 216 s, sampled betweenness 166 s (more than
its 150 s budget, used the fallback). Scaling is almost linear for k-core, PageRank,
articulation points, and connected components.

**Weak points.** Betweenness does not stay in its budget. The latency values are for a
warm page cache. A cold start must first do the 13-second load.

---

## 2. Power-law goodness-of-fit

**File:** [`powerlaw_gof.json`](../results/metrics/powerlaw_gof.json).

**Measurement.** Is the degree distribution a power law, or only a heavy tail?

**Method.** The Clauset-Shalizi-Newman bootstrapped goodness-of-fit test. Fit the
exponent by maximum likelihood. Make 300 synthetic datasets of the same size from the
fitted power law, fit each dataset, and calculate the fraction with a Kolmogorov-Smirnov
distance equal to or more than the observed distance. That fraction is the p-value. The
discrete power-law CDF uses the Hurwitz zeta function. We validated the KS statistic
against known power-law, lognormal, and Poisson inputs, after an earlier version gave an
incorrect KS of 0.376.

**Result.** In-degree `alpha = 1.957`, corrected KS 0.0479, **p = 0.0**. Out-degree
`alpha = 1.918`, KS 0.0874, **p = 0.0**. The test rejects the power law for the two
directions.

**Weak points.** At a tail size of approximately 285,000, the strict test rejects almost
all real distributions. Thus "rejected" means "not a clean power law". It does not mean
"no heavy tail". The distribution has a heavy tail. At this scale, we cannot find the
exact tail family (power law with cutoff, or lognormal). The other analyses do not need
it.

---

## 3. Resolver fidelity against deps.dev

**File:** [`resolver_fidelity.json`](../results/metrics/resolver_fidelity.json).

**Measurement.** Does `resolve.resolve` select the same version as the deps.dev resolver,
for a set of well-known packages?

**Method.** For each `(dependency, declared range)` pair, compare the `scgraph` version
with the deps.dev version. Our corpus is a January 2020 snapshot and deps.dev is live.
Thus the correct number uses only pairs where the deps.dev version is also in our
snapshot (the two resolvers could select it). This separates resolver logic from data
age.

**Result.** Raw exact match 9.3 percent over 1,121 edges. **In-snapshot agreement 97.2
percent** over 107 pairs: npm 97.6 percent (42 pairs), Cargo 100 percent (63 pairs).
PyPI and Maven had too few in-snapshot pairs.

**Weak points.** The in-snapshot sample is small (107 pairs), and most pairs are npm and
Cargo. This module does not validate the PyPI and Maven resolver logic. The raw 9.3
percent comes from data coverage, not from a resolver defect. But it shows that the
`RESOLVES_TO` edges are less reliable for ecosystems with many releases after 2020.

---

## 4. Feature ablation across three decision surfaces

**File:** [`ablation.json`](../results/metrics/ablation.json).

**Measurement.** Do the advanced graph signals (articulation points, betweenness,
community structure, blast radius) change the decisions of a triage engineer?

**Method.** Three decision surfaces, each calculated with and without the structural
signals:

1. **Alert order.** The baseline priority is severity, then depth. The advanced priority
   adds a structural-criticality boost. Measured by Kendall's tau and top-k overlap
   between the two orders, over 56,496 exposures.
2. **Escalation target.** When a manifest has a package with no fix, the baseline
   escalates the package with the highest severity. The advanced version escalates the
   package with the highest blast radius. Measured as how frequently they disagree on the
   first package, over 1,885 manifests.
3. **High-risk classifier.** A logistic model flags manifests with a high advisory load,
   with and without the structural features. Measured by AUROC difference and
   flagged-set overlap, over 2,123 manifests.

**Result.**

- Alert order: Kendall's tau 0.86. Top-20 overlap 0.50. Thus **10 of the top 20 change
  position** with the structural boost.
- Escalation target: severity and blast radius disagree on the first package in **67.5
  percent** of manifests (613 agree, 1,272 disagree).
- Classifier: AUROC **0.9954 with and without** the structural features (difference
  0.0001). But the advanced model flags a different set (top-200 overlap 0.535, 93
  manifests flagged only by the advanced model).

**Conclusion:** the advanced graph signals change decisions, but only some decisions.
They change **which package you fix first**. They do not make a binary risk classifier
more accurate, because severity and tree shape already contain that signal.

**Weak points.** This is a consistency analysis, not a ground-truth evaluation. There is
no labelled "correct escalation target". There is only a measurement that two reasonable
heuristics disagree. The classifier AUROC of 0.9954 is very high. Probably the target is
easy (a high advisory load is almost a function of tree size).

---

## 5. Comparison with osv-scanner

**File:** [`vs_osvscanner_big.json`](../results/metrics/vs_osvscanner_big.json).

**Measurement.** How does the alert set of `scgraph` (after the ladder) compare with
`osv-scanner`, the reference OSV client from Google?

**Method.** Take 150 manifest roots. Write each resolved tree as a lockfile
(`requirements.txt` or `package-lock.json`). Run `osv-scanner --format json` on each
lockfile. Compare its vulnerability set with the alert set of `scgraph`. Report the
confusion (both, only `scgraph`, only scanner). Do not select a winner.

**Result.** **96.9 percent agreement**: 1,748 common findings, 45 only from `scgraph`
(deeper transitive resolution, and alias mapping that `osv-scanner` did not do), 10 only
from `osv-scanner` (advisories that `scgraph` gates out as withdrawn or out of range).

**Weak points.** The lockfiles come from the graph. Thus the two tools see the same tree.
This measures agreement on advisory match, not on resolution. It is not a recall
benchmark. `scgraph` is a governance layer that gates on provenance. Most "only scanner"
findings show the gates operating correctly. They are not misses.

---

## Known limits

### The three partly tautological or lexical metrics

**1. "100 percent path retention" is a tautology.** The decision block in
[`run_manifest.json`](../results/run_manifest.json) shows `retention_pct: 100.0`. That
check asks if the endpoints of a `RESOLVES_TO` edge exist as version nodes. They always
exist, because the parser writes an edge only when it interned the two endpoints. The
number that measures resolution coverage is **parse retention: 96.64 percent** of
declared dependencies found a published version that satisfies them (2.88 million of
85.8 million are dangling). The deps.dev comparison (section 3) measures resolver
*logic*: 97.2 percent in-snapshot.

**2. Ablation monotonicity is a consistency check, not a causal proof.** The ablation
tiers are nested removal sets (T3 contains T2, T2 contains T1). Thus a system that only
counts current alerts makes a monotonic curve by construction. The test finds a system
that alerts on nothing (flat at zero) or a system that is not monotonic (a bug; the test
found one bug in this way). But a monotonic curve to zero shows consistency. It does not
prove that the removed graph elements cause the alerts. The test supports the claim "the
system does not alert on an item that it cannot trace". It does not prove causality.

**3. The semantic-relevance AUROC is partly lexical overlap.** The 0.955 value is the
AUROC of the separation of a real (advisory, affected package) pair from a control pair
with a different package of the same ecosystem. Advisory summaries often name the
package ("Prototype Pollution in lodash", "RCE in Apache Commons Text"). Thus a large
part of the separation is string match, not semantic understanding. The number measures
"can the embedding select the named package over a different package". It does not show
that the model knows if your code path triggers the bug.

### Other limits

**The model layer needs a GPU.** `embed`, `gnn`, and `judge` need CUDA. On a CPU machine
they give a clear error, and the notebook loads cached results from the GPU run. The CPU
part (data, graph store, structure, grounding, traversal, remediation, reports) runs on
all machines.

**The corpus is a 2020 snapshot.** Libraries.io Open Data v1.6.0 has the date 2020-01-12.
It does not contain versions released after that date. The OSV feed is live. Thus the
pipeline can flag a 2024 CVE against a 2019 version, but it cannot resolve a project to a
version released in 2021. The pinned corpus makes the results reproducible and possible
to cite. It also limits the resolver comparison to in-snapshot versions. A newer corpus
changes the numbers, not the design.

**We do not claim "zero false negatives".** The safety claim is about *provenance*: each
alert has a resolvable path, and each "not affected" is a proven absence in the graph or
an explicit "not verified, review". It does not claim that the pipeline finds all real
exposures. A false-negative rate needs a complete ground-truth set of real exposures, and
that set does not exist. The pipeline can miss an exposure through a package that it did
not ground, a transitive edge that the resolver dropped, or an advisory range that is too
narrow.

**Grounding is the probable limit.** The grounder cannot resolve informal names,
transferred or renamed packages, monorepo sub-packages, and vendored copies with no
registry identity. We measure coverage. The remaining items are the limit of what the
pipeline can see.

**Reachability is not decidable in general.** For dynamic languages (reflection,
dependency injection, native addons), the correct output has three values: `reachable`,
`unreachable`, `undetermined`. `undetermined` is the most frequent (79 percent in the
full run). A path proves presence in an affected range. It does not prove that your use
triggers the bug.

### Bugs that gave good-looking incorrect results

Each of these bugs made the system look better or safer than it was, and none gave an
error. We found and fixed them during development:

1. **Advisory rows were not indexed by advisory id** when an OSV record occurred in
   several ecosystem zip files. The alias reverse index pointed at the incorrect package.
2. **Alias-to-CVE canonicalisation did not find the CVE**, because the CVE is an alias,
   not an advisory row. Thus `CVE-2021-44228` grounded to nothing, but
   `GHSA-jfh8-c2jp-5v3q` operated correctly.
3. **The grounder matched malware packages.** The more than 200,000 `MAL-` advisories name
   removed packages. A name-substring match against them gives only noise. Fix: index
   only packages with one or more real published versions.
4. **Remediation selected prerelease versions as the fix.** `_clean_versions` accepted
   all versions with no advisory. Thus the greedy fixer recommended
   `jetty 10.0.0-alpha0` and similar versions. This increased the "needs a major bump"
   and "advisories introduced" counts. Fix: a prerelease filter.
5. **"Power law" came from a KS distance only.** An earlier KS of 0.376 was called
   heavy-tailed without a test. The Clauset bootstrapped test rejects the power law
   (p = 0.0).
6. **Betweenness did not stop.** The simple k-core limit did not hold on a dense real
   cluster, and the calculation ran for more than 25 minutes. Fix: a hard degree limit
   and a wall-clock timeout with a fallback.

Each of these bugs kept or improved a metric while the system was incorrect. This is why
each layer needs its own ground truth. An end-to-end score hides all six bugs.

### Rejected changes

We built the full multi-agent coordination layer and measured it against the one-pass
pipeline on all exposed manifests (refer to [results.md](results.md), section 11). It
decreased alerts from 12,717 to 12,316 and cleared fewer advisories (273 to 178). It gave
less coverage for more precision, with no clear win. It stays in the repository as a
measured negative result and an ablation, not as the architecture.

We expected the structural reachability prior to suppress a large fraction of alerts. It
did not: 9,853 to 9,789 (refer to [results.md](results.md), section 7). We report its
real effect size. We did not tune it to look useful.

## What helped

The gains come from **grounding** (a deterministic name-to-PURL resolver that indexes
only real packages) and from the **provenance gates** (withdrawn, as-of date, not
installable). They do not come from the model layer or the agent loop. The graph, built
with zero model calls, changes an audit list that you cannot act on into a short list of
paths and an explicit refusal for all other items.

Refer to [results.md](results.md) for the results that these limits apply to.
