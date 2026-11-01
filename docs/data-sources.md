# Data sources

This document gives each input of the pipeline: its data, version, identifier, license,
how `scgraph` reads it, and its limits. All sources are free bulk sources. Only deps.dev
is used outside the pipeline, as ground truth for the evaluation.

---

## 1. Libraries.io Open Data (primary corpus)

**Data.** The dependency graph: package names and platforms, versions with publication
dates, and declared dependency rows (`project, version, dependency name, requirement,
kind, optional, dependency platform`). The `RESOLVES_TO` edges come from this source.

**Version.** Libraries.io Open Data **v1.6.0**, the last published release, snapshot
date **2020-01-12**.

- Zenodo record **3626071**, DOI **10.5281/zenodo.3626071**
- File `libraries-1.6.0-2020-01-12.tar.gz`
- Size **24,890,021,718 bytes** (approximately 24.89 GB). It extracts to approximately
  100 GB of CSV.
- MD5 **`4f2275284b86827751bb31ce74238b15`**
- Contents: 34 package managers, approximately 4.2 million projects, 26 million versions,
  and 105 million dependency rows

**License.** Creative Commons Attribution-ShareAlike 4.0 (CC BY-SA 4.0).

**How `scgraph` reads it.** `acquire_full.fetch_libraries_io` downloads the pinned
tarball (resumable), verifies the size and the MD5, and extracts it.
`acquire_full.build_full_tables` reads the `projects`, `versions`, and `dependencies`
CSV files into the Parquet edge tables. `resolve.py` changes each declared requirement
into a concrete version. If a CSV row has a `resolved_version`, the pipeline uses it as
a lockfile pin. The pipeline keeps resolution results by `(package, range, ecosystem)`.

**Limit.** The snapshot is from **January 2020**. It does not contain versions released
after that date. This affects the resolver comparison in [evaluation.md](evaluation.md):
deps.dev is live, and if it selects a version from after 2020, the two resolvers cannot
agree. Thus the comparison uses only the cases where the deps.dev version is also in the
snapshot ("in-snapshot"). In these cases, agreement is 97.2 percent. The 2025
Libraries.io release has the same schema and is larger. We use v1.6.0 because it is fully
documented, pinned to a DOI, and possible to cite.

---

## 2. OSV (advisory layer)

**Data.** All advisories in the OSV schema, with `affected[].ranges` (version events:
`introduced`, `fixed`, `last_affected`), `affected[].versions` (explicit version lists),
`aliases` (CVE, GHSA, RUSTSEC, PYSEC), `severity` (CVSS vectors), `withdrawn`, and
references.

**Version.** OSV `all.zip` for each ecosystem, downloaded **live on each run**. There is
no fixed version. The full-run snapshot has **285,698 advisories**.

- URL pattern `https://osv-vulnerabilities.storage.googleapis.com/<ECOSYSTEM>/all.zip`
- Ecosystem names as OSV writes them: `npm`, `PyPI`, `Maven`, `crates.io`, `Go`,
  `RubyGems`, `Packagist`, `NuGet`

**License.** The OSV aggregate uses Creative Commons Attribution 4.0 (CC BY 4.0). Each
record also has the terms of its upstream database.

**How `scgraph` reads it.** `acquire.fetch_osv` downloads the `all.zip` of each
ecosystem and keeps it **as a zip** (one file write, not hundreds of thousands).
`acquire.iter_osv_records` reads records from the zip. One OSV record can occur in
several ecosystem zip files. Thus `parse.py` interns each advisory by its OSV id and
writes one row for each unique advisory. Each `affected[]` entry gets the ecosystem from
its own `package.ecosystem`, not from the zip. `osv.materialise` then compares each
affected range with the version table to make the `affected_versions` bitsets. It also
builds the alias union-find, which maps each id to a canonical CVE, and the `withdrawn`
mask.

**Limit.** Curators write the advisory ranges. Some ranges are too wide, some are
incorrect, and some are withdrawn. The graph keeps them as they are. It does not change
them without an upstream signal. The over-claim measurement in
[methodology.md](methodology.md) shows a gap of approximately 1 percent between ranges
and explicit lists, where a check is possible. The as-of-date gate removes advisories
published after the version that a project ships. This occurs at query time. The data
does not change.

Malware advisories (prefix `MAL-`) are most of the recent feed.
[`temporal.json`](../results/metrics/temporal.json) records 197,809 advisories published
in 2025 and 31,365 in 2026. Most of them are malware records for removed packages. The
grounder indexes only packages with one or more real published versions. Thus substring
matches against the names of removed packages do not cause false alerts. (This was a
real bug. Refer to [evaluation.md](evaluation.md).)

---

## 3. GitHub Advisory Database

**Data.** GHSA records in OSV format, with `database_specific.cwe_ids` (the CWE weakness
class), CVSS v3.1 and v4.0 vectors, and patched versions. The pipeline uses it for **CWE
identifiers and CVE aliases**.

**Version.** A shallow `git clone` of `https://github.com/github/advisory-database`, as
it is at run time.

**License.** Creative Commons Attribution 4.0 (CC BY 4.0).

**How `scgraph` reads it.** `acquire_full.fetch_ghsa` makes the shallow clone. Parsing
adds the CWE and alias mappings to the advisory table. If the clone fails, the pipeline
continues without the CWE mapping.

**Limit.** GHSA has only reviewed advisories, which are a subset of OSV. The pipeline
uses it to add data, not as a primary source of affected ranges.

---

## 4. deps.dev API (evaluation only)

**Data.** The resolved transitive dependency closure from Google for npm, PyPI, Maven,
Go, and Cargo, with the declared requirement on each edge. The pipeline uses it as
**resolver ground truth** and as the source of the smoke corpus.

**Version.** The live API at `https://api.deps.dev/v3`. You do not need a key.

**License.** The deps.dev terms of service (the data is CC BY, from Google).

**How `scgraph` reads it.** For the smoke corpus, `scripts/acquire_smoke.py` reads
approximately 50 seed packages for each ecosystem and a set of known vulnerable version
pins. For each package, it gets the default version and the resolved dependency graph.
For the evaluation, the resolver-fidelity module takes each `(dependency, declared
range)` pair from a set of well-known packages. It then examines if `resolve.resolve`
selects the same version as deps.dev.

**Limit.** The bulk export of deps.dev (BigQuery) needs a Google Cloud account. Thus the
pipeline uses deps.dev only for the evaluation and the small smoke sample, and the
pipeline itself needs no login. The API is live and the corpus is from 2020. Thus the
comparison uses only in-snapshot versions (section 1). Full-run agreement: **97.2 percent
in-snapshot** over 107 pairs (npm 97.6 percent, Cargo 100 percent; PyPI and Maven had
too few in-snapshot pairs),
[`resolver_fidelity.json`](../results/metrics/resolver_fidelity.json).

---

## 5. CVSS specifications (FIRST.org)

**Data.** The base-score formula that changes a CVSS vector string into a number.

**Version.** CVSS v3.1 Specification Document (section 7.1, base scoring) and CVSS v4.0
Specification, from FIRST.org.

**License.** FIRST publishes them for open use.

**How `scgraph` reads it.** `cvss.py` calculates the v3.1 score directly: impact and
exploitability sub-scores, the scope-change branch, and the round-up rule. It is
arithmetic, not a model. CVSS v4.0 base scoring uses a lookup table. The module
calculates an approximate v4.0 value from the v3-equivalent metrics and marks the value
as approximate.

**Limit.** OSV records have CVSS v2, v3.0, v3.1, and v4.0 vectors. The v4.0 value is an
estimate, not an official v4.0 base score.

---

## 6. The eight ecosystems

The full run uses eight package ecosystems
([`run_manifest.json`](../results/run_manifest.json), field `ecosystems`):

| Ecosystem | Registry | Range grammar (`resolve.py`) |
|---|---|---|
| npm | npmjs.com | node-semver |
| PyPI | pypi.org | PEP 440 (`packaging.specifiers`) |
| Maven | Maven Central | Interval notation `[a,b)` |
| Cargo | crates.io | node-semver style |
| Go | pkg.go.dev | Exact or semver `>=` |
| RubyGems | rubygems.org | node-semver style |
| Packagist | packagist.org | node-semver style |
| NuGet | nuget.org | Interval or exact |

---

## 7. The parsed tables

`parse.py` and `osv.materialise` write these Parquet tables in `data/parquet/`. The row
counts are from the full run
([`run_manifest.json`](../results/run_manifest.json)):

| Table | Rows | One row is |
|---|---|---|
| `packages` | **4,460,049** | One package: `(pkg_id, ecosystem, name)` |
| `versions` | **21,415,461** | One published version: `(ver_id, pkg_id, version, is_default, published)` |
| `resolved` | **82,807,953** | One `RESOLVES_TO` edge: `(ver_id, res_ver_id)` |
| `advisories` | **285,698** | One OSV record: `(adv_id, osv_id, canon_id, summary, severity, withdrawn, published)` |
| `affected` | One for each raw OSV `affected[]` entry | `(adv_id, pkg_id, entry_json)`. The raw entry is kept for the over-claim check. |
| `affected_versions` | **1,350,518** | One match: `(adv_id, ver_id)`. This version is in the affected range of this advisory. |
| `aliases` | One for each alias pair | `(osv_id, alias)`. The union-find uses it to map each id to a canonical CVE. |

The package-level dependency graph that the structural analyses use has **6,682,795
edges** (`run_manifest.json`, field `package_dep_edges`).

The size of the `affected` and `aliases` tables changes with the advisory feed. The run
manifest does not record their row counts. The pipeline queries `affected_versions`
(1,350,518 rows).

---

## 8. Downloads for each tier

| Tier | Sources | Approximate download |
|---|---|---|
| Smoke | OSV `all.zip` (5 ecosystems) and a deps.dev sample | Tens of MB |
| Full, from Release artifacts | Parsed Parquet tables and embeddings | 550 MB |
| Full, from the start | Libraries.io v1.6.0 tarball, OSV (8 ecosystems), GHSA clone | 25 GB |

Refer to [reproducing.md](reproducing.md) for the commands of each tier.
