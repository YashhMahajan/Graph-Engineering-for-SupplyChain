# Data sources

This page lists each input: its data, version, license, how scgraph reads it, and its limits. It
follows the ASD-STE100 rules for Simplified Technical English. All sources are free.

## 1. Libraries.io Open Data (the graph)

- **Data.** Package names, versions with dates, and declared dependency rows. The `RESOLVES_TO`
  edges come from here.
- **Version.** v1.6.0, snapshot of 2020-01-12. Zenodo record 3626071, DOI
  10.5281/zenodo.3626071. File size 24,890,021,718 bytes. MD5 `4f2275284b86827751bb31ce74238b15`.
  It has 34 package managers, about 4.2 million projects, 26 million versions and 105 million
  dependency rows.
- **License.** CC BY-SA 4.0.
- **How scgraph reads it.** `acquire_full.fetch_libraries_io` downloads the file, checks the size
  and the MD5, and extracts it. `build_full_tables` writes the Parquet tables. `resolve.py` changes
  each declared range into a version.
- **Limit.** The snapshot has no version released after January 2020. The resolver comparison with
  deps.dev uses only versions that exist in the snapshot (97.2% agreement).

## 2. OSV (advisories)

- **Data.** All advisories in the OSV schema: affected ranges, aliases (CVE, GHSA, RUSTSEC, PYSEC),
  severity vectors, withdrawn flags and references. The full-run snapshot has 285,698 advisories.
- **Version.** `all.zip` per ecosystem, downloaded at each run. URL pattern:
  `https://osv-vulnerabilities.storage.googleapis.com/<ECOSYSTEM>/all.zip`.
- **License.** CC BY 4.0. Each record also has the terms of its source database.
- **How scgraph reads it.** `acquire.fetch_osv` keeps each zip as one file. `parse.py` interns each
  advisory by its id. `osv.materialise` builds the table of affected versions and the alias map.
  The symbols pipeline reads `data/raw/osv/<ecosystem>.zip`.
- **Limit.** Curators write the ranges. Some ranges are too wide or wrong. scgraph keeps them as
  they are. Most of the recent feed is malware records (`MAL-`). The grounder indexes only
  packages with at least one real version.

## 3. GitHub Advisory Database

- **Data.** GHSA records with CWE identifiers and CVE aliases.
- **Version.** A shallow `git clone` of `github.com/github/advisory-database`, at run time.
- **License.** CC BY 4.0.
- **How scgraph reads it.** `acquire_full.fetch_ghsa` clones it. If the clone fails, the run
  continues without the CWE mapping.
- **Limit.** It has only reviewed advisories, a subset of OSV.

## 4. deps.dev (evaluation only)

- **Data.** The resolved dependency closure for npm, PyPI, Maven, Go and Cargo.
- **Version.** The live API, `https://api.deps.dev/v3`. No key is necessary.
- **Use.** The ground truth for the resolver, and the source of the smoke corpus.
- **Limit.** The API is live and the main corpus is from 2020, so the comparison is partial.

## 5. CVSS specifications (FIRST.org)

`cvss.py` calculates the CVSS v3.1 base score from the vector. It is arithmetic. For v4.0 it gives
an approximate value and marks it as approximate.

## 6. Sources of the symbols pipeline

| Source | What scgraph takes | Use |
|---|---|---|
| GitHub (`.diff`, `.patch`, raw files) | Fix commits and the files at the fix revision | Candidate functions |
| PyPI JSON API and wheels | Versions and released source | Verifier, entry points |
| Go module proxy (`proxy.golang.org`) | Module zips | Verifier, entry points |
| npm registry | Package documents and tarballs | Verifier, entry points |
| Go vulnerability database (in OSV) | Labelled vulnerable symbols | Evaluation ground truth |
| `hugovk.github.io/top-pypi-packages` | Download rank of PyPI packages | Choose packages to cover |
| npm downloads API | Downloads of the last month | Choose packages to cover |
| OpenRouter | Replies of a free model | The LLM stage (build time only) |

Every HTTP reply is cached on disk (`~/.cache/scgraph/http`). A missing file (404) is cached too.
Scans do not use these sources. They read the shipped datasets.

## 7. The ecosystems

| Ecosystem | Registry | Range grammar |
|---|---|---|
| npm | npmjs.com | node-semver |
| PyPI | pypi.org | PEP 440 |
| Maven | Maven Central | Intervals `[a,b)` |
| Cargo | crates.io | node-semver style |
| Go | pkg.go.dev | Exact or `>=` |
| RubyGems | rubygems.org | node-semver style |
| Packagist | packagist.org | node-semver style |
| NuGet | nuget.org | Interval or exact |

## 8. The parsed tables

`parse.py` and `osv.materialise` write these tables to `data/parquet/`. The counts are from the
full run (`results/run_manifest.json`).

| Table | Rows | One row is |
|---|---|---|
| `packages` | 4,460,049 | A package |
| `versions` | 21,415,461 | A published version |
| `resolved` | 82,807,953 | A `RESOLVES_TO` edge |
| `advisories` | 285,698 | An OSV record |
| `affected_versions` | 1,350,518 | A version inside an advisory's affected range |
| `affected`, `aliases` | varies | The raw `affected[]` entries, and the alias pairs |

The package-level graph for the structure analysis has 6,682,795 edges.

## 9. Downloads for each tier

| Tier | Sources | Download |
|---|---|---|
| Smoke | OSV (5 ecosystems) and a deps.dev sample | tens of MB |
| Full, from release artifacts | Parquet tables and embeddings | 550 MB |
| Full, from the start | Libraries.io tarball, OSV (8 ecosystems), GHSA clone | 25 GB |
