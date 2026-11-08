# Changelog

This file records all important changes to this project. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-11-08

### Added

- `scgraph scan --format openvex`: an OpenVEX 0.2.0 document. Alerts are `affected` with
  the path in the action statement; `path` and `scope` abstentions are `not_affected`
  with a justification. Severity-floor, ignored and withdrawn findings emit nothing.
  Each product is unique per lockfile, so same-named folders do not collide.
- `scgraph scan --vex FILE` (repeatable): `not_affected` and `fixed` statements from an
  OpenVEX file suppress matching findings as a `vex` abstention. The newest statement
  wins, malware is never suppressed, and malformed files exit 2.
- **`scgraph diff --base REF`**: scan each lockfile at a git ref and in the working tree
  and report only the difference: new alerts with their paths, resolved alerts, package
  changes and the count of inherited alerts. The exit code counts new alerts only. Output:
  text, JSON and a Markdown comment with a hidden marker for a sticky pull-request comment.
- GitHub Action `mode: diff`, `base` and `comment` inputs: comments only what a pull
  request introduces and edits one comment authored by `github-actions[bot]`.
- **Release anomalies in `scgraph check` (npm)**: warnings when a release differs from
  its predecessor: `publisher_changed`, `maintainer_added`, `provenance_dropped`,
  `install_script_added`, `backport_published` and `publish_burst`. They use only the
  registry document the guard already fetches, examine releases from the last 14 days, and
  also apply to the Claude Code hook and the MCP server.
- **Five more input formats**: `pnpm-lock.yaml` (v6 to v9), `bun.lock`, `gradle.lockfile`
  and `buildscript-gradle.lockfile`, CycloneDX JSON (`*.cdx.json`, `bom.json`) and SPDX
  JSON (`*.spdx.json`). An SBOM's ecosystem comes from each purl, so one file can mix
  registries; components with no pinned, supported purl are skipped.
- **`scgraph audit`**: audit `.mcp.json`, Claude and Gemini settings, Cursor and VS Code MCP
  config and `.vscode/tasks.json` for code that runs on its own. It flags unpinned `npx` and
  `uvx` launchers, `runOn: folderOpen` tasks, download-and-execute commands and
  `enableAllProjectMcpServers`, and sends each launched package through the guard.
  Unreadable config is a warning, never a pass. Exit codes: 0, 1 warn, 2 block.
- **Scan history**: `scgraph scan --history DIR` records each scan in the bitemporal
  ledger, and `scgraph history DIR --advisory ID` answers when exposure began, when it was
  fixed and whether it regressed, with a verifiable receipt (`--receipt`, `--check`,
  `--verify`). A window starts at the first recorded scan, not when the code became
  vulnerable. `--history` refuses `--advisory`, because a subset scan would close exposures.
- `--format html`: a self-contained report with no script, no remote resource, escaped
  lockfile text and a strict Content-Security-Policy.
- `scan --imports`: a hint that marks an alert `imported` or `not imported` by whether the
  project's source imports the dependency at the top of its path. It never suppresses an
  alert or changes the exit code, it is not a call graph, and PyPI is only ever `imported`.

### Changed

- When a release adds an install script, the guard reports `install_script_added` instead
  of the generic `install_scripts` warning, so the script is not listed twice.

### Fixed

- Lockfile text is neutralised before it enters Markdown (`md_safe`). A hostile package
  name could close a code span or fence, add a table cell, inject HTML or ping a GitHub
  user in a PR comment or job summary. Affects `--format markdown` and `--github-summary`.
- A malformed `until=` date in `.scgraph-ignore` now names the file, line and value.
- Two unclosed file handles (`parse.py`, `acquire.py`). The one in `parse.py` made the
  smoke-pipeline test fail intermittently, because the test config turns a
  `ResourceWarning` into an error.

## [1.2.1] - 2026-11-03

### Fixed

- `action.yml`: the description is now shorter than 125 characters, so the Action can
  go on the GitHub Marketplace.
- The Scorecard workflow uses `ossf/scorecard-action@v2.4.3`. Version 2.4.0 pulls its
  image from `gcr.io`, which now refuses the download.
- The distribution name is now `scgraph-cli`, because `scgraph` on PyPI belongs to
  another project. The command and the import name stay `scgraph`.
- `.github/workflows/publish-pypi.yml` publishes a tag to PyPI with Trusted Publishing.
- The release workflow attaches the wheel, the sdist and `SHA256SUMS` to a release that
  already exists (for example one made in the web UI), and does not fail.

## [1.2.0] - 2026-11-03

### Added

- **`scgraph scan`**: scan real lockfiles. Ten formats: `package-lock.json` (v1 to v3),
  `yarn.lock` (classic and Berry), `poetry.lock`, `uv.lock`, `requirements*.txt`,
  `Pipfile.lock`, `Cargo.lock`, `Gemfile.lock`, `composer.lock` and `go.mod`.
  - The lockfile becomes a `scgraph.core.TypedGraph`. Exposure search is `find_paths`.
    The verdict is a `Ladder` with five gates: withdrawn, path, scope, severity, ignored.
  - Each alert shows the shortest dependency path. A production path has priority
    over a dev path.
  - OSV records for one issue (GHSA, PYSEC, CVE) merge into one finding.
  - Malicious packages (OSV `MAL-`) are P0 and alert in dev dependencies too.
  - CISA KEV and FIRST EPSS set the priority (P0 to P4).
  - Fix plan: the smallest safe version per package. For npm, the smallest
    direct-dependency bump that removes the vulnerable child.
  - Output: text, JSON, SARIF 2.1.0 and Markdown. `--fail-on` sets the exit code.
  - Incident mode (`--advisory ID`) and a portfolio view for many lockfiles.
  - `.scgraph-ignore` entries with an expiry date (`until=YYYY-MM-DD`).
  - Offline mode (`--offline DIR`, `scgraph fetch-osv`, `SCGRAPH_OSV_DIR`) with an index
    per dump. A warm offline scan of a 90-package lockfile takes about 2 s.
- **`scgraph check`**: a pre-install guard. It blocks names that are not in the
  registry, malicious releases and missing versions. It warns about fresh releases
  (48 h cooldown), new packages, typosquats, install scripts, sdist-only versions,
  deprecated or yanked versions and known vulnerabilities. A failed lookup is
  `unverified`, never `allow`.
- **`scgraph hook claude-code`**: a `PreToolUse` hook that checks the packages in each
  shell command before an agent runs it.
- **`scgraph mcp`**: a Model Context Protocol server with no extra dependencies. Tools:
  `check_package`, `scan_lockfile`, `explain_advisory`.
- `action.yml` (GitHub Action with SARIF upload) and `.pre-commit-hooks.yaml`.
- `examples/` with three sample lockfiles, one of them a reconstruction of the
  September 2025 npm compromise.
- `scripts/make_scan_figures.py`, three figures and `results/metrics/scan_examples.json`.
- `docs/scan.md` and `docs/responsible-use.md`.

## [1.1.0] - 2026-11-02

### Added

- **`scgraph.core`**, the domain-agnostic engine: `TypedGraph` (typed nodes, named
  relations, per-edge confidence, validity window and provenance, content fingerprint,
  pickle-free mmap persistence), `find_paths` (evidence paths with product confidence
  and explicit truncation), `Ladder`/`Gate` (alert or abstain with a reason) and
  `Ledger` (bitemporal, hash-chained, file-locked change log with as-of views,
  compaction and verifiable answer receipts).
- **`scgraph.adapters.software`**: the CVE pipeline on the core engine; publication
  dates become edge validity, so as-of audits use the same mechanism as any domain.
- `docs/core.md`.
- `scripts/demo.py` and `make demo`: one abstention and one exposure path, no data needed.
- OpenSSF Scorecard workflow and README badge.
- Release workflow: a `vX.Y.Z` tag tests, builds and publishes a GitHub Release with
  `SHA256SUMS`.
- `scripts/bench/bench_kgstore.py` and `make bench`: build, load and audit latency on a
  synthetic heavy-tailed graph of any size.

### Changed

All numbers come from `make bench` (2M versions, 8M edges). See `docs/performance.md`.

- **Load time of the store: 1.34 s to 0.020 s (67x faster).** The store does not use
  pickle now. Strings are a UTF-8 block plus offsets, and both are memory-mapped.
- **Build time of the store: 21.7 s to 7.7 s (2.8x faster).** One 1-D sort replaces a
  sort of structured rows. One `bincount` replaces a scatter.
- **Projection onto the core graph: 29.0 s to 12.5 s (2.3x faster).** Arrow makes the
  node keys and parses the dates.
- **First key lookup: 1.4 s to less than 1 ms.** The build step saves the sort order of
  the keys. A lookup is a binary search.
- **Security: a graph directory cannot run code at load.** A directory from 1.0 gives an
  error. To change it once, run `python -m scgraph.kgstore --migrate DIR`.
- **Security: `fetch_artifacts.py` needs a pinned sha256.** To continue without one, use
  `--allow-unverified`. Only HTTPS is permitted. A stalled download stops after 120 s.
- The on-disk format of `scgraph.core.graph` is `/2`. The code can still read `/1`.

> **How I did it:** I removed every pickled array and kept strings as one UTF-8 block
> plus offsets, so the store opens with memory maps and no code runs. I then replaced
> each per-row Python loop on the build and load paths with one NumPy or Arrow operation.

### Fixed

- `paths.exposure_paths(min_severity=...)` had no effect. Now it removes advisories with
  a score below the limit. It keeps advisories with no score, as the ladder does.
- A corpus with zero packages caused a division by zero in `build`. Now `build` makes an
  empty store.

## [1.0.0] - 2026-11-01

First public release. The pipeline was built and validated on the full open-source
dependency graph (8 ecosystems: 4,460,049 packages, 21,415,461 versions, 82,807,953
resolved edges, 285,698 advisories).

### Added

- **Engine (`src/scgraph/`, 25 modules)** in seven layers: data acquisition and parsing,
  the CSR memmap graph store, structural analysis (degree law, k-core, cycles,
  articulation points, reverse PageRank, densification, community detection, temporal
  trajectories), deterministic grounding and exposure-path traversal, the seven-gate
  alert ladder, remediation as an integer linear program, reports with a CycloneDX SBOM,
  an optional GPU model layer (embeddings, reachability prior, GraphSAGE, a severity
  check from advisory text), and a system layer (capability graph, coordinated run,
  versioned run graph with dependency-graph bisect).
- **Notebook** `notebooks/supply_chain_graph_engineering.ipynb`: 10 parts, 41 sections,
  with all outputs and figures from the full run.
- **Evaluation suite** (`scripts/run_evaluation.py`): query latency and throughput, a
  Clauset bootstrapped power-law goodness-of-fit test, resolver fidelity against
  deps.dev, a feature ablation across three decision surfaces, and a comparison with
  `osv-scanner` on 150 lockfiles.
- **Committed results** (`results/`): figures, approximately 25 metric files, 11 exposure
  reports, and the portfolio SBOM.
- **Additional figures**: ecosystem composition, centrality leaders, and the results
  scorecard.
- **CLIs** (`scripts/`): acquire (smoke and full), run the pipeline, build the graph, run
  the evaluation suite, fetch release artifacts, run the notebook.
- Tools: `pyproject.toml` with ruff, mypy, pytest, and coverage configuration; a
  `Makefile`; pre-commit hooks; GitHub Actions for CI and a nightly smoke-profile notebook
  run.

### Known limits

- Three metrics are partly tautological or lexical. `docs/evaluation.md` and notebook
  section S28 mark them: the "100% path retention" value (real parse retention is
  96.64%), the ablation-monotonicity consistency check, and the semantic-relevance AUROC
  (partly text overlap).
- The model layer needs a CUDA GPU. The full Parquet corpus and the embeddings are not in
  git. They are GitHub Release assets.

[1.1.0]: https://github.com/YashhMahajan/Graph-Engineering-for-SupplyChain/releases/tag/v1.1.0
[1.0.0]: https://github.com/YashhMahajan/Graph-Engineering-for-SupplyChain/releases/tag/v1.0.0
