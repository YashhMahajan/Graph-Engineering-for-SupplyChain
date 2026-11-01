# Changelog

This file records all important changes to this project. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- `scripts/bench/bench_kgstore.py` and `make bench`: build, load and audit latency on a
  synthetic heavy-tailed graph of any size.

### Changed

- **Graph store no longer uses pickle.** String columns are a UTF-8 blob plus int64
  offsets, memory-mapped (`scgraph.core.strings.StrColumn`). Loading a graph directory
  can no longer execute code. Directories from 1.0 are refused with a clear error;
  convert them with `python -m scgraph.kgstore --migrate DIR`.
- **Faster.** Measured with `make bench` on 2M versions / 8M edges, same machine:
  `KGStore()` load 1.27 s -> 0.06 s (21x); `build` 22.1 s -> 6.8 s (3.3x);
  `adapters.software.from_kgstore` 29.0 s -> 12.5 s; first core key lookup 1.4 s -> 0 on a
  loaded graph (persisted sort order + binary search). Ledger views at 1M nodes / 5M edges:
  first verified snapshot load 1.2 s -> 0.6 s.
- `scripts/fetch_artifacts.py` refuses to extract assets without a pinned sha256 unless
  `--allow-unverified` is passed, refuses non-HTTPS URLs and times out stalled downloads.
- `scgraph.core.graph` on-disk format is now `/2` (keys as a string column plus a
  fingerprinted lookup index).

### Fixed

- `paths.exposure_paths(min_severity=...)` was ignored; it now drops advisories scored
  below the floor (unscored advisories are kept, as the ladder does).

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

[1.0.0]: https://github.com/YashhMahajan/Graph-Engineering-for-SupplyChain/releases/tag/v1.0.0
