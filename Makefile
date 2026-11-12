# scgraph developer tasks. Run `make help` for the list.
# Windows without GNU make: the equivalent commands are in CONTRIBUTING.md.

PY ?= python
VENV ?= .venv
BIN := $(VENV)/bin
ifeq ($(OS),Windows_NT)
	BIN := $(VENV)/Scripts
endif

.DEFAULT_GOAL := help
.PHONY: help setup lint fmt test test-all cov smoke graph notebook eval symbols-eval symbols-refresh plotpack figures build clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

setup: ## Create the venv and install the package with dev extras
	$(PY) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -e ".[dev,notebook]"
	$(BIN)/pre-commit install

lint: ## ruff check + ruff format --check + mypy
	$(BIN)/ruff check .
	$(BIN)/ruff format --check .
	$(BIN)/mypy src/scgraph

fmt: ## Auto-fix with ruff
	$(BIN)/ruff check --fix .
	$(BIN)/ruff format .

test: ## Run unit tests (no network)
	$(BIN)/pytest -m "not network"

test-all: ## Run every test, including the networked smoke pipeline
	$(BIN)/pytest

cov: ## Run tests with a coverage report
	$(BIN)/pytest -m "not network" --cov=scgraph --cov-report=term-missing

smoke: ## Acquire the smoke corpus and run the pipeline end to end
	$(BIN)/python scripts/acquire_smoke.py
	$(BIN)/python scripts/run_pipeline.py --profile smoke

graph: ## Rebuild the CSR graph store from data/parquet
	$(BIN)/python scripts/build_graph.py

demo: ## Print one abstention and one exposure path (10 seconds, no data needed)
	$(BIN)/python scripts/demo.py

bench: ## Benchmark build, load and audit latency on a synthetic 2M-version graph
	$(BIN)/python scripts/bench/bench_kgstore.py --versions 2000000 --audits 1000

notebook: ## Execute the notebook on the smoke profile (overwrites its outputs locally)
	$(BIN)/python scripts/_run_notebook.py notebooks/supply_chain_graph_engineering.ipynb scgraph 1500

eval: ## Run the evaluation suite (needs data/graph and network)
	$(BIN)/python scripts/run_evaluation.py --all

symbols-refresh: ## Spend the free-tier LLM budget on what is open, then sign (run after the daily reset)
	$(BIN)/python scripts/symbols/build_dataset.py --ecosystem npm --popular 3000 --fix 800 --search 100 --llm-requests 20 --search-needs-llm --merge
	$(BIN)/python scripts/symbols/build_dataset.py --ecosystem pypi --popular 5000 --fix 1500 --search 150 --llm-requests 20 --search-needs-llm --merge
	$(BIN)/python scripts/symbols/eval_go.py --llm-requests 6 --llm-batch 6
	$(BIN)/python -m scgraph.cli symbols sign

symbols-eval: ## Vulnerable-symbol inference on the Go database (model-free stages; network once)
	$(BIN)/python scripts/symbols/go_eval_set.py --prefetch
	$(BIN)/python scripts/symbols/prefetch_releases.py --split test
	$(BIN)/python scripts/symbols/eval_go.py
	$(BIN)/python scripts/symbols/eval_entry.py

plotpack: ## Make the plotting-data bundle
	$(BIN)/python scripts/make_plotpack.py

figures: ## Make the extra figures from results/metrics
	$(BIN)/python scripts/make_extra_figures.py

build: ## Build the wheel and sdist
	$(BIN)/python -m build

clean: ## Remove caches and build artifacts
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage coverage.xml
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
