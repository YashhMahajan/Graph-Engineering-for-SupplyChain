# CLAUDE

@docs/AGENTS.md

This file is the memory of the project for AI agents. Claude Code reads it at the start of a session.
It follows the ASD-STE100 rules for Simplified Technical English. It has no secret values.

## How to use this file

1. Read the whole file at the start of a session.
2. Do the work. Use [docs/AGENTS.md](docs/AGENTS.md) for the rules and commands.
3. At the end of the session, update **Short-term memory**. Remove items that are done.
4. Add to **Long-term memory** only a fact that stays true and that the code does not show.
5. Keep the file under 150 lines. Delete a line when it is wrong.

## Short-term memory

Last updated: 2026-11-13.

State:

- `main` has the symbols work and PR #27 (docs pinned to v1.4.0). The docs are 6 files.
  `MEMORY.md` is gone: this file holds the memory.
- Version 1.4.0 is set in `pyproject.toml`, `CITATION.cff` and the changelog. The user approved
  the release and the tag on 2026-11-13. Steps: merge the data PR, then
  `gh workflow run release.yml` (tags `v1.4.0`, publishes the GitHub Release), then
  `gh workflow run publish-pypi.yml -f tag=v1.4.0`. If a tool blocks the command, ask the user to
  run it.
- The datasets are signed. If you change a `*.jsonl` file in `src/scgraph/symbols/data/`, you must
  sign it again: `scgraph symbols sign`. The private key is `~/.config/scgraph/signing.key`.

Open:

1. **Data refresh (points 5 and 9).** Branch `data/symbols-refresh-2` runs `make symbols-refresh`
   (30 + 5 + 5 LLM requests). Then: `scgraph symbols verify`, `scgraph symbols sign`, tests, ruff,
   mypy, a pull request with the changed data and `results/metrics`. Merge when CI passes.
2. **Point 7, wider datasets.** The build with `--popular 5000` (PyPI) and `3000` (npm) did not
   finish: it is heavy. Run it on a quiet machine, with `nice`, never with the refresh.
   Maven and Cargo scan-side support is out of scope.
3. Send OSV patches to an advisory database only when the user says so.

## Long-term memory

User preferences:

- The user wants small, simple changes and lean docs. Do not add features that no one asked for.
- The user wants numbers in the README that engineers see first. Use measured numbers only.
- The user wants Simplified Technical English in the docs.
- The user allows an agent to merge a pull request when all CI checks pass. The user does not
  allow publishing a release or sending anything to another project.

Decisions and reasons:

- **No model in a scan.** This is the main strength of the project. A model works at build time
  and its output is verified and signed.
- **A verdict never closes an alert.** The call graph is name-based and over-approximates.
- **Hand-set ranker, not a trained one.** The trained model lost on validation.
- **Default LLM model is `baidu/ernie-5.5-flash-preview:free`.** `inkling-2-small:free` answers
  HTTP 403 to an ordinary key. Do not try to pass as another client.
- **Answers are cached per advisory.** A changed prompt makes old answers miss. Change it rarely.
- **No search records without an LLM confirmation.** Search alone is right less than half the time.
- **Maven and Cargo scan-side support is out of scope.** No parser and no dataset exist for them.
- **The docs are 6 files in `docs/`.** Do not add more without a reason.

Facts about the environment:

- The API key is in `.env` (ignored by Git). Never print it or commit it.
- The free tier gives 50 requests a day per key. The reset is at 00:00 UTC.
- OSV dumps are in `data/raw/osv/` (ignored by Git). `scgraph fetch-osv` downloads them.
- macOS ignores case in file names. Use `git mv` to change the case of a file name.
- CI runs Linux and Windows on Python 3.11 and 3.12, plus lint and a notebook run.

Past lessons:

- A check that passes on Linux can fail on Windows (file modes, line endings). Test both.
- Run ruff before every commit. A `&&` chain does not stop on `ruff check` output unless you
  read the exit code.
- A metric can look good while the system is wrong. See [docs/ISSUES.md](docs/ISSUES.md).
