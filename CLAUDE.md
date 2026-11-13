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
- Release 1.4.0 is **tagged and on GitHub** (`v1.4.0`, 2026-11-13, with wheel, sdist and
  `SHA256SUMS`). It is **not on PyPI**: `publish-pypi.yml` failed with `invalid-publisher`.
  PyPI has no `scgraph-cli` project and no trusted publisher. The user must add a pending
  publisher on pypi.org (owner `YashhMahajan`, repo `Graph-Engineering-for-SupplyChain`,
  workflow `publish-pypi.yml`, environment `pypi`). Then run
  `gh workflow run publish-pypi.yml -f tag=v1.4.0`.
- The datasets are signed. If you change a `*.jsonl` file in `src/scgraph/symbols/data/`, you must
  sign it again: `scgraph symbols sign`. The private key is `~/.config/scgraph/signing.key`.

Open:

1. **PyPI upload of 1.4.0.** See State above. The data refresh is done (PR #28).
2. **Point 7, wider datasets.** The build with `--popular 5000` (PyPI) and `3000` (npm) did not
   finish: it is heavy. Run it on a quiet machine, with `nice`, never with the refresh.
   Maven and Cargo scan-side support is out of scope.
3. Send OSV patches to an advisory database only when the user says so.

## Long-term memory

User preferences:

- The user wants small, simple changes and lean docs. Do not add features that no one asked for.
- The user wants numbers in the README that engineers see first. Use measured numbers only.
- The user wants Simplified Technical English in the docs.
- The user wants LLM requests spent only on what is needed. The daily 50 is a ceiling, not a
  target. Do not use a request to fill the budget.
- The user allows an agent to merge a pull request when all CI checks pass. The user allows a release
  and a tag only when the user says so for that version. The user does not allow sending anything
  to another project.

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
