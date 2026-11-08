# The `scgraph` command

`scgraph` checks the dependencies that a project really installs. It reads the
lockfile, not a guess of the tree. Each alert shows the dependency path that proves
it. Each finding that is not an alert shows the reason.

```bash
pipx install scgraph-cli             # or: uvx --from scgraph-cli scgraph scan .
scgraph scan .
```

## `scgraph scan`

```bash
scgraph scan [PATH ...] [options]
```

`PATH` is a lockfile or a directory. In a directory, scgraph finds every lockfile. It
does not go into `node_modules`, `.venv`, `vendor`, `target` or hidden directories.

| lockfile | ecosystem | edges |
|---|---|---|
| `package-lock.json`, `npm-shrinkwrap.json` (v1, v2, v3) | npm | yes |
| `yarn.lock` (classic and Berry) | npm | yes |
| `pnpm-lock.yaml` (lockfile v6 to v9) | npm | yes |
| `bun.lock` (the text lockfile) | npm | yes |
| `poetry.lock`, `uv.lock` | PyPI | yes |
| `requirements*.txt`, `Pipfile.lock` | PyPI | no (flat) |
| `Cargo.lock` | crates.io | yes |
| `Gemfile.lock` | RubyGems | yes |
| `composer.lock` | Packagist | yes |
| `go.mod` | Go | no (flat) |
| `gradle.lockfile`, `buildscript-gradle.lockfile` | Maven | no (flat) |
| `*.cdx.json`, `bom.json` (CycloneDX JSON) | from each purl | yes |
| `*.spdx.json` (SPDX JSON) | from each purl | yes |

A prefixed name also works, for example `api.uv.lock` or `web.package-lock.json`.

### SBOMs, pnpm, Bun and Gradle

- **SBOMs** (`app.cdx.json`, `bom.json`, `app.spdx.json`) are scanned like a lockfile, so a
  container SBOM from `syft` or a build's SBOM works too. The ecosystem comes from each
  component's **purl**, so one file can mix npm, PyPI, Maven, Cargo and more (the result
  reports the ecosystem as `mixed`). A component with no purl, an unsupported purl type
  (for example `deb`) or no version is **skipped**, because OSV cannot match it, and an
  SBOM that carries no dependency relationships has no paths to show. CycloneDX
  `cdx:npm:package:development` marks a dev dependency.
- **`pnpm-lock.yaml`** from pnpm 8 and 9 (lockfile v6 and later). Peer-dependency suffixes
  are folded into one package, aliased dependencies resolve to the real package, and
  workspace links are skipped. pnpm 7 and older (lockfile v5) is refused with a message,
  not read wrongly.
- **`bun.lock`** is Bun's text lockfile (Bun 1.2 and later). The older binary `bun.lockb`
  is not read: run `bun install --save-text-lockfile` to create `bun.lock`.
- **Gradle** `gradle.lockfile` records no edges, so every package is a direct dependency. One
  that only test configurations use is dev. `pom.xml` is not read: Maven resolves versions
  at build time, so a pom alone does not say what is installed.

### What happens

1. scgraph parses the lockfile into a graph. The root has edges to the direct
   dependencies. Each edge is a field in the lockfile.
2. scgraph asks OSV which package versions have advisories. OSV includes the
   OpenSSF malicious-packages data as `MAL-` records.
3. Records that name the same issue (GHSA, PYSEC, CVE) become one finding.
4. A breadth-first search finds the shortest path from the root to each finding.
   A path through production dependencies has priority over a dev path.
5. Each finding goes through the gates. The first gate that stops it is the reason.
6. scgraph calculates the smallest safe upgrade. For npm, it also finds the smallest
   upgrade of the direct dependency that removes the vulnerable child.

### The gates

| gate | the finding stops when |
|---|---|
| `withdrawn` | the advisory is withdrawn |
| `path` | no path from a declared root reaches the package |
| `scope` | only dev dependencies reach the package. Malicious packages do not stop here, because install scripts run in CI and on laptops. |
| `severity` | the CVSS score is below `--min-severity`. Malicious and CISA KEV findings do not stop here. |
| `ignored` | an entry in the ignore file matches and is not expired |

### Priorities

| priority | meaning |
|---|---|
| P0 | a malicious release |
| P1 | actively exploited (CISA KEV) |
| P2 | critical (CVSS 9.0 or more) or EPSS 0.1 or more |
| P3 | high (CVSS 7.0 or more) |
| P4 | all other alerts |

### Options

| option | effect |
|---|---|
| `-f, --format` | `text` (default), `json`, `sarif`, `markdown`, `openvex`, `html` |
| `-o, --output FILE` | write the report to a file |
| `--fail-on LEVEL` | exit 1 at this priority or worse: `P0` to `P4`, `any` (default), `never` |
| `--min-severity N` | CVSS floor |
| `--include-dev` | alert on dev-only dependencies |
| `--advisory ID` | incident mode: report only this advisory. Use it more than once for a list. |
| `--ignore-file FILE` | ignore list. The default is `.scgraph-ignore` if it exists. |
| `--offline DIR` | use OSV dumps in `DIR`, not the OSV API |
| `--no-signals` | do not get CISA KEV and EPSS |
| `--no-registry` | do not get registry data for the direct-dependency bump |
| `--summary FILE`, `--github-summary` | also write a Markdown summary |
| `-v` | show each abstention and each advisory |

Exit codes: `0` no alert at the `--fail-on` level, `1` alerts, `2` error.

### Incident mode

An advisory is public. You must know which repositories it reaches.

```bash
scgraph scan ~/src --advisory CVE-2021-44228 --advisory GHSA-jfh8-c2jp-5v3q
```

The last section of the output lists each package and each lockfile that it reaches.
`--format json` gives the full list.

### The ignore file

```text
# .scgraph-ignore
GHSA-29mw-wpgm-hmr9  until=2027-01-31  # not reachable: we never call _.template
CVE-2024-45590                         # fixed by our proxy limits
```

An entry with `until=` stops after that date. Then the alert comes back. This
prevents old ignores that nobody reads again.

### Offline and air-gapped use

```bash
scgraph fetch-osv --dir osv npm pypi cargo
scgraph scan . --offline osv
export SCGRAPH_OSV_DIR=$PWD/osv     # use the dumps for check, hook and mcp too
```

The first offline scan of an ecosystem builds an index next to the dump. Later
scans read only the records they need.

## `scgraph check`

```bash
scgraph check npm left-pad@1.3.0 lodash
scgraph check pypi requests==2.32.3
```

Use it before you add a dependency. The result is `ALLOW`, `WARN` or `BLOCK`.

| result | reason |
|---|---|
| BLOCK | the name is not in the registry (a hallucinated name, the target of slopsquatting) |
| BLOCK | the version is a known malicious release |
| BLOCK | the version is not in the registry |
| WARN | the release is younger than `--cooldown` hours (default 48) |
| WARN | the package is younger than 30 days |
| WARN | the name is one edit from a popular package |
| WARN | npm install scripts, or a PyPI version with no wheel |
| WARN | npm release anomalies (see below) |
| WARN | deprecated, yanked, or known vulnerabilities |
| WARN | scgraph cannot check the registry or OSV (`unverified`) |

scgraph does not change "cannot check" into "safe". Exit codes: `0` allow, `1` warn,
`2` block.

### Release anomalies (npm)

The September 2025 to 2026 npm worms published malicious versions of real packages. Some
carried **valid Sigstore provenance**, because the attacker ran the build inside the
maintainers' own CI. Provenance shows where a package was built, not who asked for the
build, so `scgraph check` also compares a release with the one before it, using only
fields the registry already returns (no extra request):

| code | fires when |
|---|---|
| `publisher_changed` | a different account published it than the previous release |
| `maintainer_added` | the maintainer list gained a name |
| `provenance_dropped` | the previous release had a provenance attestation and this one has none |
| `install_script_added` | it has a `preinstall`, `install` or `postinstall` script and the previous release had none (replaces the generic `install_scripts` warning) |
| `backport_published` | it was published after a higher stable version existed |
| `publish_burst` | five or more versions appeared within fifteen minutes |

Only releases from the last 14 days are examined, because a release that has survived for
months is not suspicious for who published it. Every signal is a **warning** with the
evidence in the message, never a block: each has innocent causes (a team changes its
publisher, a project backports a fix), so the guard states the cause and lets a person
judge. PyPI, crates.io and the other registries do not return this history in the
document the guard fetches, so for them these signals are not checked. If the comparison
itself fails, the result is `unverified`, never clean.

## AI coding agents

### Claude Code hook

Add this to `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "scgraph hook claude-code"}]}
    ]
  }
}
```

The hook reads each shell command before it runs. It finds the packages that the
command installs or runs: `npm`, `pnpm`, `yarn`, `bun`, `npx`, `pip`, `uv`, `uvx`,
`poetry`, `pipx`, `cargo`, `gem`, `composer` and `go get`. A `BLOCK` denies the
command. A `WARN` asks you. An `ALLOW` does nothing, so your usual permissions apply.

### MCP server

```bash
claude mcp add scgraph -- scgraph mcp
```

The server has no extra dependencies. It has three tools:

| tool | use |
|---|---|
| `check_package` | before the agent adds or runs a package |
| `scan_lockfile` | scan a lockfile or a directory, with paths and a fix plan |
| `explain_advisory` | summary, affected ranges, fixed versions, KEV and EPSS for one id |

## CI

### GitHub Action

Scan everything on a push, and judge a pull request only on what it introduces (see
[`scgraph diff`](#review-a-pull-request-scgraph-diff)):

```yaml
name: dependencies
on: [push, pull_request]
permissions:
  contents: read
  security-events: write   # for the SARIF upload
jobs:
  scgraph:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: YashhMahajan/Graph-Engineering-for-SupplyChain@v1.2.1
        with:
          fail-on: P2
```

The action uploads SARIF to code scanning and writes a summary to the job page.

For pull requests, add a second job with `mode: diff`. It compares with the base branch,
writes the summary and edits one sticky comment. Use `pull_request`, not
`pull_request_target`: the comment step tolerates the read-only token a fork gets, and
never check out and run fork code with a write token.

```yaml
  review:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write   # for the sticky comment
    steps:
      - uses: actions/checkout@v5
      - uses: YashhMahajan/Graph-Engineering-for-SupplyChain@v1.2.1
        with:
          mode: diff
```

### pre-commit

```yaml
repos:
  - repo: https://github.com/YashhMahajan/Graph-Engineering-for-SupplyChain
    rev: v1.2.1
    hooks:
      - id: scgraph-scan
```

The hook runs only when a lockfile changes. It blocks malicious and exploited
dependencies (`--fail-on P1`).

## HTML report

`scgraph scan . --format html -o report.html` writes one self-contained page: no script,
no remote resource, collapsible dependency paths and the fix for each alert. Every
lockfile-derived string is escaped, advisory links are percent-encoded, and a strict
Content-Security-Policy `<meta>` forbids scripts and network loads even if an escape were
ever missed, so the file is safe to attach to a ticket or open from an email.

## Import-level hint: `--imports`

```bash
scgraph scan . --imports
```

Marks each alert `imported` or `not imported`: does the project's own source import the
dependency at the top of the alert's path (the package itself when it is direct, otherwise
the direct dependency that pulls it in)? It is a **hint, not a call graph**. It never
suppresses an alert and never changes the exit code.

- JavaScript and TypeScript: `require`, `import ... from`, `import 'x'` and dynamic
  `import()` are recognised. `not imported` means no source file imports it. A package used
  through configuration (a Babel or ESLint plugin, a Jest preset, a bundler loader) is never
  imported in source, so it can show `not imported` while being in use.
- PyPI: only `imported` is ever shown. A distribution and its import name differ (`pyyaml` is
  imported as `yaml`), so not seeing the name proves nothing.
- Other ecosystems, and projects with no source files, show nothing.
- It does not answer "is the vulnerable function called".

## Review a pull request: `scgraph diff`

```bash
scgraph diff --base origin/main            # text
scgraph diff --base origin/main -f markdown -o comment.md
```

A scan of a large repository reports every inherited vulnerability, so a pull request
that adds nothing still looks red. `scgraph diff` scans each lockfile at `--base` and in
the working tree and reports **only the difference**:

- **new alerts**, each with the dependency path that brought it in
- **resolved** alerts the change fixes
- the package changes behind them (added, removed, version changes)
- the count of alerts that were already there, so the debt stays visible

The exit code counts new alerts only (`--fail-on`, default `any`), so a change that adds
no alert passes even in a repository full of old ones. Rules:

- Alerts are compared with alerts. A finding that was abstained at the base and alerts
  now, for example a dependency moved from `devDependencies` to `dependencies`, is new.
- A lockfile that does not exist at the base is entirely new. A lockfile the change
  deletes is not reported.
- Both sides are read from text the same way, and registry lookups are skipped.
- The Markdown output starts with a hidden `<!-- scgraph-diff -->` marker, so CI can edit
  one comment instead of posting a new one on every push. Every lockfile-derived string is
  neutralised first: the author of a pull request controls the lockfile, and a package
  name must not be able to close a code span, add a table cell or inject HTML.
- `--base` must name a commit in the local clone. In CI, fetch it (the Action does).
  A ref that looks like an option (`-p`) is refused. A lockfile outside the git
  repository is an error.

`diff` takes the same options as `scan`: `--min-severity`, `--include-dev`, `--vex`,
`--ignore-file`, `--offline`, `--no-signals` and `--no-registry`.

## Scan history: when were we first exposed?

```bash
scgraph scan . --history .scgraph-history          # record this scan
scgraph history .scgraph-history --advisory CVE-2021-44228
scgraph history .scgraph-history --advisory CVE-2021-44228 --receipt answer.json
scgraph history .scgraph-history --check answer.json
scgraph history .scgraph-history --verify
```

`--history DIR` records each scan in a bitemporal, hash-chained ledger (`scgraph.core.Ledger`).
An exposure opens at the first recorded scan that alerts on an advisory and closes at the
first later scan that does not, so the history shows first exposure, the fix, and any
regression as separate episodes. Any alias works in a query (GHSA, CVE, PYSEC).

- A window starts at the **first recorded scan that alerted**, not when the code became
  vulnerable. It can only be as early as you began recording.
- `--receipt` writes the ledger's verifiable receipt for the answer, and `--check` verifies
  it later: the log is hash-chained, so editing or deleting a past scan breaks `--verify`.
- Exit code of `history --advisory`: `1` while any episode is still open, else `0`.
- "Alert" means what that scan's policy said, so record with the same options each time.
  `--history` cannot be combined with `--advisory`, because a subset scan would close
  every exposure it did not look at.

## Audit agent and IDE config: `scgraph audit`

```bash
scgraph audit                # the project in the current directory
scgraph audit -v             # also list every command that starts on its own
scgraph audit --offline-check
```

Later waves of the Shai-Hulud worm did not need `npm install`. They added files that run
code when a developer opens the repository or starts a coding agent, such as a
`runOn: folderOpen` task in `.vscode/tasks.json` or a hook in `.claude/settings.json`.
Reviewers read source diffs and skip these files, so `scgraph audit` reads them.

It looks at the project's own `.mcp.json`, `.claude/settings.json` and
`.claude/settings.local.json`, `.cursor/mcp.json`, `.gemini/settings.json`,
`.vscode/mcp.json` and `.vscode/tasks.json`. It never reads your home directory.

| level | code | meaning |
|---|---|---|
| info | `runs_automatically` | a command that starts on its own (shown with `-v`) |
| warn | `unpinned_package` | an `npx` or `uvx` launcher with no version: a freshly published malicious release would run on the next start |
| warn | `runs_on_folder_open` | a VS Code task that runs when the folder is opened |
| warn | `download_and_execute` | `curl ... \| sh`, `bash -c "$(curl ...)"`, `base64 -d \| sh` and similar |
| warn | `auto_approve_mcp` | `enableAllProjectMcpServers`: a pull request can add an MCP server that starts without a prompt |
| warn | `unreadable` | the file cannot be parsed or is too large, so it was not audited |
| warn or block | `package_*` | the pre-install guard's verdict on a package a launcher fetches (malicious, nonexistent, fresh, typosquat, release anomaly) |

Exit codes match `check`: `0` nothing above info, `1` a warning, `2` a block. An unreadable
file is a warning, never a clean pass. `--offline-check` skips the registry and OSV
lookups and reports only what the files themselves show. Add `scgraph audit` to CI to
catch a pull request that introduces an auto-run entry.

## Python API

```python
from scgraph.scan import scan, Policy

for result in scan(".", policy=Policy(min_severity=7.0)):
    for f in result.alerts:
        print(f.priority, f.id, " -> ".join(f.path), f.fix)
```

## Limits

- `requirements.txt`, `Pipfile.lock`, `go.mod` and `gradle.lockfile` have no edges. Each
  package shows as a direct dependency.
- `bun.lockb` (binary) and `pom.xml` are not read, see above.
- The direct-dependency bump is for npm only.
- A path shows that the package is installed. It does not show that your code calls
  the vulnerable function.


## VEX output

`scgraph scan . --format openvex` writes an [OpenVEX](https://openvex.dev) 0.2.0 document,
so the "why is this not an alert" answers travel with your SBOM.

| scgraph verdict | VEX statement |
|---|---|
| alert | `affected`, with the fix and the dependency path as the action statement |
| abstained: `path` (no path from a declared root) | `not_affected`, `component_not_present` |
| abstained: `scope` (dev dependencies only) | `not_affected`, `vulnerable_code_not_in_execute_path` |
| abstained: `withdrawn`, `severity`, `ignored` | no statement |

Only abstentions that make a claim about exploitability become `not_affected`. A severity
floor and an ignore entry are policy (an ignore can mean "accepted risk"), and a withdrawn
advisory is not a vulnerability, so none of those three is written as a VEX claim. The
`scope` justification is inferred from the lockfile graph, not from a call graph, and the
statement says so.

Each statement's product is `pkg:generic/<project>?lockfile=<relative path>`, so two
projects with the same folder name stay distinct. A lockfile outside the working
directory gets `?path-sha256=<hash>` instead, so parent directories are not published.
With `--advisory` (incident mode) only the matching advisories are scanned, so the VEX
document covers only those advisories. Do not publish it as the project's full VEX.

### Applying a supplier's VEX

```bash
scgraph scan . --vex supplier.vex.json
```

A `not_affected` or `fixed` statement turns a matching finding into an abstention with the
reason `vex`. It never disappears from the counts. Rules:

- A statement matches on the advisory id **or any alias** (GHSA, CVE, PYSEC) and on the
  package purl. A purl without a version covers every version.
- For one advisory and package, the **newest timestamp wins**, so a later `affected`
  statement revokes an earlier `not_affected`.
- Only `not_affected` and `fixed` suppress. `affected` and `under_investigation` never do.
- **Malicious packages are never suppressed**, whatever the file says.
- Parsing is strict. A `not_affected` without a justification or impact statement, an
  unknown status or a bad purl stops the scan with exit code 2, because silently ignoring
  one statement could hide a real finding. Repeat `--vex` to merge several files.

