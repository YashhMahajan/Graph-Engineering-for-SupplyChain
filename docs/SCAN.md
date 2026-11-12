# The `scgraph` command

`scgraph` checks the dependencies that a project really installs. It reads the lockfile. It does
not guess the tree. Each alert shows the dependency path that proves it. Each finding that is not
an alert shows the reason. This page follows the ASD-STE100 rules for Simplified Technical English.

```bash
pipx install "scgraph-cli[symbols-js]"     # the extra adds npm and TypeScript support
scgraph scan .
```

## `scgraph scan`

```bash
scgraph scan [PATH ...] [options]
```

`PATH` is a lockfile or a directory. In a directory, scgraph finds every lockfile. It does not
enter `node_modules`, `.venv`, `vendor`, `target` or hidden directories.

| Lockfile | Ecosystem | Edges |
|---|---|---|
| `package-lock.json`, `npm-shrinkwrap.json` (v1, v2, v3) | npm | yes |
| `yarn.lock` (classic and Berry) | npm | yes |
| `pnpm-lock.yaml` (v6 to v9) | npm | yes |
| `bun.lock` (the text lockfile) | npm | yes |
| `poetry.lock`, `uv.lock` | PyPI | yes |
| `requirements*.txt`, `Pipfile.lock` | PyPI | no (flat) |
| `Cargo.lock` | crates.io | yes |
| `Gemfile.lock` | RubyGems | yes |
| `composer.lock` | Packagist | yes |
| `go.mod` | Go | no (flat) |
| `gradle.lockfile`, `buildscript-gradle.lockfile` | Maven | no (flat) |
| `*.cdx.json`, `bom.json` (CycloneDX) | from each purl | yes |
| `*.spdx.json` (SPDX) | from each purl | yes |

A prefixed name also works, for example `api.uv.lock`.

Notes on formats:

- **SBOMs** are scanned like a lockfile. The ecosystem comes from the purl of each component. A
  component with no purl, an unsupported purl type or no version is skipped.
- **pnpm** lockfile v5 and older is refused with a message. It is never read wrongly.
- **`bun.lockb`** (binary) is not read. Run `bun install --save-text-lockfile`.
- **Gradle** lockfiles record no edges, so every package is a direct dependency. `pom.xml` is not
  read, because Maven resolves versions at build time.

### What happens

1. scgraph parses the lockfile into a graph. The root has an edge to each direct dependency.
2. scgraph asks OSV which versions have advisories. OSV includes `MAL-` records for malware.
3. Records for the same issue (GHSA, PYSEC, CVE) become one finding.
4. A breadth-first search finds the shortest path from the root to each finding. A path through
   production dependencies has priority over a dev path.
5. Each finding goes through the gates. The first gate that stops it gives the reason.
6. scgraph finds the smallest safe upgrade. For npm it also finds the smallest upgrade of the
   direct dependency that removes the vulnerable child.

### Gates

| Gate | The finding stops when |
|---|---|
| `withdrawn` | The advisory is withdrawn |
| `path` | No path from a declared root reaches the package |
| `scope` | Only dev dependencies reach the package. Malware does not stop here. |
| `severity` | The CVSS score is below `--min-severity`. Malware and CISA KEV do not stop here. |
| `ignored` | An entry in the ignore file matches and has not expired |

### Priorities

| Priority | Meaning |
|---|---|
| P0 | A malicious release |
| P1 | Actively exploited (CISA KEV) |
| P2 | Critical (CVSS 9.0 or more) or EPSS 0.1 or more |
| P3 | High (CVSS 7.0 or more) |
| P4 | All other alerts |

### Options

| Option | Effect |
|---|---|
| `-f, --format` | `text` (default), `json`, `sarif`, `markdown`, `openvex`, `html` |
| `-o, --output FILE` | Write the report to a file |
| `--fail-on LEVEL` | Exit 1 at this priority or worse: `P0` to `P4`, `any` (default), `never` |
| `--min-severity N` | CVSS floor |
| `--include-dev` | Alert on dev-only dependencies |
| `--advisory ID` | Incident mode: report only this advisory. Repeat the option for a list. |
| `--ignore-file FILE` | Ignore list. The default is `.scgraph-ignore`, if it exists. |
| `--offline DIR` | Use OSV dumps in `DIR` and not the OSV API |
| `--no-signals` | Do not get CISA KEV and EPSS |
| `--no-registry` | Do not get registry data for the direct-dependency bump |
| `--imports` | Hint whether your source imports each dependency |
| `--reachability` | Check whether your code calls the vulnerable function |
| `--deep` | `--reachability`, and also transitive dependencies (downloads sources) |
| `--history DIR` | Record the scan in a ledger |
| `-v` | Show each abstention |

Exit codes: `0` no alert at the `--fail-on` level, `1` alerts, `2` error.

### Incident mode

A new advisory is public. You must find which repositories it reaches.

```bash
scgraph scan ~/src --advisory CVE-2021-44228 --advisory GHSA-jfh8-c2jp-5v3q
```

The end of the output lists each package and lockfile that the advisory reaches.

### The ignore file

```text
# .scgraph-ignore
GHSA-29mw-wpgm-hmr9  until=2027-01-31  # not reachable: we never call _.template
CVE-2024-45590                         # fixed by our proxy limits
```

An entry with `until=` stops working after that date. The alert then comes back.

### Offline use

```bash
scgraph fetch-osv --dir osv npm pypi cargo
scgraph scan . --offline osv
export SCGRAPH_OSV_DIR=$PWD/osv     # the dumps also serve check, hook and mcp
```

The first offline scan of an ecosystem builds an index next to the dump. Later scans read only the
records that they need.

## Does your code call the vulnerable function?

```bash
scgraph scan . --reachability     # direct dependencies: Python, npm, Go
scgraph scan . --deep             # also transitive dependencies of Python and npm
scgraph scan . --imports          # a weaker hint: does your source import the package?
```

Where do the function names come from?

1. **The advisory**, when it names them (OSV `affected_functions`, or `imports[].symbols` in the Go
   database).
2. **The shipped dataset**, when the advisory does not. scgraph recovered the function at build
   time from the fix commit and released source. A verdict that uses the dataset shows
   `(inferred)`. The JSON has the evidence. See [SYMBOLS.md](SYMBOLS.md).

A scan makes **no model call**. It reads the dataset. It reads your source with `ast` (Python),
tree-sitter (JavaScript and TypeScript, extra `symbols-js`) or a pattern match (Go). An alias
resolves: `import yaml as y; y.load(x)` and `const {merge: m} = require('lodash'); m(x)` both match.

| Verdict | Meaning |
|---|---|
| `reachable` | Your source references a vulnerable function, or an entry point that reaches it |
| `class_used` | The vulnerable function is a method, and your source references its class |
| `not_called` | The function names are known, and your source has no reference to any of them |
| `not_analyzed` | The ecosystem is not supported, no names are known, or the package is transitive and you did not pass `--deep` |

`--deep` follows the dependency path backwards through the released source of each package on it
(`app -> requests -> urllib3`). It finds the public names of your **direct** dependency that lead
to the vulnerable function. It needs the network once for each package version. The shortest path
only is analyzed, so `not_called` means "not through this path". The output shows the hop count,
for example `vulnerable function called (inferred, 2 hops)`.

A verdict **never closes an alert** and never changes the exit code. `not_called` means that scgraph
found no reference. It is not proof. A call through `getattr`, `eval`, a plugin registry or a
wrapper is not seen.

`--imports` marks each alert `imported` or `not imported`. It is a hint. A package that is used
through configuration (a Babel plugin, a Jest preset) can show `not imported` while it is in use. For
PyPI it shows only `imported`, because the import name can differ from the package name.

## `scgraph diff`

```bash
scgraph diff --base origin/main
scgraph diff --base origin/main -f markdown -o comment.md
```

A scan of a large repository reports every old vulnerability. `scgraph diff` scans each lockfile at
`--base` and in the working tree, and reports only the difference:

- new alerts, each with its dependency path
- alerts that the change resolves
- the package changes behind them
- the count of alerts that were already there

The exit code counts new alerts only. Rules:

- A finding that did not alert at the base and alerts now is new.
- A lockfile that does not exist at the base is entirely new. A lockfile that the change deletes is
  not reported.
- The Markdown output starts with the hidden marker `<!-- scgraph-diff -->`. CI uses it to edit one
  comment. scgraph neutralizes every string from the lockfile, because the author of the pull
  request controls the lockfile.
- `--base` must name a commit in the local clone. A ref that looks like an option is refused.

`diff` takes the same options as `scan`.

## `scgraph check`

```bash
scgraph check npm left-pad@1.3.0 lodash
scgraph check pypi requests==2.32.3
```

Use it before you add a dependency. The result is `ALLOW`, `WARN` or `BLOCK`.

| Result | Reason |
|---|---|
| BLOCK | The name is not in the registry (a made-up name: the target of slopsquatting) |
| BLOCK | The version is a known malicious release, or is not in the registry |
| WARN | The release is younger than `--cooldown` hours (default 48), or the package is younger than 30 days |
| WARN | The name is one edit from a popular package |
| WARN | npm install scripts, or a PyPI version with no wheel |
| WARN | A release anomaly (see below), a deprecated or yanked version, or known vulnerabilities |
| WARN | scgraph cannot check the registry or OSV (`unverified`) |

scgraph never changes "cannot check" into "safe". Exit codes: `0` allow, `1` warn, `2` block.

### Release anomalies (npm)

Some npm worms published malicious versions of real packages. Some had valid Sigstore provenance,
because the attacker ran the build in the CI of the maintainers. `scgraph check` compares a release
with the one before it. It uses only fields that the registry already returns.

| Code | It fires when |
|---|---|
| `publisher_changed` | A different account published the release |
| `maintainer_added` | The maintainer list has a new name |
| `provenance_dropped` | The previous release had a provenance attestation and this one has none |
| `install_script_added` | The release has an install script and the previous one had none |
| `backport_published` | The release was published after a higher stable version existed |
| `publish_burst` | Five or more versions appeared within 15 minutes |

Only releases of the last 14 days are examined. Each signal is a warning with the evidence in the
message. It is never a block, because each signal has innocent causes.

## AI coding agents

Claude Code hook. Add this to `.claude/settings.json`:

```json
{"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "scgraph hook claude-code"}]}]}}
```

The hook reads each shell command before it runs. It finds the packages that the command installs
or runs (`npm`, `pnpm`, `yarn`, `bun`, `npx`, `pip`, `uv`, `uvx`, `poetry`, `pipx`, `cargo`, `gem`,
`composer`, `go get`). A `BLOCK` denies the command. A `WARN` asks you.

MCP server:

```bash
claude mcp add scgraph -- scgraph mcp
```

| Tool | Use |
|---|---|
| `check_package` | Before the agent adds or runs a package |
| `scan_lockfile` | Scan a lockfile or directory, with paths and a fix plan |
| `explain_advisory` | Summary, ranges, KEV, EPSS, and the verified vulnerable function |

## CI

GitHub Action:

```yaml
- uses: YashhMahajan/Graph-Engineering-for-SupplyChain@v1.3.0
  with:
    fail-on: P2
    reachability: "true"      # optional: check the vulnerable function
    deep: "false"             # optional: also transitive dependencies (network)
```

The action uploads SARIF to code scanning and writes a summary. For pull requests add a second job
with `mode: diff`. Use `pull_request`, not `pull_request_target`. Never run code from a fork with a
write token.

pre-commit:

```yaml
repos:
  - repo: https://github.com/YashhMahajan/Graph-Engineering-for-SupplyChain
    rev: v1.3.0
    hooks:
      - id: scgraph-scan
```

The hook runs only when a lockfile changes. It blocks malicious and exploited dependencies.

## More commands

| Command | Use |
|---|---|
| `scgraph scan . --format html -o report.html` | One self-contained page, with no script and no remote resource |
| `scgraph scan . --history DIR`, `scgraph history DIR --advisory ID` | Record scans in a hash-chained ledger. Find the first exposure, the fix and any regression. `--receipt` and `--check` verify an answer. |
| `scgraph audit` | Read agent and IDE configuration (`.mcp.json`, `.claude/settings.json`, `.vscode/tasks.json`) for code that runs on its own, unpinned launchers and `curl ... \| sh`. Exit `0`, `1` or `2`. |
| `scgraph ask "question" [PATH]` | Answer a question about the scan. Each sentence has a citation. No model is used. |
| `scgraph symbols ...` | Infer, look up, sign, verify and export vulnerable functions. See [SYMBOLS.md](SYMBOLS.md). |
| `scgraph scan . --format openvex` | An OpenVEX 0.2.0 document: `affected` for an alert, `not_affected` for a `path` or `scope` abstention |
| `scgraph scan . --vex FILE` | Use `not_affected` statements from a supplier to suppress findings |

Python API:

```python
from scgraph.scan import scan, Policy

for result in scan(".", policy=Policy(min_severity=7.0)):
    for f in result.alerts:
        print(f.priority, f.id, " -> ".join(f.path), f.fix)
```

## Limits

- `requirements.txt`, `Pipfile.lock`, `go.mod` and `gradle.lockfile` have no edges. Each package
  shows as direct.
- The direct-dependency bump is for npm only.
- A path shows that the package is installed. It does not show that your code calls the vulnerable
  function. `--reachability` and `--deep` check this, within the limits in [ISSUES.md](ISSUES.md).
