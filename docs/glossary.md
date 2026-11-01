# Glossary

This glossary defines the terms in this repository. If a term has a special function in
`scgraph`, the entry gives that function.

---

### Articulation point

A node in an undirected graph. If you remove it, the number of connected components
increases. Thus it is a single point of failure: no path goes around it. `scgraph` finds
all articulation points with Hopcroft-Tarjan in linear time. The full run has 88,273
articulation points. The most used are packages such as `lodash`, `react`, and
`express`. Refer to [methodology.md](methodology.md), section 4.

### Betweenness centrality

The fraction of all shortest paths in a graph that go through a node. It shows how much
traffic goes through that node. The exact Brandes algorithm costs `O(VE)`, which is too
much at ecosystem scale. Thus `scgraph` samples source pivots and uses the
Riondato-Kornaropoulos bound to set the sample size. It finds different packages than
PageRank or in-degree.

### Blast radius

For a package: the number of application packages that contain it in their transitive
dependency closure. It tells how many projects a compromise or a yank of the package
affects. `scgraph` calculates it with a bounded reverse breadth-first search. It is a
signal for escalation priority. For the top package to escalate, it disagrees with
"highest severity" approximately two times in three.

### Bridge (graph)

An edge that disconnects the graph when you remove it. It is the edge version of an
articulation point. The ecosystem has no redundant path around a bridge dependency.
`scgraph` finds 386,554 bridges in the full package graph, in the same Hopcroft-Tarjan
pass as the articulation points.

### CSR (Compressed Sparse Row)

A layout for a sparse graph or matrix. Edges are sorted by source node. An `indptr` array
gives the offset where the neighbour list of each node starts. An `indices` array holds
all neighbour lists in sequence. A neighbour lookup is one array slice, at `O(degree)`
cost, with no allocation. `scgraph` keeps the full dependency graph in this layout,
memory-mapped. It does not use a graph database.

### CVSS

The Common Vulnerability Scoring System. It changes a vector string that describes a
vulnerability (attack vector, complexity, privileges, and impact on confidentiality,
integrity, and availability) into a base score from 0 to 10. The base score is a
deterministic function of the vector. `scgraph` calculates it with arithmetic in
`cvss.py`, not with a model. Versions 3.1 and 4.0 are in use now.

### CWE

The Common Weakness Enumeration: a list of software weakness classes (for example,
CWE-79 cross-site scripting and CWE-89 SQL injection). Advisories have one or more CWE
identifiers. `scgraph` reads CWE identifiers from the GitHub Advisory Database.

### CycloneDX

An open standard for a software bill of materials: a machine-readable list of the
components in software, with optional vulnerability annotations. `scgraph` writes one
CycloneDX SBOM for each exposure report. The exposure paths of each component are
annotations. Examples are in [`../results/sbom/`](../results/sbom).

### Densification law

Real networks become denser as they grow (Leskovec, Kleinberg, Faloutsos, 2005). The edge
count grows as a power of the node count larger than one: `|E| proportional to |V|^a`
with `a > 1`. `scgraph` fits `a` across yearly snapshots and finds `a = 1.153`
(R-squared 0.9977). Each new group of packages depends on more existing packages than the
group before.

### Dependency confusion

A supply-chain attack. An attacker publishes a public package with the same name as a
private internal package. A resolver with an incorrect configuration then installs the
attacker's version. It is a reachability question on the resolution graph: which name
resolves to which published artifact. The grounding and resolution of `scgraph` map one
name to one published identity only.

### Exposure path

The primary output of `scgraph`: a path in the resolved dependency tree from an
application to an affected version. An example is `your-app -> framework -> ... ->
log4j-core@2.14.1`, where the last node is in the affected range of an advisory. The path
is the proof of the alert. If there is no path, this is a proven property of the graph.
A path is DIRECT (depth 1) or TRANSITIVE (deeper). The resolver makes each hop.

### GHSA

A GitHub Security Advisory identifier, for example `GHSA-jfh8-c2jp-5v3q`. GHSA records
use the OSV schema and often have CWE identifiers and CVSS vectors. `scgraph` keeps GHSA
ids as aliases and maps them to a canonical CVE with a union-find. Thus you can query
with each of the two ids.

### Gini coefficient

A measure of inequality in a distribution, from 0 (fully equal) to 1 (all mass on one
element). `scgraph` applies it to the reverse-PageRank vector to show how concentrated
systemic influence is. The full run gives 0.262 over the connected core: influence is
concentrated, but not very much.

### GraphSAGE

An inductive graph neural network (Hamilton, Ying, Leskovec, 2017). It calculates a node
embedding from the features of its neighbours over some message-passing layers. `scgraph`
uses a 2-layer mean-aggregator GraphSAGE for a temporal task with no leakage: predict
which packages get their first CVE next. It compares the result with the same features in
a model that does not use the graph. The graph model wins, but the confidence interval on
the margin is only just above zero.

### k-core

The largest subgraph in which each node has a degree of `k` or more. The coreness of a
node is the largest `k` whose k-core contains the node. High coreness shows deep
infrastructure. Coreness 0 or 1 shows a leaf. `scgraph` calculates coreness with
Batagelj-Zaversnik bucket peeling at `O(E)` cost. The GraphSAGE task uses only the 2-core
of the giant component.

### Label propagation

A community-detection method with near-linear cost (Raghavan, Albert, Kumara, 2007). Each
node takes the label that is most frequent among its neighbours. This continues until the
labels are stable. Each sweep costs `O(E)`, and a small number of sweeps is sufficient.
`scgraph` uses a seeded permutation and a random tie-break. Thus the result is
deterministic.

### Lockfile

A file that records the exact resolved version of each direct and transitive dependency.
Thus an install is reproducible. Examples: `package-lock.json`, `poetry.lock`,
`Cargo.lock`, `go.sum`, `pnpm-lock.yaml`. Resolution is expensive and not deterministic,
thus tools solve it one time and keep the result in a lockfile. `scgraph` uses lockfile
pins directly when the source data has them.

### Manifest

The file where a project declares its direct dependencies as ranges, not exact versions.
Examples: `package.json`, `pyproject.toml` or `requirements.txt`, `pom.xml`,
`Cargo.toml`, `go.mod`, `*.gemspec`. A manifest declares intent. A lockfile records the
resolution of that intent. In `scgraph`, a "manifest root" is the default version of a
package that no other package depends on. It is the root of a resolved tree.

### Modularity

A score for a partition of a graph into communities (Newman, Girvan, 2004). It is the
fraction of edges inside communities, minus the fraction that a random graph with the
same degrees gives. `Q > 0.3` shows real structure. `scgraph` finds `Q = 0.518` on the
dependency graph. Most of the communities agree with ecosystems.

### OSV

The Open Source Vulnerabilities schema and database. It is a machine-readable format for
advisories, with affected version ranges as event lists (`introduced`, `fixed`,
`last_affected`), explicit version lists, aliases, CVSS severity, and a `withdrawn` flag.
`scgraph` uses the `all.zip` export of each ecosystem as its advisory layer. It downloads
the feed live on each run.

### Power law

A distribution of the form `P(k) proportional to k^(-alpha)`. Some values are very large
and most are very small, with no characteristic scale. `scgraph` fits `alpha` for the
in-degree distribution by maximum likelihood (`alpha = 1.957`). Then it runs the Clauset
bootstrapped goodness-of-fit test, which **rejects** a pure power law (p = 0.0). The
distribution has a heavy tail, but it is not scale-free.

### Preferential attachment

The mechanism that gives a growing network a heavy tail (Barabasi, Albert, 1999). A new
node connects to an existing node with a probability proportional to the current degree
of that node. Thus popular nodes become more popular. `scgraph` measures the attachment
kernel across snapshots and finds a slope of 0.936. This agrees with approximately linear
attachment, not with "winner takes all".

### PURL

A package URL: a short, deterministic identifier of the form
`pkg:type/namespace/name@version`, for example
`pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1`. The grounder of `scgraph`
resolves an explicit PURL before it tries a looser match.

### Reverse PageRank

PageRank on the graph with all edges reversed. Probability mass moves to the packages
that many packages depend on. The stationary distribution shows how much load each
package carries. This is the systemic-risk view. `scgraph` calculates it by power
iteration on the reverse CSR, in approximately 40 sparse matrix-vector products.

### SAT / constraint satisfaction

Boolean satisfiability: the decision if all clauses in a set can be true at the same
time. Version resolution encodes SAT. Each package version is a variable and each
declared range is a clause. Thus, with peer dependencies and diamond conflicts,
resolution is NP-complete. This is why lockfiles exist. The bulk resolver of `scgraph`
implements a defined common subset, not a full solver.

### SBOM

A software bill of materials: a formal, machine-readable list of the components in
software and their relations. Regulations require SBOMs for more classes of software (US
Executive Order 14028, EU Cyber Resilience Act). An SBOM is a static list. `scgraph` adds
the impact analysis: what is exposed, through which path, and how to fix it.

### Semantic versioning (semver)

A version-number convention, `MAJOR.MINOR.PATCH`. A major increase shows a breaking
change. A minor increase adds backward-compatible features. A patch increase is a
backward-compatible fix. Range operators such as `^1.2.0` (same major) and `~1.2.0` (same
minor) use this convention. The remediation of `scgraph` does not cross a major boundary,
because builds break there.

### Transitive dependency

A dependency of a dependency: a package that your project gets indirectly, not one that
you declared. Most of a resolved tree is transitive. Most audit noise that you cannot act
on is about transitive packages. The exposure paths of `scgraph` show each transitive
hop.

### VEX

A Vulnerability Exploitability eXchange statement. It is a machine-readable statement
that a product is or is not affected by a vulnerability, with a reason (for example,
"vulnerable code not in the execution path"). `scgraph` uses VEX "not affected"
statements as ground truth to evaluate its reachability layer.

---

Refer to [methodology.md](methodology.md) for the methods and to
[architecture.md](architecture.md) for the pipeline.
