# Sample lockfiles

These lockfiles are vulnerable on purpose. Use them to try `scgraph scan`.

| file | what it shows |
|---|---|
| `express-app.package-lock.json` | An old Express app: 90 packages, 48 alerts, 4 fix actions. One `express` bump clears 6 transitive packages. |
| `flask-api.uv.lock` | A Flask API locked with uv. GHSA and PYSEC ids for the same issue merge into one finding. |
| `sept-2025-npm-compromise.package-lock.json` | A reconstruction of the 8 September 2025 npm compromise. `chalk@5.6.1` is direct. `debug@4.4.2` is three hops deep. |

```bash
scgraph scan examples/
```

The names have a prefix (`express-app.`), so Dependabot and other scanners do not
report this repository as vulnerable. scgraph reads a prefixed name the same way as
the plain name.

Do not install these dependencies.
