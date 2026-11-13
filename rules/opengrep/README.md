# Opengrep rules

The rules the `opengrep` image bundles at `/opt/cybedefend-scanners/rules/opengrep`.
Every rule here is CybeDefend's own, written from the CWE it names, under
Apache-2.0 (`metadata.license`); no third-party rule set is copied in.

| Rule id | Languages | CWE | `security-severity` |
|---|---|---|---|
| `python-eval` | Python | CWE-95 | 9.8 |
| `python-exec` | Python | CWE-95 | 9.8 |
| `python-subprocess-shell-true` | Python | CWE-78 | 9.8 |
| `python-yaml-unsafe-load` | Python | CWE-502 | 7.5 |
| `python-pickle-loads` | Python | CWE-502 | 7.5 |
| `python-flask-debug-true` | Python | CWE-489 | 5.0 |
| `python-sql-string-format` | Python | CWE-89 | 8.8 |
| `javascript-eval` | JavaScript, TypeScript | CWE-95 | 9.8 |
| `javascript-child-process-exec-concat` | JavaScript, TypeScript | CWE-78 | 9.8 |
| `javascript-innerhtml-assignment` | JavaScript, TypeScript | CWE-79 | 6.1 |
| `java-runtime-exec-concat` | Java | CWE-78 | 9.8 |
| `go-exec-command-shell` | Go | CWE-78 | 9.8 |

## Layout

Each rule is one file, `<id>.yaml`, next to its annotated test file `<id>.<ext>`:
a `ruleid: <id>` comment marks the line below it as a finding the rule must
report, an `ok: <id>` comment a line it must not. The test files are
deliberately vulnerable code: never run them.

Every rule carries `metadata.cwe`, `metadata.security-severity` (a quoted
number, which Opengrep copies into the SARIF rule's `properties`, where the
server reads the severity) and `metadata.license: Apache-2.0`.

## Testing

`go test ./internal/rules/` checks the metadata, the list of ids and the test
files. Opengrep's own rule tests run in the image (integration suite):

```
opengrep scan --test rules/opengrep
```
