# CLI Reference

## Commands

```bash
agentready scan [path]
agentready baseline [path]
agentready init [path]
agentready doctor [path]
agentready config validate [path]
agentready list-rules
agentready version
```

## Exit Codes

- `0`: command completed and no CI failure threshold was reached
- `1`: scan completed and findings met the configured `failOn` threshold
- `2`: CLI usage or argument error
- `3`: configuration or baseline file error
- `4`: unexpected runtime error

## stdout and stderr

- Normal reports are written to stdout.
- Errors are written to stderr.
- `--format json` writes only JSON to stdout.
- `--output file` writes the report to a file and prints a short success message.

## Scan Options

```bash
agentready scan . --format text|json|markdown|sarif
agentready scan . --output agentready-report.md
agentready scan . --ci
agentready scan . --fail-on high|medium|low|info|none
agentready scan . --baseline .agentready-baseline.json
agentready scan . --ignore-rule python.unpinned_requirement
agentready scan . --ignore-path "fixtures/**"
agentready scan . --quiet
agentready scan . --verbose
agentready scan . --no-color
```

## Init Options

```bash
agentready init . --preset balanced
agentready init . --preset strict
agentready init . --preset legacy
agentready init . --with-ci
agentready init . --dry-run
agentready init . --force
```

Existing files are preserved unless `--force` is passed.
