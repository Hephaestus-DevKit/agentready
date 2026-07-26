# CLI Reference

## Commands

```bash
agentready scan [path]
agentready baseline [path]
agentready baseline diff [path]
agentready baseline prune [path]
agentready debt [path]
agentready init [path]
agentready quickstart [path]
agentready doctor [path]
agentready config validate [path]
agentready list-rules
agentready version
```

## Exit Codes

- `0`: command completed and no CI failure threshold was reached
- `1`: scan completed and findings met the configured `failOn` threshold
- `2`: CLI usage or argument error
- `3`: configuration or baseline file error, or `config validate` warnings
- `4`: unexpected runtime error

## stdout and stderr

- Normal reports are written to stdout.
- Errors are written to stderr.
- `--format json` writes only JSON to stdout.
- `--output file` writes the report to a file, creates missing parent
  directories, and prints a short success message.

## Scan Options

```bash
agentready scan . --format text|json|markdown|sarif
agentready scan . --output agentready-report.md
agentready scan . --ci
agentready scan . --fail-on high|medium|low|info|none
agentready scan . --baseline .agentready-baseline.json
agentready scan . --ignore-rule python.unpinned_requirement
agentready scan . --ignore-path "fixtures/**"
agentready scan . --max-file-size 1048576
agentready scan . --max-findings 25
agentready scan . --summary-only
agentready scan . --format markdown --group-by category
agentready scan . --quiet
agentready scan . --verbose
agentready scan . --no-color
```

Options that are not supported by the selected command are rejected with exit
code `2` instead of being ignored.

`--max-findings` and `--summary-only` change only the amount of detail printed
in the report. CI failure decisions still use the complete scan result.
`--group-by category` is useful for Markdown reports posted into pull requests.
`--max-file-size` changes the maximum input file size AgentReady reads during
the scan. The default is `524288` bytes.

Text reports colorize severity and status labels when printed to an
interactive terminal. Colors are disabled automatically for piped output,
`--output` files, and the `NO_COLOR` environment variable, or explicitly with
`--no-color`.

## Baseline Options

```bash
agentready baseline . --output .agentready-baseline.json
agentready baseline . --config .agentready.json
agentready baseline . --ignore-rule python.unpinned_requirement
agentready baseline . --ignore-path "fixtures/**"
agentready baseline . --max-file-size 1048576
agentready baseline diff . --format markdown --output agentready-baseline-diff.md
agentready baseline diff . --max-file-size 1048576
agentready baseline prune .
agentready baseline prune . --output .agentready-baseline.pruned.json
agentready baseline prune . --max-file-size 1048576
agentready debt . --format markdown --output agentready-debt.md
```

`baseline` creates parent directories for the output path when needed. Use
ignore options only for reviewed findings that should not be captured as
baseline debt.

`baseline diff` compares the reviewed baseline with the current scan and shows
new findings plus stale entries. `baseline prune` rewrites the baseline with
only entries that still match current findings. Both commands respect the same
configuration and explicit ignore options used when building the comparison
scan.

## Debt Options

```bash
agentready debt .
agentready debt . --baseline .agentready-baseline.json
agentready debt . --config .agentready.json
agentready debt . --format text|json|markdown
agentready debt . --output agentready-debt.md
```

`debt` is read-only. It summarizes reviewed baseline entries by severity, age,
rule id, and file so teams can reduce baseline debt without hiding new findings.
It uses `baselinePath` from configuration unless `--baseline` is passed.

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

## Quickstart

```bash
agentready quickstart .
```

`quickstart` is a zero-write onboarding command. It detects package-manager
conventions, existing AgentReady setup files, and GitHub Actions workflows, then
prints the recommended commands for setup, scanning, reports, and legacy
baselines.

## Doctor Options

```bash
agentready doctor .
agentready doctor . --config .agentready.json
agentready doctor . --baseline .agentready-baseline.json
agentready doctor . --max-file-size 1048576
agentready doctor . --max-findings 25
agentready doctor . --summary-only
agentready doctor . --group-by category
agentready doctor . --quiet
agentready doctor . --verbose
```

`doctor` checks the local runtime and workspace, then includes scan results. It
respects the same configuration and baseline inputs as `scan`.
