# Reports

AgentReady supports four output formats.

## Text

```bash
agentready scan . --format text
```

Text output is the default. It includes:

- scan duration
- files scanned
- files skipped by reason, when any files are skipped
- status label
- configuration path
- CI failure threshold
- severity summary
- top risks
- findings grouped by severity
- next steps

Use `--quiet` for a one-line summary and `--verbose` to include fingerprints.

Large repositories can cap printed detail without changing CI decisions:

```bash
agentready scan . --max-findings 25
agentready scan . --summary-only
```

The severity summary and CI exit code still use the complete scan result.
Avoid capping SARIF output when uploading to code scanning unless you
intentionally want only a subset of results in that system.

Use `--max-file-size` or `maxFileBytes` to change the maximum input file size
AgentReady reads during scans. Skipped files are reported by reason, including
`oversized`, `binary`, `unsupported-type`, ignored paths, and unreadable files.

## JSON

```bash
agentready scan . --format json
```

JSON is intended for scripts and AI agents. It includes `schemaVersion` so
automation can guard against future structural changes, `toolVersion` so
results can be traced to the producing package release, and `nextSteps` so
callers do not need to parse the human-readable report.

The scan-result schema is published at
`schema/agentready-result.schema.json`. Baseline files use
`schema/agentready-baseline.schema.json`.

## Markdown

```bash
agentready scan . --format markdown --output agentready-report.md
```

Markdown is intended for PR comments, issues, and human review.

For pull requests, category grouping is often easier to assign to owners:

```bash
agentready scan . --format markdown --group-by category --output agentready-report.md
```

## SARIF

```bash
agentready scan . --format sarif --output agentready.sarif
```

SARIF can be uploaded to GitHub code scanning. Findings include partial
fingerprints for deduplication. The SARIF driver includes tool metadata, a help
URI, and the complete AgentReady rule catalog so code-scanning consumers can
display rule information consistently. Locations use a `PROJECTROOT` URI base
so repository-relative findings remain stable across local and CI paths.

Reference: [GitHub SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support-for-code-scanning)

## Sensitive Output

AgentReady redacts known secret formats and generic secret assignments, but
reports can still contain sensitive filenames, paths, and contextual evidence.
Treat reports and SARIF files as sensitive artifacts.
