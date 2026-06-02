# Reports

AgentReady supports four output formats.

## Text

```bash
agentready scan . --format text
```

Text output is the default. It includes:

- scan duration
- files scanned
- severity summary
- top risks
- findings grouped by severity
- next steps

Use `--quiet` for a one-line summary and `--verbose` to include fingerprints.

## JSON

```bash
agentready scan . --format json
```

JSON is intended for scripts and AI agents. It includes `schemaVersion` so
automation can guard against future structural changes.

## Markdown

```bash
agentready scan . --format markdown --output agentready-report.md
```

Markdown is intended for PR comments, issues, and human review.

## SARIF

```bash
agentready scan . --format sarif --output agentready.sarif
```

SARIF can be uploaded to GitHub code scanning. Findings include partial
fingerprints for deduplication.

## Sensitive Output

AgentReady redacts known secret formats and generic secret assignments, but
reports can still contain sensitive filenames, paths, and contextual evidence.
Treat reports and SARIF files as sensitive artifacts.
