# CI Usage

AgentReady can run in CI as a preflight gate before an AI coding agent or MCP
tooling is allowed to work on a repository.

## Basic GitHub Actions Job

Using the composite action from this repository:

```yaml
name: agentready

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - uses: wangjiehu/agentready@main
        with:
          fail-on: medium
```

The composite action runs the repository CLI with `node`, so self-hosted runners
must provide Node.js 20 or newer. GitHub-hosted Ubuntu runners already include
Node.js.

Using `npx` directly:

```yaml
name: agentready

on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npx agentready scan . --ci --format sarif --output agentready.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: agentready.sarif
```

## Failure Thresholds

By default, CI mode fails on `high` or `medium` findings.

```bash
agentready scan . --ci --fail-on high
agentready scan . --ci --fail-on none
```

Exit codes:

- `0`: scan completed and did not reach the failure threshold
- `1`: scan completed and reached the configured `failOn` threshold
- `2`: CLI usage error
- `3`: configuration or baseline file error
- `4`: unexpected runtime error

## Adoption Modes

Report-only mode:

```bash
agentready scan . --format markdown --output agentready-report.md --fail-on none --ci
```

New findings only:

```bash
agentready baseline . --output .agentready-baseline.json
agentready scan . --baseline .agentready-baseline.json --ci
```

Strict mode:

```bash
agentready scan . --ci --fail-on medium
```

## Composite Action Inputs

- `path`: project path to scan, default `.`
- `fail-on`: `high`, `medium`, `low`, `info`, or `none`
- `format`: `text`, `json`, `markdown`, or `sarif`
- `output`: optional report output path
- `baseline`: optional baseline file path
- `config`: optional configuration file path

## Configuration File

AgentReady automatically reads `agentready.config.json` or `.agentready.json`
from the scanned project root.

```json
{
  "baselinePath": ".agentready-baseline.json",
  "failOn": "medium",
  "ignorePaths": ["fixtures/**"],
  "ignoreRules": ["python.unpinned_requirement"],
  "severityOverrides": {
    "package.lifecycle_script": "low"
  }
}
```

Use ignores sparingly. Prefer fixing real risks and only ignoring intentional,
reviewed exceptions.

## Baseline Existing Findings

For an existing repository, create a baseline once and keep CI focused on new
findings.

```bash
agentready baseline . --output .agentready-baseline.json
agentready scan . --baseline .agentready-baseline.json --ci
```

Commit the baseline only after reviewing the findings. Remove entries as the
underlying issues are fixed.
