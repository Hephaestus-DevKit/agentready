# AgentReady

Preflight security checks before you give Claude Code, Codex, Cursor, MCP
tooling, or another AI coding agent access to a software project.

```bash
npx agentready quickstart .
npx agentready scan .
```

AgentReady runs locally. It does not upload your code, findings, baseline, or
configuration.

## Why It Exists

AI coding agents can read files, run scripts, modify CI, and connect to MCP
servers. AgentReady focuses on the trust boundary just before that access is
granted: it shows which repository risks should be fixed, reviewed, ignored, or
baselined before an agent works in the project.

The project is intentionally small: a Node.js CLI with zero runtime
dependencies, machine-readable reports, CI support, and starter agent boundary
files.

## Capabilities

- Implemented CLI commands: `scan`, `quickstart`, `init`, `doctor`, `baseline`,
  `debt`, `config validate`, `list-rules`, and `version`
- Text, JSON, Markdown, and SARIF report output
- GitHub composite action support through `action.yml`
- Baseline support for reviewed legacy findings, including diff and prune
- Report controls for PR-friendly grouping, summary-only output, and scan-size caps
- Verified with `npm run market:check`, including tests, self-scan, config
  validation, npm package dry-run, tarball smoke, link checks, and public-surface
  cleanup checks

## Example Output

```text
AgentReady Report
Root: /path/to/project
Duration: 48ms
Files scanned: 184
Status: action required
Summary: high=1 medium=2 low=1 info=0

Top risks:
- [HIGH] .env:2 Secret-like assignment is present
- [MEDIUM] .github/workflows/agent.yml:12 GitHub Actions grants contents write permission

Next steps:
- Fix high severity findings before giving an AI agent broad repository access.
- Save a markdown report with agentready scan . --format markdown --output agentready-report.md for review.
```

## What It Checks

- Known secret formats and generic secret-like assignments in sensitive files,
  sensitive directories, and agent-readable templates
- Risky package scripts, shell scripts, Dockerfile/Makefile-style project files,
  and GitHub Actions `run` commands
- Overbroad GitHub Actions permissions, `pull_request_target`, inherited secrets,
  floating action references, and unsafe `pull_request_target` checkout patterns
- MCP configurations with shell tools, broad filesystem access, inline secret
  values, authorization forwarding, OAuth client settings, remote URLs, private
  network URLs, or cloud metadata endpoints
- Missing `AGENTS.md` and `.agentignore` boundaries
- Python reproducibility issues such as unpinned requirements

## Install

Start without installing:

```bash
npx agentready quickstart .
npx agentready scan .
pnpm dlx agentready scan .
yarn dlx agentready scan .
bunx agentready scan .
```

Install in a project:

```bash
npm install -D agentready
npx agentready scan .
```

Use this repository directly during development:

```bash
npm install
npm link
agentready scan .
```

## Common Workflows

Preview the recommended setup path without writing files:

```bash
agentready quickstart .
```

Initialize project boundaries:

```bash
agentready init .
agentready init . --preset strict --with-ci
agentready init . --dry-run
```

Create a report:

```bash
agentready scan . --format markdown --output agentready-report.md
agentready scan . --format markdown --group-by category --max-findings 25
agentready scan . --summary-only
agentready scan . --max-file-size 1048576
agentready scan . --format sarif --output agentready.sarif
```

Use CI mode:

```bash
agentready scan . --ci
agentready scan . --ci --fail-on high
agentready scan . --ci --format sarif --output agentready.sarif
```

## GitHub Actions

```yaml
name: agentready

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          persist-credentials: false
      - uses: wangjiehu/agentready@v0.1.0
        with:
          fail-on: medium
          format: sarif
          output: agentready.sarif
          upload-sarif: true
```

See [CI usage](docs/CI.md) for report-only, baseline, and direct `npx` modes.

Adopt in a legacy project:

```bash
agentready scan .
agentready baseline .
agentready baseline diff .
agentready debt .
agentready scan . --baseline .agentready-baseline.json --ci
agentready baseline prune .
```

Inspect rules:

```bash
agentready list-rules
agentready list-rules --category github-actions
agentready list-rules --severity high
```

Validate configuration:

```bash
agentready config validate .
```

## Output Formats

```bash
agentready scan . --format text
agentready scan . --format json
agentready scan . --format markdown
agentready scan . --format sarif
```

Text output is optimized for humans. JSON and SARIF are intended for automation
and CI.

## Configuration

AgentReady automatically reads `agentready.config.json` or `.agentready.json`
from the scanned project root.

```json
{
  "$schema": "https://raw.githubusercontent.com/wangjiehu/agentready/main/schema/agentready.schema.json",
  "baselinePath": ".agentready-baseline.json",
  "failOn": "medium",
  "ignorePaths": ["fixtures/**"],
  "ignoreRules": ["python.unpinned_requirement"],
  "severityOverrides": {
    "package.lifecycle_script": "low"
  },
  "maxFileBytes": 524288
}
```

## Documentation

- [Getting started](docs/GETTING_STARTED.md)
- [Examples](docs/EXAMPLES.md)
- [Evaluation](docs/EVALUATION.md)
- [CLI reference](docs/CLI_REFERENCE.md)
- [Reports](docs/REPORTS.md)
- [Configuration](docs/CONFIGURATION.md)
- [Baseline](docs/BASELINE.md)
- [Rules](docs/RULES.md)
- [CI usage](docs/CI.md)
- [Supply chain](docs/SUPPLY_CHAIN.md)
- [Repository settings](docs/REPOSITORY_SETTINGS.md)
- [Next steps](next_steps.md)
- [Privacy](docs/PRIVACY.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Maintainer guide](docs/MAINTAINERS.md)
- [Release checklist](docs/RELEASE.md)
- [Changelog](CHANGELOG.md)

## Contributing and Security

See [CONTRIBUTING.md](CONTRIBUTING.md) for development workflow and rule
guidelines. See [SECURITY.md](SECURITY.md) for vulnerability reporting and
secret-handling guidance.

## License

MIT
