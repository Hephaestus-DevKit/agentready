# AgentReady

Preflight security checks before you give Claude Code, Codex, Cursor, MCP
tooling, or another AI coding agent access to a software project.

```bash
npx agentready quickstart .
npx agentready scan .
```

AgentReady runs locally. It does not upload your code, findings, baseline, or
configuration.

## What It Checks

- Secrets and secret-like assignments in agent-readable files
- Risky package scripts, shell scripts, and GitHub Actions `run` commands
- Overbroad GitHub Actions permissions, `pull_request_target`, and inherited secrets
- MCP configurations with shell tools, broad filesystem access, or inline secrets
- Missing `AGENTS.md` and `.agentignore` boundaries
- Python reproducibility issues such as unpinned requirements

## Install

Start without installing:

```bash
npx agentready quickstart .
npx agentready scan .
pnpm dlx agentready scan .
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
agentready scan . --format sarif --output agentready.sarif
```

Use CI mode:

```bash
agentready scan . --ci
agentready scan . --ci --fail-on high
```

Adopt in a legacy project:

```bash
agentready scan .
agentready baseline . --output .agentready-baseline.json
agentready scan . --baseline .agentready-baseline.json --ci
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
  "baselinePath": ".agentready-baseline.json",
  "failOn": "medium",
  "ignorePaths": ["fixtures/**"],
  "ignoreRules": ["python.unpinned_requirement"],
  "severityOverrides": {
    "package.lifecycle_script": "low"
  }
}
```

## Documentation

- [Getting started](docs/GETTING_STARTED.md)
- [CLI reference](docs/CLI_REFERENCE.md)
- [Reports](docs/REPORTS.md)
- [Configuration](docs/CONFIGURATION.md)
- [Baseline](docs/BASELINE.md)
- [Rules](docs/RULES.md)
- [CI usage](docs/CI.md)
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
