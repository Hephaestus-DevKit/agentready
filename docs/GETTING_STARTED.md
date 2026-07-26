# Getting Started

## Run Your First Scan

```bash
npx @hephaestus-devkit/agentready quickstart .
npx @hephaestus-devkit/agentready scan .
```

`quickstart` does not write files. It detects the project package runner,
existing AgentReady files, and GitHub Actions setup, then prints the commands
that fit the current repository.

The default text report shows a severity summary, top risks, detailed findings,
and recommended next steps.

## Initialize Agent Boundaries

```bash
agentready init .
```

This creates:

- `AGENTS.md`
- `.agentignore`
- `.agentready.json`

Preview changes first:

```bash
agentready init . --dry-run
```

Use a stricter starter profile:

```bash
agentready init . --preset strict
```

Generate a starter GitHub Actions workflow:

```bash
agentready init . --with-ci
```

Validate the setup:

```bash
agentready config validate .
agentready scan . --format markdown --output agentready-report.md
agentready scan . --format markdown --group-by category --max-findings 25
```

## Existing Projects

For a repository with existing findings, baseline the reviewed current state and
block only new findings in CI.

```bash
agentready scan .
agentready baseline .
agentready baseline diff .
agentready debt .
agentready scan . --baseline .agentready-baseline.json --ci
agentready baseline prune .
```

Commit the baseline only after a human review.
