# Getting Started

## Run Your First Scan

```bash
npx agentready scan .
```

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

## Existing Projects

For a repository with existing findings, baseline the reviewed current state and
block only new findings in CI.

```bash
agentready scan .
agentready baseline . --output .agentready-baseline.json
agentready scan . --baseline .agentready-baseline.json --ci
```

Commit the baseline only after a human review.
