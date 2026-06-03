# Contributing

AgentReady is intentionally small and dependency-light. Contributions should keep
the CLI easy to run in local repositories and CI.

## Development

```bash
npm run verify
```

No build step is required for the current JavaScript ESM implementation.

## Rule Changes

When adding or changing a rule:

1. Add or update scanner logic.
2. Add the rule id to `src/rules.js`.
3. Add tests that cover positive and negative cases when practical.
4. Update documentation if users need to configure the rule.

Rule ids should be stable after release because users may reference them in
`ignoreRules` and `severityOverrides`.

## Severity Guidelines

- `high`: likely credential exposure, untrusted code execution, or high-impact
  CI/tool permission risk.
- `medium`: risky automation or broad permissions that need review before agent
  use.
- `low`: hardening recommendation with limited immediate impact.
- `info`: setup or reproducibility guidance.

## Pull Requests

Keep pull requests focused. Include the command output for relevant verification
such as `npm run verify`.

Use the pull request template and explain:

- what changed
- why it changed
- user impact
- verification performed

For behavior changes, update the relevant docs in `docs/`.
