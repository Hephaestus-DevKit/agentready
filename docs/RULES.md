# Rules

List rules:

```bash
agentready list-rules
agentready list-rules --format markdown
agentready list-rules --category github-actions
agentready list-rules --severity high
```

Invalid category or severity filters are reported as CLI usage errors.

Each rule has:

- stable rule id
- default severity
- category
- description
- recommendation

Rule ids are used in configuration:

```json
{
  "ignoreRules": ["python.unpinned_requirement"],
  "severityOverrides": {
    "package.lifecycle_script": "low"
  }
}
```

Prefer fixing real issues. Use ignores for reviewed, intentional exceptions.

## Severity Adjustments

Secret findings in conventional test locations (`test/`, `tests/`,
`__tests__/`, `__mocks__/`, `spec/`, `fixtures/`, `*.test.*`, `*.spec.*`,
`*_test.*`, `conftest.py`) are reported at `low` severity instead of `high`.
Test fixtures are usually deliberate fakes, but the finding stays visible so a
real committed credential can still be caught. Use `--fail-on low` to treat
them as blocking again.

Values that start with obvious placeholder instructions (`change-this`,
`replace-`, `your-`, `fill-in`, and similar) are not reported as secrets in
sensitive files or MCP configurations.

## Market-Critical Coverage

The current catalog includes rules for:

- agent boundary files and sensitive path exposure
- secret material in agent-readable files
- risky package, shell, Dockerfile/Makefile-style, and workflow commands
- GitHub Actions permissions, inherited secrets, floating `uses:` references,
  unsafe `pull_request_target` checkout patterns, `workflow_run` chains,
  comment-triggered commands, cache restore risks, artifact execution, and
  OIDC deployment combinations
- MCP shell tools, broad filesystem access, inline secrets, remote endpoints,
  authorization forwarding, OAuth client settings, private network endpoints,
  and cloud metadata endpoints
- Python reproducibility metadata

References:

- [GitHub Actions secure use reference](https://docs.github.com/en/enterprise-cloud%40latest/actions/reference/secure-use-reference)
- [MCP security best practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)
