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
sensitive files or MCP configurations. GitHub Actions template expressions
(`${{ secrets.NAME }}`) and environment references (`$NAME`, `${NAME}`,
`%NAME%`) are treated as placeholders too.

## Market-Critical Coverage

The current catalog includes rules for:

- agent boundary files and sensitive path exposure
- secret material in agent-readable files, including GitHub, npm, Hugging Face,
  AWS, Anthropic, OpenAI, Stripe, Google, and Slack token formats
- risky package, shell, Dockerfile/Makefile-style, and workflow commands
- GitHub Actions permissions, inherited secrets, floating `uses:` references,
  unsafe `pull_request_target` checkout patterns, `workflow_run` chains,
  comment-triggered commands, cache restore risks, artifact execution, OIDC
  deployment combinations, and untrusted context interpolated into `run:`
  scripts
- MCP shell tools, broad filesystem access, inline secrets, remote endpoints,
  authorization forwarding, OAuth client settings, private network endpoints,
  and cloud metadata endpoints
- Python reproducibility metadata

References:

- [GitHub Actions secure use reference](https://docs.github.com/en/enterprise-cloud%40latest/actions/reference/secure-use-reference)
- [MCP security best practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)

## Rule Catalog

| Rule | Default Severity | Category | Description | Recommendation |
| --- | --- | --- | --- | --- |
| `agent.missing_agents_md` | info | agent-boundaries | AGENTS.md is missing | Create AGENTS.md to document safe AI agent operating boundaries. |
| `agent.missing_agentignore` | low | agent-boundaries | .agentignore is missing | Create .agentignore to mark sensitive paths agents should avoid. |
| `secret.sensitive_filename` | medium | secrets | Sensitive-looking file is agent-readable | Keep sensitive files out of git and agent-readable paths. |
| `secret.private_key` | high | secrets | Private key material is present | Remove private keys and rotate exposed credentials. |
| `secret.github_token` | high | secrets | GitHub token-like value is present | Move tokens to scoped secret storage and rotate exposed values. |
| `secret.anthropic_key` | high | secrets | Anthropic-style API key is present | Move API keys to environment secrets and rotate exposed values. |
| `secret.openai_key` | high | secrets | OpenAI-style API key is present | Move API keys to environment secrets and rotate exposed values. |
| `secret.aws_access_key` | high | secrets | AWS access key-like value is present | Rotate exposed keys and use scoped secret storage. |
| `secret.generic_assignment` | high | secrets | Secret-like assignment is present | Move secret values out of repository files and rotate exposed values. |
| `script.dangerous_command.recursive_delete` | high | shell | Risky recursive delete command | Guard recursive deletes and require manual approval. |
| `script.dangerous_command.remote_code_execution` | high | shell | Remote download piped to shell | Pin scripts and verify checksums before execution. |
| `script.dangerous_command.world_writable` | medium | shell | World-writable permission command | Avoid chmod -R 777 and scope permissions tightly. |
| `script.dangerous_command.sudo` | medium | shell | Elevated privilege command | Require manual approval for privileged commands. |
| `package.invalid_json` | low | package | package.json could not be parsed | Fix package.json so scripts and dependencies can be inspected. |
| `package.script.recursive_delete` | high | package | Risky npm script recursive delete | Guard recursive deletes and require manual approval. |
| `package.script.remote_code_execution` | high | package | Risky npm script remote shell execution | Avoid piping remote downloads directly into shells. |
| `package.script.world_writable` | medium | package | Risky npm script world-writable permissions | Avoid chmod -R 777 in npm scripts. |
| `package.script.sudo` | medium | package | Risky npm script elevated privilege use | Require manual approval for privileged scripts. |
| `package.lifecycle_script` | medium | package | Package lifecycle script detected | Review lifecycle scripts before automated installs. |
| `github_actions.pull_request_target` | high | github-actions | GitHub Actions uses pull_request_target | Avoid pull_request_target for untrusted code or restrict it heavily. |
| `github_actions.write_all` | medium | github-actions | GitHub Actions grants write-all permissions | Use least-privilege workflow permissions. |
| `github_actions.write_permission` | medium | github-actions | GitHub Actions grants a write permission | Use job-level least-privilege write permissions. |
| `github_actions.secrets_inherit` | medium | github-actions | GitHub Actions inherits all caller secrets | Pass only required secrets to reusable workflows. |
| `github_actions.persist_credentials` | low | github-actions | actions/checkout persists credentials | Disable persisted credentials when jobs do not need push access. |
| `github_actions.unpinned_action` | medium | github-actions | GitHub Actions uses a floating external action or reusable workflow reference | Use a full commit SHA or reviewed release tag instead of a branch or missing ref. |
| `github_actions.pull_request_target_checkout` | high | github-actions | pull_request_target workflow checks out repository code | Avoid checking out untrusted pull request code in pull_request_target workflows. |
| `github_actions.workflow_run` | medium | github-actions | GitHub Actions uses workflow_run | Review workflow_run chains carefully before granting secrets or write permissions. |
| `github_actions.comment_trigger_run` | medium | github-actions | Comment-triggered workflow runs shell commands | Gate comment-triggered commands behind explicit maintainer authorization. |
| `github_actions.cache_restore_pr` | medium | github-actions | PR-triggered workflow uses broad cache restore keys | Avoid broad restore-keys in untrusted PR-triggered workflows. |
| `github_actions.artifact_execution` | high | github-actions | Workflow downloads artifacts and executes commands | Do not execute downloaded artifacts unless their producer and contents are trusted. |
| `github_actions.oidc_cloud_deploy` | medium | github-actions | Workflow grants OIDC tokens and runs cloud deployment commands | Constrain OIDC trust policies to specific refs, environments, and audiences. |
| `github_actions.script_injection` | high | github-actions | Untrusted GitHub context is interpolated into a run command | Pass untrusted values through env: and reference them as shell variables. |
| `github_actions.run.recursive_delete` | high | github-actions | Risky GitHub Actions recursive delete command | Guard recursive deletes and require manual approval. |
| `github_actions.run.remote_code_execution` | high | github-actions | Risky GitHub Actions remote shell execution | Avoid piping remote downloads directly into shells. |
| `github_actions.run.world_writable` | medium | github-actions | Risky GitHub Actions world-writable permissions | Avoid chmod -R 777 in workflow run commands. |
| `github_actions.run.sudo` | medium | github-actions | Risky GitHub Actions elevated privilege use | Require review before privileged workflow commands. |
| `mcp.shell_tool` | medium | mcp | MCP configuration can launch a shell | Restrict shell-capable MCP servers. |
| `mcp.broad_filesystem` | medium | mcp | MCP configuration may expose broad filesystem access | Limit filesystem MCP access to project-specific directories. |
| `mcp.inline_secret` | high | mcp | MCP configuration appears to contain inline secret values | Move secret values out of MCP config files. |
| `mcp.authorization_passthrough` | medium | mcp | MCP configuration forwards authorization headers | Avoid passing user or workspace tokens through unreviewed MCP server configuration. |
| `mcp.oauth_client_config` | medium | mcp | MCP configuration includes OAuth client settings | Review OAuth scopes, redirect URIs, and token handling before exposing the MCP server to agents. |
| `mcp.remote_url` | medium | mcp | MCP configuration references a remote server URL | Review remote MCP servers before exposing agent tools or repository context. |
| `mcp.private_network_url` | medium | mcp | MCP configuration references a private network URL | Limit MCP access to private network services unless the service is intended for agent use. |
| `mcp.metadata_endpoint` | high | mcp | MCP configuration references a cloud metadata endpoint | Remove metadata endpoint access from MCP configuration and review credential exposure. |
| `secret.stripe_key` | high | secrets | Stripe live API key is present | Rotate the key and move it to scoped secret storage. |
| `secret.google_api_key` | high | secrets | Google API key is present | Restrict the key scope and move it to secret storage. |
| `secret.slack_token` | high | secrets | Slack bot token is present | Rotate the token and use scoped secret storage. |
| `secret.slack_app_token` | high | secrets | Slack app-level token is present | Rotate the token and use scoped secret storage. |
| `secret.jwt_token` | medium | secrets | Hardcoded JWT token detected | Tokens should be generated dynamically, not stored in source files. |
| `secret.npm_token` | high | secrets | npm access token is present | Revoke the token and use trusted publishing or scoped CI secrets. |
| `secret.huggingface_token` | high | secrets | Hugging Face access token is present | Revoke the token and move it to scoped secret storage. |
| `python.unpinned_requirement` | low | python | Unpinned Python dependency | Pin dependency versions for reproducible agent and CI runs. |
| `python.missing_requires_python` | info | python | pyproject.toml does not declare requires-python | Declare supported Python versions. |
| `doctor.node` | info | environment | Node.js runtime | Use Node.js 20 or newer. |
| `doctor.git` | info | environment | Git repository check | Run AgentReady inside a project repository. |
| `doctor.write` | info | environment | Workspace write access | Ensure report output and init can write to the workspace. |
