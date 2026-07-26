# AgentReady Security Report

## Summary

- Root: `/workspace/agent-tooling`
- Generated: 2026-07-26T00:00:00.000Z
- Duration: 5ms
- Files scanned: 4
- Status: action required
- Config: `(defaults)`
- CI fail threshold: medium
- Findings displayed: 9 of 9

| Severity | Count |
| --- | ---: |
| high | 4 |
| medium | 5 |
| low | 0 |
| info | 0 |

## Top Risks

- **HIGH** `.github/workflows/agent.yml:4` GitHub Actions uses pull_request_target
- **HIGH** `.github/workflows/agent.yml:14` pull_request_target workflow checks out repository code
- **HIGH** `.github/workflows/agent.yml:18` Workflow downloads artifacts and executes commands
- **HIGH** `mcp.json:11` MCP configuration references a cloud metadata endpoint
- **MEDIUM** `.github/workflows/agent.yml:7` GitHub Actions grants contents write permission

## Findings By Category

### github-actions

#### GitHub Actions uses pull_request_target

- Rule: `github_actions.pull_request_target`
- Severity: high
- Category: github-actions
- Location: `.github/workflows/agent.yml:4`
- Evidence: pull_request_target:
- Why it matters: AI-generated changes often touch CI; overbroad workflow permissions can expose secrets or write access.
- Recommendation: Avoid pull_request_target for untrusted code, or heavily restrict checkout, scripts, and secrets.

#### pull_request_target workflow checks out repository code

- Rule: `github_actions.pull_request_target_checkout`
- Severity: high
- Category: github-actions
- Location: `.github/workflows/agent.yml:14`
- Evidence: uses: actions/checkout@v6
- Why it matters: AI-generated changes often touch CI; overbroad workflow permissions can expose secrets or write access.
- Recommendation: Avoid checking out pull request code in pull_request_target workflows, or restrict checkout to trusted refs with no secrets.

#### Workflow downloads artifacts and executes commands

- Rule: `github_actions.artifact_execution`
- Severity: high
- Category: github-actions
- Location: `.github/workflows/agent.yml:18`
- Evidence: bash artifact/run.sh
- Why it matters: AI-generated changes often touch CI; overbroad workflow permissions can expose secrets or write access.
- Recommendation: Do not execute downloaded artifacts unless their producer workflow and contents are trusted.

#### GitHub Actions grants contents write permission

- Rule: `github_actions.write_permission`
- Severity: medium
- Category: github-actions
- Location: `.github/workflows/agent.yml:7`
- Evidence: contents: write
- Why it matters: AI-generated changes often touch CI; overbroad workflow permissions can expose secrets or write access.
- Recommendation: Use least-privilege permissions and grant write access only to jobs that require it.

#### GitHub Actions uses a floating external action or reusable workflow reference

- Rule: `github_actions.unpinned_action`
- Severity: medium
- Category: github-actions
- Location: `.github/workflows/agent.yml:15`
- Evidence: uses: owner/deploy-action@main
- Why it matters: AI-generated changes often touch CI; overbroad workflow permissions can expose secrets or write access.
- Recommendation: Use a full commit SHA or reviewed release tag instead of a branch or missing ref.

#### Workflow grants OIDC tokens and runs cloud deployment commands

- Rule: `github_actions.oidc_cloud_deploy`
- Severity: medium
- Category: github-actions
- Location: `.github/workflows/agent.yml:19`
- Evidence: aws deploy push
- Why it matters: AI-generated changes often touch CI; overbroad workflow permissions can expose secrets or write access.
- Recommendation: Constrain cloud OIDC trust policies to specific refs, environments, repositories, and audiences.

### mcp

#### MCP configuration references a cloud metadata endpoint

- Rule: `mcp.metadata_endpoint`
- Severity: high
- Category: mcp
- Location: `mcp.json:11`
- Evidence: http://169.254.169.254
- Why it matters: MCP servers can expose tools and local resources to agents, so broad access should be reviewed before use.
- Recommendation: Remove metadata endpoint access from MCP configuration and review whether credentials may be exposed.

#### MCP configuration can launch a shell

- Rule: `mcp.shell_tool`
- Severity: medium
- Category: mcp
- Location: `mcp.json:4`
- Evidence: Shell command "bash" found in MCP configuration.
- Why it matters: MCP servers can expose tools and local resources to agents, so broad access should be reviewed before use.
- Recommendation: Restrict shell-capable MCP servers and require human approval for destructive commands.

#### MCP configuration references a remote server URL

- Rule: `mcp.remote_url`
- Severity: medium
- Category: mcp
- Location: `mcp.json:8`
- Evidence: https://mcp.example.com
- Why it matters: MCP servers can expose tools and local resources to agents, so broad access should be reviewed before use.
- Recommendation: Review remote MCP servers before exposing agent tools or repository context.

## Next Steps

- Fix high severity findings before giving an AI agent broad repository access.
- Review medium severity findings and decide whether to fix, baseline, or explicitly configure exceptions.
- Save a markdown report with agentready scan . --format markdown --output agentready-report.md for review.
- For legacy projects, create a reviewed baseline with agentready baseline . --output .agentready-baseline.json.
