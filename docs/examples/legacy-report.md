# AgentReady Security Report

## Summary

- Root: `/workspace/legacy-app`
- Generated: 2026-07-26T00:00:00.000Z
- Duration: 5ms
- Files scanned: 2
- Status: review recommended
- Config: `(defaults)`
- CI fail threshold: medium
- Findings displayed: 4 of 4

| Severity | Count |
| --- | ---: |
| high | 0 |
| medium | 1 |
| low | 2 |
| info | 1 |

## Top Risks

- **MEDIUM** `package.json:3` Package lifecycle script detected: postinstall
- **LOW** `(project)` .agentignore is missing
- **LOW** `requirements.txt:1` Unpinned Python dependency
- **INFO** `(project)` AGENTS.md is missing

## Findings By Category

### agent-boundaries

#### .agentignore is missing

- Rule: `agent.missing_agentignore`
- Severity: low
- Category: agent-boundaries
- Evidence: No .agentignore file was found at the project root.
- Why it matters: AI coding agents need explicit project boundaries so they avoid sensitive files and risky operations.
- Recommendation: Run agentready init and add sensitive paths that agents should avoid.

#### AGENTS.md is missing

- Rule: `agent.missing_agents_md`
- Severity: info
- Category: agent-boundaries
- Evidence: No AGENTS.md file was found at the project root.
- Why it matters: AI coding agents need explicit project boundaries so they avoid sensitive files and risky operations.
- Recommendation: Run agentready init to document safe operating boundaries for AI coding agents.

### package

#### Package lifecycle script detected: postinstall

- Rule: `package.lifecycle_script`
- Severity: medium
- Category: package
- Location: `package.json:3`
- Evidence: postinstall: node setup.js
- Why it matters: Package scripts can execute during installs or agent-run commands, which makes them part of the agent trust boundary.
- Recommendation: Review lifecycle scripts before allowing agents or CI to install dependencies automatically.

### python

#### Unpinned Python dependency

- Rule: `python.unpinned_requirement`
- Severity: low
- Category: python
- Location: `requirements.txt:1`
- Evidence: requests
- Why it matters: Pinned Python metadata helps agents and CI reproduce the same environment.
- Recommendation: Pin dependency versions for reproducible agent and CI runs.

## Next Steps

- Review medium severity findings and decide whether to fix, baseline, or explicitly configure exceptions.
- Save a markdown report with agentready scan . --format markdown --output agentready-report.md for review.
- For legacy projects, create a reviewed baseline with agentready baseline . --output .agentready-baseline.json.
