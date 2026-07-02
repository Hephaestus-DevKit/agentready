# Repository Settings

These settings are configured in GitHub and npm, not in the repository files.
Review them before the first public release and after any ownership transfer.

## GitHub Rulesets

Protect `main` with required checks:

- `test (ubuntu-latest, node 20)`
- `test (ubuntu-latest, node 22)`
- `test (ubuntu-latest, node 24)`
- `test (windows-latest, node 20)`
- `test (windows-latest, node 22)`
- `test (windows-latest, node 24)`
- `test (macos-latest, node 20)`
- `test (macos-latest, node 22)`
- `test (macos-latest, node 24)`
- `tarball-smoke`
- `action-smoke`
- `dependency-review`

Require pull requests before merge and block force pushes. Keep bypass access
limited to maintainers who can publish releases.

## Release Environment

Create a GitHub environment named `npm` for the `release` workflow.

- Restrict deployment branches to protected release tags such as `v*`.
- Require reviewer approval for first public releases and ownership changes.
- Keep environment secrets empty when npm Trusted Publishing is configured.
- The workflow also checks that the release tag equals `v` plus
  `package.json` version.

## npm Trusted Publishing

Configure the npm package trusted publisher to the GitHub repository and the
`release.yml` workflow.

- Publisher: GitHub Actions
- Repository: `Hephaestus-DevKit/agentready`
- Workflow: `release.yml`
- Environment: `npm`

Do not add a long-lived npm automation token unless Trusted Publishing is
temporarily unavailable. If a token fallback is used, document the exception in
the release notes and rotate the token after use.

## Tags

Use immutable release tags such as `v0.1.0`. Do not move a published tag.
Keep the tag aligned with `package.json` version and publish a patch release
instead of moving an existing tag.

## Code Scanning

Enable code scanning alerts so AgentReady SARIF uploads and Scorecard SARIF
results are visible to maintainers.
