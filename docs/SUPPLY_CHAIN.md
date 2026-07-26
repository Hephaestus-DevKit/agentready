# Supply Chain

AgentReady should be held to the same standard it recommends for user
repositories.

## Release

Published npm releases should come from the GitHub `release` workflow.

- Release trigger: published GitHub release
- Release runtime: Node.js 24 for npm Trusted Publishing support
- Package runtime support: Node.js 20 or newer
- Verification: `npm run market:check`
- Publish command: `npm publish --provenance --access public`
- Authentication: npm Trusted Publishing for the GitHub `release` workflow
- Required permission: `id-token: write` for npm provenance
- Required npm CLI: 11.5.1 or newer, checked in the release workflow
- Required release tag: `v` plus the package version
- Release package-manager cache: disabled

Do not publish from a local workstation unless the GitHub release workflow is
unavailable and the release notes explain the exception.

Repository and registry settings that cannot be represented in git are listed
in [Repository settings](REPOSITORY_SETTINGS.md).

References:

- [npm provenance](https://docs.npmjs.com/viewing-package-provenance)
- [npm trusted publishing](https://docs.npmjs.com/trusted-publishers)
- [SLSA provenance](https://slsa.dev/provenance)

## CI

The main CI workflow runs on Linux, macOS, and Windows across supported Node.js
versions. It also installs the packed tarball into a temporary project and runs
the packaged CLI, which catches packaging mistakes that unit tests can miss.

## Action Pinning

Repository workflows and the composite action pin every external GitHub Action
to a full commit SHA with a version comment (`owner/repo@<sha> # vX.Y.Z`), the
same posture the `github_actions.unpinned_action` rule recommends and OpenSSF
Scorecard rewards. A test (`test/workflows.test.js`) enforces the invariant.
Documentation examples use version tags for readability.

## Dependency Review

Pull requests run GitHub Dependency Review so dependency changes are visible
before merge. Dependabot is configured for npm and GitHub Actions updates.

Reference: [GitHub Dependency Review Action](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/manage-your-dependency-security/configuring-the-dependency-review-action)

## Scorecard

OpenSSF Scorecard runs on a weekly schedule and on pushes to `main`. Results are
uploaded as SARIF so repository-level supply-chain signals are visible in code
scanning.

Reference: [OpenSSF Scorecard](https://openssf.org/scorecard/)

## Tagging

Use immutable release tags such as `v1.1.0`. Do not move published tags. If a
release is bad, publish a new patch version instead of rewriting history.

## Baseline

AgentReady baselines are reviewed debt, not fixes. Do not auto-update baselines
in CI. Use `agentready debt .` and `agentready baseline diff .` to review debt
before pruning entries.
