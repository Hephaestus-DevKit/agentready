# Changelog

## Unreleased

### Fixed

- All `npx` commands in generated CI workflows (`init --with-ci`), `quickstart` output, and documentation now use the scoped package name `@hepheastus-devkit/agentready`. The unscoped `agentready` on the npm registry is an unrelated package, so the previous commands could fetch and run the wrong tool in CI.
- README npm badge and link now point at the scoped package instead of the unrelated unscoped one.
- `docs/CI.md` composite action example now references `Hephaestus-DevKit/agentready@v1` instead of the stale `@v0.1.0` tag; example workflows updated to `actions/checkout@v7`.
- `package-lock.json` name field updated to the scoped package name.
- JSON and SARIF reports now carry the real package version (`toolVersion` field, SARIF `tool.driver.version`) instead of a hardcoded `0.1.0`.
- Rule `fixUrl` links now point at the repository rule documentation (`docs/RULES.md`) instead of an unregistered domain, matching the SARIF `helpUri`.

### Improved

- Single source of truth for the tool version (`src/version.js`), shared by the `version` command, scanner results, and reporters.
- Table-driven CLI option parser replaces ~200 lines of per-flag branches; behavior and error messages are unchanged.
- Consolidated duplicate `escapeRegExp` implementations and unified line splitting (`splitLines`) across scanners so lone `\r` line endings are handled consistently.
- MCP and package.json scanners split file content once per file for line lookups instead of re-splitting on every finding.
- Text and Markdown report summaries share one row builder instead of two parallel hand-maintained lists.

## 1.0.1

### Fixed

- Fixed missing `agentready` binary in published npm package caused by Windows-style `./` path prefix in `bin` field.

## 1.0.0

### Added

- Agent Readiness Score (0–100) for quantified project health assessment.
- `badge` command to generate shields.io badge URLs and Markdown embeds for README display.
- `fixUrl` field on every rule linking to detailed remediation documentation.
- Stripe, Google API, Slack, and JWT secret detection patterns.
- Extended sensitive file scanning to 25+ file types.
- Utility module (`src/utils.js`) consolidating shared functions.
- New test suites for doctor, fingerprint, init, onboarding, utils, and score modules (143+ → 160+ tests).

### Improved

- Parallel directory traversal and batched file scanning (32-file concurrency) for faster scans.
- Pre-compiled regex caching for secret and shell pattern matching.
- Glob matching now supports `?` single-character wildcards.
- Code deduplication: extracted `summarizeSeverities`, `sortFindings`, `escapeMarkdown`, and `escapeRegExp` into shared utilities.
- Scanner no longer depends on reporters module, breaking circular coupling.
- Expanded npm keywords for better search discoverability.

### Fixed

- Glob `?` wildcard patterns not being routed through glob-to-regexp conversion.
- Version information caching for repeated CLI invocations.
- Input validation for scan target existence.

- Removed internal planning material from the product documentation package.
- Refined generated agent ignore patterns so source files that discuss secret scanning are not hidden by broad filename globs.
- Hardened the GitHub composite action input handling.
- Improved scanner signal for sensitive directories, extensionless secret files, JSON-style secret assignments, MCP environment references, workflow comments, `pull_request_target` trigger forms, and alternate shell script extensions.
- Added GitHub Actions rules for floating external `uses:` references and `pull_request_target` workflows that check out repository code.
- Added MCP checks for authorization forwarding, OAuth client settings, remote servers, private network endpoints, and cloud metadata endpoints.
- Classified IPv6 localhost MCP URLs as private network endpoints.
- Added `baseline diff` and `baseline prune` for reviewed baseline debt management.
- Added report controls for `--max-findings`, `--summary-only`, and `--group-by category`.
- Added scan input-size control through `maxFileBytes` and `--max-file-size`, plus binary-file skip reporting.
- Preserved UTF-16 text scanning when binary sniffing is enabled.
- Improved onboarding command path quoting for shell-sensitive paths.
- Added JSON `nextSteps` for automation and AI-agent callers.
- Added skipped-file statistics and common extensionless project files such as `Dockerfile`, `Makefile`, and `Justfile`.
- Added baseline entry `firstSeenAt` and `lastSeenAt` metadata plus severity summaries in baseline diffs.
- Added read-only `agentready debt` reporting for baseline debt.
- Added scan-result and baseline JSON schemas with contract tests.
- Added optional SARIF upload support to the GitHub composite action.
- Ensured composite action SARIF uploads still run when scan findings fail the CI threshold.
- Added CI matrix, packed-tarball smoke testing, Dependency Review, Scorecard, and npm provenance release workflow.
- Changed the release workflow to use npm Trusted Publishing instead of a long-lived npm token.
- Added a release workflow guard for npm 11.5.1 or newer before publishing.
- Added repository settings guidance for protected branches, release environments, trusted publishing, tags, and code scanning.
- Corrected trusted publisher setup guidance and required check names for the full CI matrix.
- Added runnable demo fixtures for clean, legacy, and CI/MCP projects.
- Added `npm run market:check` as a local market-readiness gate.
- Added a concise evaluation guide for adoption fit, release gates, and dogfood criteria.
- Expanded SARIF output with tool metadata and the complete rule catalog.
- Expanded SARIF output with a `PROJECTROOT` URI base for more stable code-scanning locations.
- Added product examples and sample reports for clean, legacy, and CI/MCP scenarios.
- Tightened CLI and configuration validation for invalid rule filters, invalid failure thresholds, unknown configuration fields, and non-object configuration files.
- Added config schema hints to generated configuration and documented schema metadata.
- Improved command recommendations for non-current target paths and rejected unsupported command-specific options instead of ignoring them.
- Added output-directory creation for scan reports and baseline files.
- Added `.envrc`, `.npmrc`, `.pypirc`, and `.netrc` coverage to sensitive-file scanning and generated agent boundaries.
- Validated baseline file structure before applying suppression.
- Fixed `**/` path pattern handling so root-level files and directories match expected glob behavior.

## 0.1.0

- Initial AgentReady CLI.
- Added local project scanning for secrets, risky scripts, GitHub Actions risks, MCP configuration risks, Python reproducibility issues, and missing agent boundaries.
- Added `scan`, `init`, `doctor`, `baseline`, `list-rules`, `config validate`, and `version` commands.
- Added text, JSON, Markdown, and SARIF reports.
- Added finding fingerprints and baseline suppression.
- Added starter GitHub Actions workflow and composite action support.
