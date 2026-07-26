# Changelog

## 1.1.0

### Changed

- **Package renamed to `@hephaestus-devkit/agentready`** (correct Hephaestus spelling). Versions up to 1.0.2 were published under the misspelled scope `@hepheastus-devkit/agentready`; that package is deprecated in place. Update installs and `npx` commands to the new name.

### Fixed

- Report evidence now redacts JWT tokens. Detection patterns and redaction share one table (`SECRET_TOKEN_RULES`), so a newly added token type can never be detected but leak unmasked into text, JSON, SARIF, or baseline output.
- `curl … | sudo bash` (and `| env … bash`) is now detected as remote code execution; previously the `sudo` between the pipe and the shell silently downgraded the finding.
- Recursive-delete detection no longer matches across `&&`, `;`, or `|` boundaries, so `rm -rf dist && cp -r build /usr/share` is no longer a false high. Windows equivalents (`Remove-Item -Recurse -Force`, `del /s /q`, `rd /s /q`) are now detected, as are `$(pwd)`-rooted deletes.
- `sudo` is flagged only at command position: `apt-get install -y sudo` no longer counts as privilege escalation.
- Trailing YAML comments no longer disable GitHub Actions analysis: `on: # comment` still opens the trigger block, and `contents: write # reason`, `id-token: write # oidc`, and `secrets: inherit # …` are still flagged. Comment prose can no longer register as a trigger.
- Block scalar headers with indent or chomping markers (`run: |2`, `run: >-`) are parsed as run blocks, and backslash-continued commands inside run blocks and shell files are analyzed as one command.
- MCP configuration detection now matches `.mcp.json` and root-level `mcp/` directories, and no longer matches lookalike paths such as `src/mcparse/` or `packages/mcpackage/`.
- `mcp.shell_tool` inspects actual command and args values: `zsh` servers are detected, and a `./scripts/setup.sh` argument no longer false-positives.
- `mcp.inline_secret` matches whole key words (`TOKENIZER` no longer flags) and reports the offending key with a line number instead of `line: null` prose.
- `${{ secrets.X }}` template expressions are treated as placeholders by both the secrets and MCP scanners.
- The netrc `password <value>` heuristic applies only to netrc files, so English prose in `private/` or `secrets/` directories no longer produces a high finding.
- JWT findings now use the documented `medium` severity from the rule catalog instead of a hardcoded `high`.
- Scan output is deterministic: collected files are sorted before scanning, so JSON, SARIF, and baseline output no longer reorder between runs on multi-directory repositories.
- CLI `--baseline` resolves against the working directory, consistent with `--config` and `--output`; a `baselinePath` from the config file stays relative to the scan target.
- `badge` now honors `--baseline` and the config `baselinePath`, so the score matches what a baseline-suppressed scan reports.
- Known errors such as `init` write failures print their curated message without a stack trace.
- Python: bare version ranges (`numpy>1.2`) count as constraints, and a Poetry `python` dependency satisfies the requires-python check.
- package.json script findings resolve line numbers inside the `scripts` block, so a dependency sharing the script name no longer steals the location.
- All `npx` commands in generated CI workflows (`init --with-ci`), `quickstart` output, and documentation now use the scoped package name (`@hephaestus-devkit/agentready` after the rename above). The unscoped `agentready` on the npm registry is an unrelated package, so the previous commands could fetch and run the wrong tool in CI.
- README npm badge and link now point at the scoped package instead of the unrelated unscoped one.
- Composite action example references updated from the stale `@v0.1.0` tag; example workflows updated to `actions/checkout@v7`.
- `package-lock.json` name field updated to the scoped package name.
- JSON and SARIF reports now carry the real package version (`toolVersion` field, SARIF `tool.driver.version`) instead of a hardcoded `0.1.0`.
- Rule `fixUrl` links now point at the repository rule documentation (`docs/RULES.md`) instead of an unregistered domain, matching the SARIF `helpUri`.

### Improved

- Repository workflows and the composite action pin every external GitHub Action to a full commit SHA with a version comment, enforced by a test; `actions/setup-node` bumped to v7. Documentation examples keep readable version tags.
- Composite action: an empty `fail-on` input now defers to the project configuration's `failOn` instead of always overriding it with `medium`.
- Each scanned file is read once (previously up to three filesystem operations per file); binary sensitive files such as `.p12` stores still get the filename finding without being content-scanned as garbage.
- `.agentignore` is recognized as a scannable text file type.
- CLI internals: output writing, format validation, and unsupported-option rejection are table-driven, so new options cannot be silently forgotten.
- Documentation: the CLI reference now covers `badge` and doctor `--no-color`; example reports are regenerated from the shipped demo fixtures; composite action usage examples pin an immutable version tag per the repository tag policy.
- Test suite: shared helpers, zero temp-directory leakage, runner-cwd independence, and about 40 new regression tests covering redaction, the badge command, config/baseline error exits, and every scanner fix in this release (217 tests total).
- Noise reduction driven by scanning real repositories (ten local projects across TypeScript, Next.js, Python, and CI-heavy codebases; all remaining findings verified as true positives):
  - Secret findings in conventional test locations (`test/`, `__tests__/`, `fixtures/`, `*.test.*`, `*.spec.*`, `conftest.py`, and similar) are reported at `low` severity instead of `high` — test fixtures are usually deliberate fakes, and nine fake keys in one scanned project previously produced nine blocking highs. The findings stay visible; `--fail-on low` restores blocking behavior.
  - Placeholder detection now recognizes `change-this...`, `replace-...`, `fill-in...`, and `insert-...` values (previously only `changeme`/`replace-me`), fixing false highs on committed `.env.example` templates. Real-looking values in template files are still reported.
  - Dangerous-command detection skips pure `echo`/`printf` lines with no command separator, so install scripts that print instructions like `echo "run: sudo systemctl ..."` are no longer flagged as executing `sudo`.
  - The placeholder heuristics are now shared between the secrets and MCP scanners (`looksLikePlaceholderValue`), so both treat the same values consistently.
  - `rm -rf` targeting a scoped temp subdirectory (`/tmp/<name>`, `/var/tmp/<name>`) is no longer flagged as a high recursive delete — routine CI cleanup evidence: `rm -rf /tmp/bidpilot-pages`. Deleting `/tmp` itself or `/` still reports.
  - Sensitive-looking filenames under test or fixture paths report at `low` severity, matching the treatment of secret values in test files.
- `--no-color` is now a real option: text reports colorize severity and status labels on interactive terminals, with automatic disabling for piped output, `--output` files, and the `NO_COLOR` environment variable. Previously the flag was accepted but had no effect because no output was ever colorized.
- A missing scan target now exits with a clean usage error (exit code 2) instead of an unexpected-error stack trace (exit code 4).
- The published result schema (`schema/agentready-result.schema.json`) now documents `toolVersion`, `configWarnings`, the `report` block, and finding `fixUrl`.
- Single source of truth for the tool version (`src/version.js`), shared by the `version` command, scanner results, and reporters.
- Table-driven CLI option parser replaces ~200 lines of per-flag branches; behavior and error messages are unchanged.
- Consolidated duplicate `escapeRegExp` implementations and unified line splitting (`splitLines`) across scanners so lone `\r` line endings are handled consistently.
- MCP and package.json scanners split file content once per file for line lookups instead of re-splitting on every finding.
- Text and Markdown report summaries share one row builder instead of two parallel hand-maintained lists.

### Removed

- Internal planning notes (`NEXT_STEPS.md`) removed from the repository; the npm tarball no longer ships maintainer-only scripts or the repository's own `.agentignore`.

## 1.0.2

### Changed

- Migrated the repository and package namespace to the Hephaestus-DevKit organization; the npm package is `@hepheastus-devkit/agentready`.
- Updated packed-tarball smoke test paths for the scoped package and moved Scorecard workflow permissions to the job level.
- Bumped `actions/checkout` to v7 and `actions/dependency-review-action` to v5.

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

### Added

- GitHub Actions rules for floating external `uses:` references and `pull_request_target` workflows that check out repository code.
- MCP checks for authorization forwarding, OAuth client settings, remote servers, private network endpoints, and cloud metadata endpoints.
- `baseline diff` and `baseline prune` for reviewed baseline debt management.
- Report controls for `--max-findings`, `--summary-only`, and `--group-by category`.
- Scan input-size control through `maxFileBytes` and `--max-file-size`, plus binary-file skip reporting.
- JSON `nextSteps` for automation and AI-agent callers.
- Skipped-file statistics and common extensionless project files such as `Dockerfile`, `Makefile`, and `Justfile`.
- Baseline entry `firstSeenAt` and `lastSeenAt` metadata plus severity summaries in baseline diffs.
- Read-only `agentready debt` reporting for baseline debt.
- Scan-result and baseline JSON schemas with contract tests.
- Optional SARIF upload support in the GitHub composite action.
- CI matrix, packed-tarball smoke testing, Dependency Review, Scorecard, and npm provenance release workflow.
- Release workflow guard for npm 11.5.1 or newer before publishing.
- Repository settings guidance for protected branches, release environments, trusted publishing, tags, and code scanning.
- Runnable demo fixtures and sample reports for clean, legacy, and CI/MCP projects.
- `npm run market:check` as a local market-readiness gate.
- A concise evaluation guide for adoption fit, release gates, and dogfood criteria.
- Config schema hints in generated configuration and documented schema metadata.
- Output-directory creation for scan reports and baseline files.
- `.envrc`, `.npmrc`, `.pypirc`, and `.netrc` coverage in sensitive-file scanning and generated agent boundaries.

### Changed

- Release workflow uses npm Trusted Publishing instead of a long-lived npm token.
- Removed internal planning material from the product documentation package.
- Refined generated agent ignore patterns so source files that discuss secret scanning are not hidden by broad filename globs.
- Hardened GitHub composite action input handling; SARIF uploads still run when scan findings fail the CI threshold.
- Improved scanner signal for sensitive directories, extensionless secret files, JSON-style secret assignments, MCP environment references, workflow comments, `pull_request_target` trigger forms, and alternate shell script extensions; IPv6 localhost MCP URLs classify as private network endpoints.
- Expanded SARIF output with tool metadata, the complete rule catalog, and a `PROJECTROOT` URI base for more stable code-scanning locations.
- Tightened CLI and configuration validation for invalid rule filters, invalid failure thresholds, unknown configuration fields, and non-object configuration files; unsupported command-specific options are rejected instead of ignored.
- Preserved UTF-16 text scanning when binary sniffing is enabled; improved onboarding command path quoting for shell-sensitive paths.
- Validated baseline file structure before applying suppression.
- Corrected trusted publisher setup guidance and required check names for the full CI matrix.

### Fixed

- Glob `?` wildcard patterns not being routed through glob-to-regexp conversion.
- Version information caching for repeated CLI invocations.
- Input validation for scan target existence.
- `**/` path pattern handling so root-level files and directories match expected glob behavior.

## 0.1.0

- Initial AgentReady CLI.
- Added local project scanning for secrets, risky scripts, GitHub Actions risks, MCP configuration risks, Python reproducibility issues, and missing agent boundaries.
- Added `scan`, `init`, `doctor`, `baseline`, `list-rules`, `config validate`, and `version` commands.
- Added text, JSON, Markdown, and SARIF reports.
- Added finding fingerprints and baseline suppression.
- Added starter GitHub Actions workflow and composite action support.
