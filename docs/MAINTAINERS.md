# Maintainer Guide

This project should stay small, local-first, and predictable. Maintenance work
should improve signal without adding heavy runtime dependencies.

## Weekly Triage

- Review new issues and pull requests.
- Label items as `bug`, `enhancement`, `dependencies`, `security`, or `needs-triage`.
- Close reports that require secrets or private data to reproduce, and ask for a redacted fixture instead.
- Prefer small rule improvements over broad rewrites.

## Pull Request Review

Before merging, check:

- The change has a clear user impact.
- `npm run verify` passes.
- Rule ids remain stable unless a breaking change is intentional and documented.
- New or changed rules include tests for true positives and practical false-positive boundaries.
- CLI output remains useful for both humans and CI.
- Reports do not expose raw secrets.

## Rule Lifecycle

1. Define the user risk in one sentence.
2. Add scanner coverage with a stable rule id.
3. Add catalog metadata in `src/rules.js`.
4. Add tests for positive and negative cases.
5. Document configuration or suppression guidance if users need it.
6. Avoid changing severity after release unless real-world signal proves it is too noisy or too weak.

## Release Criteria

A release is ready when:

- `npm run verify` passes locally and in GitHub Actions.
- The changelog describes user-visible changes.
- The npm tarball contains runtime files, docs, schema, and license.
- The composite GitHub Action smoke test passes.
- README quickstart commands still match the CLI.

## Dependency Policy

- Keep runtime dependencies at zero unless a dependency removes substantial risk or complexity.
- Prefer standard Node.js APIs for filesystem, JSON, and process handling.
- Review Dependabot pull requests weekly, but do not merge dependency updates without `npm run verify`.

## Security Handling

- Use private advisories for security reports.
- Treat scanner outputs as potentially sensitive because paths and evidence can reveal private context.
- Do not ask reporters to paste real credentials, tokens, private keys, recovery codes, or identity documents.
