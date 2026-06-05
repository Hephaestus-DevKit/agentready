# Release Checklist

Before publishing:

```bash
npm run market:check
```

Verify:

- README quick start works
- `agentready version` prints the package version
- `agentready scan . --format json` parses as JSON
- `agentready scan . --format sarif` parses as SARIF
- `agentready debt .` works for reviewed baseline files
- npm tarball includes docs and runtime files
- packed-tarball smoke test installs and runs the packaged CLI
- release workflow uses Node.js 24 and `id-token: write` for npm Trusted
  Publishing
- release tag matches `package.json` version, for example `v0.1.0`
- release workflow checks npm 11.5.1 or newer before publishing
- release workflow disables package-manager caching for the publish job
- no placeholder repository URLs are present
- public product surface does not contain internal planning or application
  material
- GitHub composite action still runs `bin/agentready.js`
- pull request and issue templates still match the current maintenance process
- GitHub `npm` environment and npm Trusted Publishing are configured as in
  [Repository settings](REPOSITORY_SETTINGS.md)
- External launch steps are checked against [Next steps](../next_steps.md)

Publishing:

- Create an immutable release tag such as `v0.1.0`.
- Keep the release tag exactly aligned with the package version.
- Publish through the GitHub `release` workflow, not from a local workstation.
- Confirm npm provenance is present after publication.
- Confirm no long-lived npm automation token was needed for the release.
- Do not move a published tag; publish a patch release instead.
