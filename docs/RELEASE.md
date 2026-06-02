# Release Checklist

Before publishing:

```bash
npm test
npm run scan:ci
npm run config:validate
npm run pack:dry-run
```

Verify:

- README quick start works
- `agentready version` prints the package version
- `agentready scan . --format json` parses as JSON
- `agentready scan . --format sarif` parses as SARIF
- npm tarball includes docs and runtime files
- no placeholder repository URLs are present
- GitHub composite action still runs `bin/agentready.js`
