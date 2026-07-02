# Configuration

AgentReady reads `agentready.config.json` or `.agentready.json` from the scanned
project root.

Validate configuration:

```bash
agentready config validate .
```

Example:

```json
{
  "$schema": "https://raw.githubusercontent.com/Hephaestus-DevKit/agentready/main/schema/agentready.schema.json",
  "baselinePath": ".agentready-baseline.json",
  "failOn": "medium",
  "ignorePaths": ["fixtures/**"],
  "ignoreRules": ["python.unpinned_requirement"],
  "severityOverrides": {
    "package.lifecycle_script": "low"
  },
  "maxFileBytes": 524288
}
```

## Fields

- `baselinePath`: optional baseline file path
- `failOn`: CI threshold, one of `high`, `medium`, `low`, `info`, `none`
- `ignorePaths`: path patterns excluded from scanning
- `ignoreRules`: rule ids hidden from results
- `severityOverrides`: per-rule severity changes
- `maxFileBytes`: maximum file size, in bytes, that AgentReady reads during scans

`$schema` is optional but recommended for editor validation and completion.

Path patterns use normalized forward slashes. For example, `secrets` matches
that directory and its children, and `**/*.pem` matches `.pem` files at the
project root or below it.

## `.agentignore` And Scan Ignores

`.agentignore` documents paths that AI coding agents should avoid. AgentReady
does not automatically treat it as a scan ignore file, because hiding those
paths could also hide the evidence that a repository still exposes sensitive
files to agents.

Use `ignorePaths` only for reviewed paths that should be excluded from
AgentReady results.

`maxFileBytes` is an input-size limit, not a report limit. Increase it only
when a repository has large text configuration files that must be scanned. Files
above the limit are counted in `filesSkipped.oversized`.

Unknown top-level fields and unknown rule ids are reported as warnings. A
configuration root that is not a JSON object is ignored and reported as a
warning. `agentready config validate` exits with code `3` when warnings are
present so CI can catch configuration drift.
