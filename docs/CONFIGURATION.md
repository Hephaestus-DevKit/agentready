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
  "baselinePath": ".agentready-baseline.json",
  "failOn": "medium",
  "ignorePaths": ["fixtures/**"],
  "ignoreRules": ["python.unpinned_requirement"],
  "severityOverrides": {
    "package.lifecycle_script": "low"
  }
}
```

## Fields

- `baselinePath`: optional baseline file path
- `failOn`: CI threshold, one of `high`, `medium`, `low`, `info`, `none`
- `ignorePaths`: path patterns excluded from scanning
- `ignoreRules`: rule ids hidden from results
- `severityOverrides`: per-rule severity changes

Unknown rule ids are reported as warnings.
