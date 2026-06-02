# Rules

List rules:

```bash
agentready list-rules
agentready list-rules --format markdown
agentready list-rules --category github-actions
agentready list-rules --severity high
```

Each rule has:

- stable rule id
- default severity
- category
- description
- recommendation

Rule ids are used in configuration:

```json
{
  "ignoreRules": ["python.unpinned_requirement"],
  "severityOverrides": {
    "package.lifecycle_script": "low"
  }
}
```

Prefer fixing real issues. Use ignores for reviewed, intentional exceptions.
