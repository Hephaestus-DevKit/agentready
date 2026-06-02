# Baseline

Baselines let existing projects adopt AgentReady without immediately blocking on
known historical findings.

```bash
agentready baseline . --output .agentready-baseline.json
agentready scan . --baseline .agentready-baseline.json --ci
```

Baseline entries are matched by stable finding fingerprints. When a matching
finding appears again, it is suppressed from the active scan result.

## Recommended Use

1. Run a normal scan.
2. Review findings with a human.
3. Create a baseline.
4. Commit the baseline only if the team accepts it as tracked debt.
5. Remove baseline entries as findings are fixed.

## Configuration

```json
{
  "baselinePath": ".agentready-baseline.json"
}
```

## Caution

A baseline is not a fix. It is a reviewed exception list. High severity baseline
entries should be removed as soon as practical.
