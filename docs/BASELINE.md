# Baseline

Baselines let existing projects adopt AgentReady without immediately blocking on
known historical findings.

```bash
agentready baseline .
agentready baseline diff .
agentready scan . --baseline .agentready-baseline.json --ci
```

Baseline entries are matched by finding fingerprints. Each entry stores an
exact `fingerprint` and a line-independent `stableFingerprint`, so inserting or
deleting lines above a reviewed finding does not turn it into a new finding.
Baselines written by earlier versions (exact fingerprints only) keep matching;
run `agentready baseline prune .` to upgrade their entries. When a matching
finding appears again, it is suppressed from the active scan result.
Each entry stores `firstSeenAt` and `lastSeenAt` timestamps so teams can track
how long reviewed debt has been present. Regenerating a baseline with
`agentready baseline .` preserves `firstSeenAt` for findings that were already
recorded.

## Recommended Use

1. Run a normal scan.
2. Review findings with a human.
3. Create a baseline.
4. Run `agentready baseline diff .` before enabling CI to confirm only reviewed
   debt is suppressed.
5. Commit the baseline only if the team accepts it as tracked debt.
6. Remove fixed entries with `agentready baseline prune .`.

## Configuration

```json
{
  "baselinePath": ".agentready-baseline.json"
}
```

## Caution

A baseline is not a fix. It is a reviewed exception list. High severity baseline
entries should be removed as soon as practical.

## Diff And Prune

```bash
agentready baseline diff .
agentready baseline diff . --format markdown --output agentready-baseline-diff.md
agentready baseline prune .
agentready debt .
```

`baseline diff` shows:

- findings that still match reviewed baseline entries
- new findings not covered by the baseline
- stale baseline entries whose underlying findings no longer exist
- severity summaries for new and stale baseline debt

`baseline prune` rewrites the baseline with only currently matched entries. Use
`--output` to preview the pruned file in a separate path.

## Debt Report

```bash
agentready debt .
agentready debt . --config .agentready.json
agentready debt . --format markdown --output agentready-debt.md
```

`debt` is a read-only baseline report. It groups reviewed debt by severity,
rule, file, and age. It does not add new findings to the baseline. It can read
`baselinePath` from configuration or an explicit `--baseline` path.
