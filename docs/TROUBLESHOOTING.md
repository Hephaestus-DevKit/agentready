# Troubleshooting

## Check the Runtime

```bash
node --version
npm --version
agentready doctor .
```

AgentReady requires Node.js 20 or newer.

## npx Uses an Old Package

Clear the npm cache or run with an explicit version once the package is
published:

```bash
npx @hephaestus-devkit/agentready@latest scan .
```

## PowerShell Quoting

Use quotes around glob patterns:

```powershell
agentready scan . --ignore-path "fixtures/**"
```

## JSON Output Will Not Parse

Use JSON format without extra shell text:

```bash
agentready scan . --format json > agentready.json
```

Errors are written to stderr.

## Baseline Missing

Create it:

```bash
agentready baseline . --output .agentready-baseline.json
```

## Scan Is Too Noisy

Use a reviewed baseline for legacy projects or configure reviewed exceptions:

```bash
agentready scan . --fail-on high
agentready scan . --max-findings 25
agentready scan . --summary-only
agentready scan . --ignore-rule python.unpinned_requirement
```

## Files Are Skipped

Reports show skipped files by reason. `unsupported-type` means the file is not a
known text input. `binary` means a text-looking file contained NUL bytes.
`oversized` means the file exceeded the scan input limit.

Increase the input limit only when the large file is text that should be
reviewed:

```bash
agentready scan . --max-file-size 1048576
```

For legacy repositories, compare and prune baseline debt:

```bash
agentready baseline diff .
agentready baseline prune . --output .agentready-baseline.pruned.json
```
