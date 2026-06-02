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
npx agentready@latest scan .
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
agentready scan . --ignore-rule python.unpinned_requirement
```
