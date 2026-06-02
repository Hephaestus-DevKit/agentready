import { existsSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { usageError } from "./errors.js";

const PRESETS = new Set(["balanced", "strict", "legacy"]);

const AGENTS_TEMPLATE = `# AGENTS.md

## Agent Boundaries

- Inspect context before changing files.
- Do not read, print, commit, or store secrets, credentials, private keys, recovery codes, or identity documents.
- Treat .env files, key files, database dumps, and private user content as sensitive.
- Ask before running commands that delete files, install global packages, change git history, push branches, or contact production systems.
- Prefer small, reviewable changes and verify behavior with tests or direct checks.

## Sensitive Paths

- .env
- .env.*
- **/*.pem
- **/*.key
- **/*secret*
- **/*credential*
- private/
- backups/
`;

const AGENTIGNORE_BASE = [
  "# Paths AI coding agents should avoid unless explicitly approved.",
  ".env",
  ".env.*",
  "*.pem",
  "*.key",
  "*.p12",
  "*.pfx",
  "*secret*",
  "*credential*",
  "private/",
  "backups/"
];

const STRICT_AGENTIGNORE_EXTRA = ["*.sqlite", "*.db", "*.dump", "data/private/", "infra/secrets/"];

const CI_WORKFLOW_TEMPLATE = `name: agentready

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npx agentready scan . --ci --format sarif --output agentready.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: agentready.sarif
`;

export async function runInit(root, options = {}) {
  const preset = options.preset || "balanced";
  if (!PRESETS.has(preset)) {
    throw usageError(`Unsupported preset "${preset}". Use balanced, strict, or legacy.`);
  }

  const messages = [];
  const agentignore = buildAgentignore(preset);
  const config = buildConfig(preset);

  await ensureFile(path.join(root, "AGENTS.md"), AGENTS_TEMPLATE, options, messages);
  await ensureFile(path.join(root, ".agentignore"), agentignore, options, messages);
  await ensureFile(path.join(root, ".agentready.json"), config, options, messages);

  if (options.withCi) {
    await ensureFile(path.join(root, ".github", "workflows", "agentready.yml"), CI_WORKFLOW_TEMPLATE, options, messages);
  }

  messages.push("");
  messages.push("Next steps:");
  messages.push("- Run agentready scan .");
  if (preset === "legacy") {
    messages.push("- Review current findings, then run agentready baseline . --output .agentready-baseline.json if needed.");
  }
  if (!options.withCi) {
    messages.push("- Add CI later with agentready init . --with-ci.");
  }

  return { messages };
}

function buildAgentignore(preset) {
  const lines = [...AGENTIGNORE_BASE];
  if (preset === "strict") {
    lines.push(...STRICT_AGENTIGNORE_EXTRA);
  }
  return `${lines.join("\n")}\n`;
}

function buildConfig(preset) {
  const config = {
    baselinePath: null,
    failOn: preset === "legacy" ? "high" : "medium",
    ignorePaths: preset === "strict" ? ["fixtures/**", "examples/**"] : [],
    ignoreRules: [],
    severityOverrides: {}
  };

  return `${JSON.stringify(config, null, 2)}\n`;
}

async function ensureFile(filePath, content, options, messages) {
  const existed = existsSync(filePath);

  if (existed && !options.force) {
    messages.push(`Skipped existing ${filePath}`);
    return;
  }

  if (options.dryRun) {
    messages.push(`${existed ? "Would overwrite" : "Would create"} ${filePath}`);
    return;
  }

  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, content, "utf8");
  messages.push(`${existed ? "Wrote" : "Created"} ${filePath}`);
}
