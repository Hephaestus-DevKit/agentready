import { existsSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { formatCommandPath } from "./command-path.js";
import { MAX_FILE_BYTES } from "./constants.js";
import { AgentReadyError, usageError } from "./errors.js";

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
- .envrc
- .npmrc
- .pypirc
- .netrc
- **/*.pem
- **/*.key
- **/*.p12
- **/*.pfx
- secrets/
- credentials/
- **/secrets/**
- **/credentials/**
- **/*secret*.env
- **/*credential*.env
- private/
- backups/
- **/private/**
- **/backups/**
`;

const AGENTIGNORE_BASE = [
  "# Paths AI coding agents should avoid unless explicitly approved.",
  ".env",
  ".env.*",
  ".envrc",
  ".npmrc",
  ".pypirc",
  ".netrc",
  "*.pem",
  "*.key",
  "*.p12",
  "*.pfx",
  "secrets/",
  "credentials/",
  "**/secrets/**",
  "**/credentials/**",
  "**/*secret*.env",
  "**/*credential*.env",
  "private/",
  "backups/",
  "**/private/**",
  "**/backups/**"
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
      - uses: actions/checkout@v7
        with:
          persist-credentials: false
      - uses: actions/setup-node@v6
        with:
          node-version: 20
      - run: npx agentready scan . --ci --format sarif --output agentready.sarif
      - uses: github/codeql-action/upload-sarif@v4
        if: \${{ !cancelled() }}
        with:
          sarif_file: agentready.sarif
`;

export async function runInit(root, options = {}) {
  const preset = options.preset || "balanced";
  if (!PRESETS.has(preset)) {
    throw usageError(`Unsupported preset "${preset}". Use balanced, strict, or legacy.`);
  }

  const messages = [];
  const targetArg = formatCommandPath(root);
  const agentignore = buildAgentignore(preset);
  const config = buildConfig(preset);

  await ensureFile(root, "AGENTS.md", AGENTS_TEMPLATE, options, messages);
  await ensureFile(root, ".agentignore", agentignore, options, messages);
  await ensureFile(root, ".agentready.json", config, options, messages);

  if (options.withCi) {
    await ensureFile(root, path.join(".github", "workflows", "agentready.yml"), CI_WORKFLOW_TEMPLATE, options, messages);
  }

  messages.push("");
  messages.push("Next steps:");
  messages.push(`- Run agentready config validate ${targetArg}`);
  messages.push(`- Run agentready scan ${targetArg}`);
  messages.push(`- Save a shareable report with agentready scan ${targetArg} --format markdown --output agentready-report.md.`);
  if (preset === "legacy") {
    messages.push(`- Review current findings, then run agentready baseline ${targetArg} if needed.`);
  }
  if (!options.withCi) {
    messages.push(`- Add CI later with agentready init ${targetArg} --with-ci.`);
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
    $schema: "https://raw.githubusercontent.com/Hephaestus-DevKit/agentready/main/schema/agentready.schema.json",
    baselinePath: null,
    failOn: preset === "legacy" ? "high" : "medium",
    ignorePaths: preset === "strict" ? ["fixtures/**", "examples/**"] : [],
    ignoreRules: [],
    severityOverrides: {},
    maxFileBytes: MAX_FILE_BYTES
  };

  return `${JSON.stringify(config, null, 2)}\n`;
}

async function ensureFile(root, relativePath, content, options, messages) {
  const filePath = path.join(root, relativePath);
  const existed = existsSync(filePath);
  const displayPath = relativePath.replaceAll("\\", "/");

  if (existed && !options.force) {
    messages.push(`Skipped existing ${displayPath}`);
    return;
  }

  if (options.dryRun) {
    messages.push(`${existed ? "Would overwrite" : "Would create"} ${displayPath}`);
    return;
  }

  try {
    await mkdir(path.dirname(filePath), { recursive: true });
    await writeFile(filePath, content, "utf8");
  } catch (error) {
    throw new AgentReadyError(
      `Failed to write ${displayPath}: ${error.message}\nCheck that the directory is writable and that you have sufficient permissions.`,
      4
    );
  }
  messages.push(`${existed ? "Wrote" : "Created"} ${displayPath}`);
}
