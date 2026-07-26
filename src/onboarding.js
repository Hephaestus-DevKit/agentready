import { existsSync } from "node:fs";
import { readdir } from "node:fs/promises";
import path from "node:path";
import { formatCommandPath } from "./command-path.js";
import { CONFIG_FILE_NAMES } from "./config.js";
import { PACKAGE_NAME } from "./version.js";

export async function runQuickstart(root) {
  const packageManager = detectPackageManager(root);
  const runner = packageManager.runner;
  const targetArg = formatCommandPath(root);
  const setup = await detectSetup(root);
  const needsSetup = !setup.hasConfig || !setup.hasAgents || !setup.hasAgentignore;
  const needsCi = !setup.hasGitHubActions;

  const lines = [
    "AgentReady Quickstart",
    `Project: ${root}`,
    `Runtime: Node ${process.versions.node} ${nodeMajor() >= 20 ? "(ok)" : "(needs Node 20+)"}`,
    `Package runner: ${runner}`,
    "",
    "Current setup:",
    `- Configuration: ${setup.hasConfig ? setup.configPath : "missing"}`,
    `- Agent boundaries: ${setup.hasAgents ? "AGENTS.md" : "missing AGENTS.md"}`,
    `- Agent ignore file: ${setup.hasAgentignore ? ".agentignore" : "missing .agentignore"}`,
    `- GitHub Actions: ${setup.hasGitHubActions ? "detected" : "not detected"}`,
    "",
    "Recommended commands:"
  ];

  // Always spell out the scoped package name: the unscoped "agentready" on the
  // npm registry is a different, unrelated package, so a bare
  // "npx agentready ..." without a local install would fetch the wrong tool.
  const cli = `${runner} ${PACKAGE_NAME}`;

  if (needsSetup) {
    const ciFlag = needsCi ? " --with-ci" : "";
    lines.push(`- Preview setup: ${cli} init ${targetArg} --dry-run${ciFlag}`);
    lines.push(`- Create setup files: ${cli} init ${targetArg}${ciFlag}`);
  } else {
    lines.push(`- Validate config: ${cli} config validate ${targetArg}`);
    if (needsCi) {
      lines.push(`- Add CI later: ${cli} init ${targetArg} --with-ci`);
    }
  }

  lines.push(`- Run a scan: ${cli} scan ${targetArg}`);
  lines.push(`- Save a review report: ${cli} scan ${targetArg} --format markdown --output agentready-report.md`);
  lines.push(`- If adopting existing findings: ${cli} baseline ${targetArg}`);
  lines.push("");
  lines.push(`Optional local install: ${packageManager.install} ${PACKAGE_NAME}`);

  return { messages: lines };
}

async function detectSetup(root) {
  const configPath = CONFIG_FILE_NAMES.map((name) => path.join(root, name)).find((candidate) => existsSync(candidate));

  return {
    hasConfig: Boolean(configPath),
    configPath: configPath ? path.basename(configPath) : null,
    hasAgents: existsSync(path.join(root, "AGENTS.md")),
    hasAgentignore: existsSync(path.join(root, ".agentignore")),
    hasGitHubActions: await hasGitHubActions(root)
  };
}

async function hasGitHubActions(root) {
  const workflowDir = path.join(root, ".github", "workflows");
  if (!existsSync(workflowDir)) {
    return false;
  }

  try {
    const entries = await readdir(workflowDir);
    return entries.some((entry) => /\.(ya?ml)$/i.test(entry));
  } catch {
    return false;
  }
}

function detectPackageManager(root) {
  if (existsSync(path.join(root, "pnpm-lock.yaml"))) {
    return { runner: "pnpm dlx", install: "pnpm add -D" };
  }

  if (existsSync(path.join(root, "yarn.lock"))) {
    return { runner: "yarn dlx", install: "yarn add -D" };
  }

  if (existsSync(path.join(root, "bun.lock")) || existsSync(path.join(root, "bun.lockb"))) {
    return { runner: "bunx", install: "bun add -d" };
  }

  return { runner: "npx", install: "npm install -D" };
}

function nodeMajor() {
  return Number(process.versions.node.split(".")[0]);
}
