import { existsSync } from "node:fs";
import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { DEFAULT_IGNORED_DIRS, MAX_FILE_BYTES, TEXT_EXTENSIONS } from "./constants.js";
import { DEFAULT_CONFIG, applyFindingConfig, matchesAnyPath } from "./config.js";
import { applyBaseline } from "./baseline.js";
import { addFingerprints } from "./fingerprint.js";
import { toRelative } from "./reporters.js";
import { enrichFindings } from "./rules.js";
import { MCP_CONFIG_NAMES, scanMcpConfig } from "./scanners/mcp.js";
import { SENSITIVE_FILE_PATTERNS, scanSecretContent, scanSensitiveFileName } from "./scanners/secrets.js";
import { scanDangerousShell } from "./scanners/shell.js";
import { scanGitHubActions } from "./scanners/github-actions.js";
import { scanPackageJson } from "./scanners/package.js";
import { scanPythonProjectFiles } from "./scanners/python.js";

export async function scanProject(root, options = {}) {
  const startedAt = Date.now();
  const config = options.config || DEFAULT_CONFIG;
  const files = await collectFiles(root, config);
  const findings = [];

  findings.push(...scanProjectLevel(root));

  for (const filePath of files) {
    const relativePath = toRelative(root, filePath);
    const basename = path.basename(filePath);
    const content = await readTextFile(filePath);

    if (content === null) {
      continue;
    }

    findings.push(...scanSensitiveFileName(relativePath, basename));
    findings.push(...scanSecretContent(relativePath, basename, content));
    findings.push(...scanDangerousShell(relativePath, content));
    findings.push(...scanPackageJson(relativePath, basename, content));
    findings.push(...scanGitHubActions(relativePath, content));
    findings.push(...scanMcpConfig(relativePath, basename, content));
    findings.push(...scanPythonProjectFiles(relativePath, basename, content));
  }

  const configuredFindings = addFingerprints(enrichFindings(applyFindingConfig(dedupeFindings(findings), config)));
  const baselineResult = applyBaseline(configuredFindings, options.baseline || null);

  return {
    schemaVersion: "1",
    root,
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt,
    filesScanned: files.length,
    config: {
      configPath: config.configPath || null,
      failOn: config.failOn,
      baselinePath: config.baselinePath || null,
      ignorePaths: config.ignorePaths || [],
      ignoreRules: config.ignoreRules || [],
      severityOverrides: config.severityOverrides || {}
    },
    configWarnings: options.configWarnings || [],
    baseline: baselineResult.summary,
    findings: baselineResult.findings,
    summary: summarize(baselineResult.findings)
  };
}

async function collectFiles(root, config) {
  const files = [];

  async function walk(current) {
    let entries;
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      const relativePath = toRelative(root, fullPath);

      if (matchesAnyPath(config.ignorePaths || [], relativePath)) {
        continue;
      }

      if (entry.isDirectory()) {
        if (!DEFAULT_IGNORED_DIRS.has(entry.name)) {
          await walk(fullPath);
        }
        continue;
      }

      if (!entry.isFile()) {
        continue;
      }

      if (await isLikelyTextFile(fullPath)) {
        files.push(fullPath);
      }
    }
  }

  await walk(root);
  return files;
}

async function isLikelyTextFile(filePath) {
  const extension = path.extname(filePath).toLowerCase();
  const basename = path.basename(filePath);

  if (SENSITIVE_FILE_PATTERNS.some((pattern) => pattern.test(basename))) {
    return true;
  }

  if (!TEXT_EXTENSIONS.has(extension) && !MCP_CONFIG_NAMES.has(basename)) {
    return false;
  }

  try {
    const details = await stat(filePath);
    return details.size <= MAX_FILE_BYTES;
  } catch {
    return false;
  }
}

async function readTextFile(filePath) {
  try {
    return await readFile(filePath, "utf8");
  } catch {
    return null;
  }
}

function scanProjectLevel(root) {
  const findings = [];

  if (!existsSync(path.join(root, "AGENTS.md"))) {
    findings.push({
      id: "agent.missing_agents_md",
      severity: "info",
      title: "AGENTS.md is missing",
      file: null,
      line: null,
      evidence: "No AGENTS.md file was found at the project root.",
      recommendation: "Run agentready init to document safe operating boundaries for AI coding agents."
    });
  }

  if (!existsSync(path.join(root, ".agentignore"))) {
    findings.push({
      id: "agent.missing_agentignore",
      severity: "low",
      title: ".agentignore is missing",
      file: null,
      line: null,
      evidence: "No .agentignore file was found at the project root.",
      recommendation: "Run agentready init and add sensitive paths that agents should avoid."
    });
  }

  return findings;
}

function dedupeFindings(findings) {
  const seen = new Set();
  const deduped = [];

  for (const finding of findings) {
    const key = [finding.id, finding.file, finding.line, finding.evidence].join("|");
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    deduped.push(finding);
  }

  return deduped;
}

function summarize(findings) {
  return dedupeFindings(findings).reduce(
    (summary, finding) => {
      summary[finding.severity] += 1;
      return summary;
    },
    { high: 0, medium: 0, low: 0, info: 0 }
  );
}
