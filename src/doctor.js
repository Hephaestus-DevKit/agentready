import { existsSync } from "node:fs";
import { access, constants as fsConstants } from "node:fs/promises";
import path from "node:path";
import { applyBaseline } from "./baseline.js";
import { DEFAULT_CONFIG, applyFindingConfig } from "./config.js";
import { scanProject } from "./scanner.js";
import { addFingerprints } from "./fingerprint.js";
import { enrichFindings } from "./rules.js";
import { nodeMajor, summarizeSeverities } from "./utils.js";
import { TOOL_VERSION } from "./version.js";

export async function runDoctor(root, options = {}) {
  const config = options.config || DEFAULT_CONFIG;
  const result = await scanProject(root, { ...options, baseline: null });
  const checks = [];
  const gitRoot = findGitRoot(root);
  const writable = await isWritable(root);

  checks.push({
    id: "doctor.node",
    severity: nodeMajor() >= 20 ? "info" : "medium",
    title: "Node.js runtime",
    file: null,
    line: null,
    evidence: `Node ${process.versions.node}`,
    recommendation: "Use Node.js 20 or newer for stable CLI execution."
  });

  checks.push({
    id: "doctor.git",
    severity: gitRoot ? "info" : "low",
    title: "Git repository check",
    file: null,
    line: null,
    evidence: gitRoot ? `Git metadata found at ${gitRoot}.` : "No .git directory found.",
    recommendation: "Run AgentReady inside a project repository for the most useful results."
  });

  checks.push({
    id: "doctor.write",
    severity: writable ? "info" : "medium",
    title: "Workspace write access",
    file: null,
    line: null,
    evidence: writable ? "Workspace is writable." : "Workspace is not writable.",
    recommendation: "Write access is required for agentready init and report output."
  });

  // Apply config overrides/ignores to doctor checks too so ignoreRules,
  // severityOverrides, and baselines treat doctor.* like any other catalog rule.
  const configuredChecks = addFingerprints(enrichFindings(applyFindingConfig(checks, config)));
  const baselineResult = applyBaseline([...configuredChecks, ...result.findings], options.baseline || null);

  return {
    schemaVersion: "1",
    toolVersion: TOOL_VERSION,
    root,
    scannedAt: new Date().toISOString(),
    durationMs: result.durationMs,
    filesScanned: result.filesScanned,
    filesSkipped: result.filesSkipped,
    config: result.config,
    configWarnings: result.configWarnings,
    baseline: baselineResult.summary,
    findings: baselineResult.findings,
    summary: summarizeSeverities(baselineResult.findings)
  };
}

async function isWritable(root) {
  try {
    await access(root, fsConstants.W_OK);
    return true;
  } catch {
    return false;
  }
}

function findGitRoot(root) {
  let current = path.resolve(root);

  while (true) {
    if (existsSync(path.join(current, ".git"))) {
      return current;
    }

    const parent = path.dirname(current);
    if (parent === current) {
      return null;
    }
    current = parent;
  }
}


