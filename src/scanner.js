import { existsSync } from "node:fs";
import { open, readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { DEFAULT_IGNORED_DIRS, MAX_FILE_BYTES, TEXT_EXTENSIONS, TEXT_FILE_NAMES } from "./constants.js";
import { DEFAULT_CONFIG, applyFindingConfig, matchesAnyPath } from "./config.js";
import { applyBaseline } from "./baseline.js";
import { addFingerprints } from "./fingerprint.js";
import { toRelative, summarizeSeverities } from "./utils.js";
import { enrichFindings } from "./rules.js";
import { MCP_CONFIG_NAMES, scanMcpConfig } from "./scanners/mcp.js";
import { isSensitivePath, scanSecretContent, scanSensitiveFileName } from "./scanners/secrets.js";
import { scanDangerousShell } from "./scanners/shell.js";
import { scanGitHubActions } from "./scanners/github-actions.js";
import { scanPackageJson } from "./scanners/package.js";
import { scanPythonProjectFiles } from "./scanners/python.js";

export async function scanProject(root, options = {}) {
  const startedAt = Date.now();
  if (!existsSync(root)) {
    throw new Error(`Scan target does not exist: ${root}`);
  }
  const config = options.config || DEFAULT_CONFIG;
  const collected = await collectFiles(root, config);
  const files = collected.files;
  const findings = [];

  findings.push(...scanProjectLevel(root));

  const BATCH_SIZE = 32;
  for (let i = 0; i < files.length; i += BATCH_SIZE) {
    const batch = files.slice(i, i + BATCH_SIZE);
    const results = await Promise.all(batch.map(async (filePath) => {
      const relativePath = toRelative(root, filePath);
      const basename = path.basename(filePath);
      const content = await readTextFile(filePath);
      if (content === null) {
        return [];
      }
      return [
        ...scanSensitiveFileName(relativePath, basename),
        ...scanSecretContent(relativePath, basename, content),
        ...scanDangerousShell(relativePath, content),
        ...scanPackageJson(relativePath, basename, content),
        ...scanGitHubActions(relativePath, content),
        ...scanMcpConfig(relativePath, basename, content),
        ...scanPythonProjectFiles(relativePath, basename, content)
      ];
    }));
    for (const batchResult of results) {
      findings.push(...batchResult);
    }
  }

  const configuredFindings = addFingerprints(enrichFindings(applyFindingConfig(dedupeFindings(findings), config)));
  const baselineResult = applyBaseline(configuredFindings, options.baseline || null);

  return {
    schemaVersion: "1",
    root,
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt,
    filesScanned: files.length,
    filesSkipped: collected.skipped,
    config: {
      configPath: config.configPath || null,
      failOn: config.failOn,
      baselinePath: config.baselinePath || null,
      ignorePaths: config.ignorePaths || [],
      ignoreRules: config.ignoreRules || [],
      severityOverrides: config.severityOverrides || {},
      maxFileBytes: config.maxFileBytes ?? DEFAULT_CONFIG.maxFileBytes
    },
    configWarnings: options.configWarnings || [],
    baseline: baselineResult.summary,
    findings: baselineResult.findings,
    summary: summarizeSeverities(baselineResult.findings)
  };
}

async function collectFiles(root, config) {
  const files = [];
  const skipped = {
    ignoredPath: 0,
    ignoredDirectory: 0,
    oversized: 0,
    binary: 0,
    unsupportedType: 0,
    unreadableDirectory: 0,
    unreadableFile: 0
  };

  async function walk(current) {
    let entries;
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch {
      skipped.unreadableDirectory += 1;
      return;
    }

    const subdirs = [];

    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      const relativePath = toRelative(root, fullPath);

      if (matchesAnyPath(config.ignorePaths || [], relativePath)) {
        skipped.ignoredPath += 1;
        continue;
      }

      if (entry.isDirectory()) {
        if (DEFAULT_IGNORED_DIRS.has(entry.name)) {
          skipped.ignoredDirectory += 1;
          continue;
        }
        subdirs.push(fullPath);
        continue;
      }

      if (!entry.isFile()) {
        continue;
      }

      const textCheck = await classifyTextFile(fullPath, relativePath, config);
      if (textCheck.ok) {
        files.push(fullPath);
      } else {
        skipped[textCheck.reason] += 1;
      }
    }

    await Promise.all(subdirs.map((dir) => walk(dir)));
  }

  await walk(root);
  return { files, skipped };
}

async function classifyTextFile(filePath, relativePath, config) {
  const extension = path.extname(filePath).toLowerCase();
  const basename = path.basename(filePath);

  let details;
  try {
    details = await stat(filePath);
  } catch {
    return { ok: false, reason: "unreadableFile" };
  }

  if (details.size > (config.maxFileBytes ?? MAX_FILE_BYTES)) {
    return { ok: false, reason: "oversized" };
  }

  if (isSensitivePath(relativePath, basename)) {
    return { ok: true };
  }

  if (!TEXT_EXTENSIONS.has(extension) && !TEXT_FILE_NAMES.has(basename) && !MCP_CONFIG_NAMES.has(basename)) {
    return { ok: false, reason: "unsupportedType" };
  }

  if (await isBinaryFile(filePath)) {
    return { ok: false, reason: "binary" };
  }

  return { ok: true };
}

async function readTextFile(filePath) {
  try {
    const buffer = await readFile(filePath);
    return decodeTextBuffer(buffer);
  } catch {
    return null;
  }
}

function decodeTextBuffer(buffer) {
  if (buffer.length >= 2 && buffer[0] === 0xff && buffer[1] === 0xfe) {
    return buffer.subarray(2).toString("utf16le");
  }

  if (buffer.length >= 2 && buffer[0] === 0xfe && buffer[1] === 0xff) {
    return decodeUtf16Be(buffer.subarray(2));
  }

  if (buffer.length >= 3 && buffer[0] === 0xef && buffer[1] === 0xbb && buffer[2] === 0xbf) {
    return buffer.subarray(3).toString("utf8");
  }

  return buffer.toString("utf8");
}

function decodeUtf16Be(buffer) {
  const swapped = Buffer.allocUnsafe(buffer.length);
  for (let index = 0; index < buffer.length; index += 2) {
    swapped[index] = buffer[index + 1] ?? 0;
    swapped[index + 1] = buffer[index];
  }
  return swapped.toString("utf16le");
}

async function isBinaryFile(filePath) {
  let handle;
  try {
    handle = await open(filePath, "r");
    const buffer = Buffer.alloc(1024);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    if (hasTextByteOrderMark(buffer, bytesRead)) {
      return false;
    }
    for (let index = 0; index < bytesRead; index += 1) {
      if (buffer[index] === 0) {
        return true;
      }
    }
    return false;
  } catch {
    return false;
  } finally {
    await handle?.close();
  }
}

function hasTextByteOrderMark(buffer, bytesRead) {
  if (bytesRead >= 2 && ((buffer[0] === 0xff && buffer[1] === 0xfe) || (buffer[0] === 0xfe && buffer[1] === 0xff))) {
    return true;
  }
  return bytesRead >= 3 && buffer[0] === 0xef && buffer[1] === 0xbb && buffer[2] === 0xbf;
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
    // Use unit separator (\x1f) to avoid collisions with pipe chars in paths
    const key = [finding.id, finding.file, finding.line, finding.evidence].join("\x1f");
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    deduped.push(finding);
  }

  return deduped;
}


