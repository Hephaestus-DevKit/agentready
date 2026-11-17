import { existsSync, statSync } from "node:fs";
import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { DEFAULT_IGNORED_DIRS, MAX_FILE_BYTES, TEXT_EXTENSIONS, TEXT_FILE_NAMES } from "./constants.js";
import { DEFAULT_CONFIG, applyFindingConfig, matchesAnyPath } from "./config.js";
import { applyBaseline } from "./baseline.js";
import { addFingerprints } from "./fingerprint.js";
import { usageError } from "./errors.js";
import { toRelative, summarizeSeverities } from "./utils.js";
import { enrichFindings } from "./rules.js";
import { TOOL_VERSION } from "./version.js";
import { MCP_CONFIG_NAMES, scanMcpConfig } from "./scanners/mcp.js";
import { isSensitivePath, scanSecretContent, scanSensitiveFileName } from "./scanners/secrets.js";
import { scanDangerousShell } from "./scanners/shell.js";
import { scanGitHubActions } from "./scanners/github-actions.js";
import { scanPackageJson } from "./scanners/package.js";
import { scanPythonProjectFiles } from "./scanners/python.js";

export async function scanProject(root, options = {}) {
  const startedAt = Date.now();
  if (!existsSync(root)) {
    // Usage error (exit 2): a missing target is caller input, not a crash,
    // so the CLI should print a clean message instead of a stack trace.
    throw usageError(`Scan target does not exist: ${root}`);
  }
  // A file target would walk zero files and report a clean scan, which a
  // `--ci` gate would read as a pass.
  if (!statSync(root).isDirectory()) {
    throw usageError(`Scan target must be a directory: ${root}`);
  }
  const config = options.config || DEFAULT_CONFIG;
  const collected = await collectFiles(root, config);
  const files = collected.files;
  const findings = [];
  let filesScanned = 0;

  findings.push(...scanProjectLevel(root));
  for (const sensitiveFile of collected.oversizedSensitiveFiles) {
    findings.push(...scanSensitiveFileName(sensitiveFile.relativePath, sensitiveFile.basename));
  }

  const BATCH_SIZE = 32;
  for (let i = 0; i < files.length; i += BATCH_SIZE) {
    const batch = files.slice(i, i + BATCH_SIZE);
    const results = await Promise.all(batch.map((filePath) => scanFile(root, filePath)));
    for (const result of results) {
      if (result.status === "scanned") {
        filesScanned += 1;
        findings.push(...result.findings);
      } else {
        collected.skipped[result.status] += 1;
      }
    }
  }

  const configuredFindings = addFingerprints(enrichFindings(applyFindingConfig(dedupeFindings(findings), config)));
  const baselineResult = applyBaseline(configuredFindings, options.baseline || null);

  return {
    schemaVersion: "1",
    toolVersion: TOOL_VERSION,
    root,
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt,
    filesScanned,
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
  const oversizedSensitiveFiles = [];
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
    } catch (error) {
      if (error?.code === "EMFILE" || error?.code === "ENFILE") {
        throw error;
      }
      skipped.unreadableDirectory += 1;
      return;
    }

    const subdirs = [];

    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      const relativePath = toRelative(root, fullPath);

      if (matchesAnyPath(config.ignorePaths || [], relativePath, { isDirectory: entry.isDirectory() })) {
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
        skipped.unsupportedType += 1;
        continue;
      }

      const textCheck = await classifyTextFile(fullPath, relativePath, config);
      if (textCheck.ok) {
        files.push(fullPath);
      } else {
        skipped[textCheck.reason] += 1;
        if (textCheck.reason === "oversized" && textCheck.sensitive) {
          oversizedSensitiveFiles.push({ relativePath, basename: entry.name });
        }
      }
    }

    const WALK_CONCURRENCY = 16;
    for (let index = 0; index < subdirs.length; index += WALK_CONCURRENCY) {
      await Promise.all(subdirs.slice(index, index + WALK_CONCURRENCY).map((dir) => walk(dir)));
    }
  }

  await walk(root);
  // Directory subtrees are walked concurrently, so collection order depends on
  // fs latency; sort by POSIX relative path so findings order stays identical
  // across runs and across Windows/POSIX path separators.
  const compareByRelative = (left, right) => {
    const leftRel = toRelative(root, left);
    const rightRel = toRelative(root, right);
    return leftRel < rightRel ? -1 : leftRel > rightRel ? 1 : 0;
  };
  files.sort(compareByRelative);
  oversizedSensitiveFiles.sort((left, right) =>
    left.relativePath < right.relativePath ? -1 : left.relativePath > right.relativePath ? 1 : 0
  );
  return { files, oversizedSensitiveFiles, skipped };
}

async function scanFile(root, filePath) {
  const relativePath = toRelative(root, filePath);
  const basename = path.basename(filePath);

  let buffer;
  try {
    buffer = await readFile(filePath);
  } catch {
    return { status: "unreadableFile" };
  }

  if (isBinaryBuffer(buffer)) {
    if (isSensitivePath(relativePath, basename)) {
      // A binary key store (.p12, .pfx, ...) still deserves the filename
      // finding; only content scanning is meaningless for it.
      return { status: "scanned", findings: scanSensitiveFileName(relativePath, basename) };
    }
    return { status: "binary" };
  }

  const content = decodeTextBuffer(buffer);
  return {
    status: "scanned",
    findings: [
      ...scanSensitiveFileName(relativePath, basename),
      ...scanSecretContent(relativePath, basename, content),
      ...scanDangerousShell(relativePath, content),
      ...scanPackageJson(relativePath, basename, content),
      ...scanGitHubActions(relativePath, content),
      ...scanMcpConfig(relativePath, basename, content),
      ...scanPythonProjectFiles(relativePath, basename, content)
    ]
  };
}

async function classifyTextFile(filePath, relativePath, config) {
  const extension = path.extname(filePath).toLowerCase();
  const basename = path.basename(filePath);
  const sensitive = isSensitivePath(relativePath, basename);

  let details;
  try {
    details = await stat(filePath);
  } catch (error) {
    if (error?.code === "EMFILE" || error?.code === "ENFILE") {
      throw error;
    }
    return { ok: false, reason: "unreadableFile" };
  }

  if (details.size > (config.maxFileBytes ?? MAX_FILE_BYTES)) {
    // Large key stores (.p12) and database dumps (backups/*.sql) still deserve
    // the sensitive-filename finding without reading megabytes into memory.
    return { ok: false, reason: "oversized", sensitive };
  }

  if (sensitive) {
    return { ok: true };
  }

  if (!TEXT_EXTENSIONS.has(extension) && !TEXT_FILE_NAMES.has(basename) && !MCP_CONFIG_NAMES.has(basename)) {
    return { ok: false, reason: "unsupportedType" };
  }

  return { ok: true };
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
  const evenLength = buffer.length - (buffer.length % 2);
  const swapped = Buffer.allocUnsafe(evenLength);
  for (let index = 0; index < evenLength; index += 2) {
    swapped[index] = buffer[index + 1];
    swapped[index + 1] = buffer[index];
  }
  return swapped.toString("utf16le");
}

function isBinaryBuffer(buffer) {
  const sniffLength = Math.min(buffer.length, 1024);
  if (hasTextByteOrderMark(buffer, sniffLength)) {
    return false;
  }
  for (let index = 0; index < sniffLength; index += 1) {
    if (buffer[index] === 0) {
      return true;
    }
  }
  return false;
}

function hasTextByteOrderMark(buffer, bytesRead) {
  // Reject 4-byte UTF-32 BOMs (`FF FE 00 00` / `00 00 FE FF`) so binary or
  // UTF-32 files are not misdecoded as UTF-16LE.
  if (
    bytesRead >= 4 &&
    ((buffer[0] === 0xff && buffer[1] === 0xfe && buffer[2] === 0x00 && buffer[3] === 0x00) ||
      (buffer[0] === 0x00 && buffer[1] === 0x00 && buffer[2] === 0xfe && buffer[3] === 0xff))
  ) {
    return false;
  }
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
    const key = JSON.stringify([finding.id, finding.file, finding.line, finding.evidence, finding.title]);
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    deduped.push(finding);
  }

  return deduped;
}


