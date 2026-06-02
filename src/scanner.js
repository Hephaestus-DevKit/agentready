import { existsSync } from "node:fs";
import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { DEFAULT_IGNORED_DIRS, MAX_FILE_BYTES, TEXT_EXTENSIONS } from "./constants.js";
import { DEFAULT_CONFIG, applyFindingConfig, matchesAnyPath } from "./config.js";
import { applyBaseline } from "./baseline.js";
import { addFingerprints } from "./fingerprint.js";
import { toRelative } from "./reporters.js";
import { enrichFindings } from "./rules.js";

const SECRET_PATTERNS = [
  {
    id: "secret.private_key",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/,
    title: "Private key material is present",
    recommendation: "Remove private keys from the repository and rotate any exposed credentials."
  },
  {
    id: "secret.github_token",
    pattern: /\bgh[pousr]_[A-Za-z0-9_]{30,}\b/,
    title: "GitHub token-like value is present",
    recommendation: "Move the token to a secret manager, rotate it, and keep it outside agent-readable files."
  },
  {
    id: "secret.anthropic_key",
    pattern: /\bsk-ant-[A-Za-z0-9_-]{32,}\b/,
    title: "Anthropic-style API key is present",
    recommendation: "Move API keys to environment secrets and add the file to .agentignore and .gitignore."
  },
  {
    id: "secret.openai_key",
    pattern: /\bsk-(?!ant-)[A-Za-z0-9_-]{32,}\b/,
    title: "OpenAI-style API key is present",
    recommendation: "Move API keys to environment secrets and add the file to .agentignore and .gitignore."
  },
  {
    id: "secret.aws_access_key",
    pattern: /\bAKIA[0-9A-Z]{16}\b/,
    title: "AWS access key-like value is present",
    recommendation: "Rotate the key, remove it from the repository, and use scoped secret storage."
  }
];

const SENSITIVE_FILE_PATTERNS = [
  /^\.env(?:\.|$)/,
  /(?:^|[._-])secret(?:s)?(?:[._-]|$)/i,
  /(?:^|[._-])credential(?:s)?(?:[._-]|$)/i,
  /\.(?:pem|key|p12|pfx)$/i
];

const MCP_CONFIG_NAMES = new Set([
  "claude_desktop_config.json",
  "mcp.json",
  "mcp-config.json"
]);

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

function scanSensitiveFileName(relativePath, basename) {
  if (!SENSITIVE_FILE_PATTERNS.some((pattern) => pattern.test(basename))) {
    return [];
  }

  return [
    {
      id: "secret.sensitive_filename",
      severity: "medium",
      title: "Sensitive-looking file is agent-readable",
      file: relativePath,
      line: null,
      evidence: basename,
      recommendation: "Keep this file out of git and add it to .agentignore unless agents explicitly need it."
    }
  ];
}

function scanSecretContent(relativePath, basename, content) {
  const findings = [];
  const lines = content.split(/\r?\n/);

  for (const rule of SECRET_PATTERNS) {
    for (let index = 0; index < lines.length; index += 1) {
      if (!rule.pattern.test(lines[index])) {
        continue;
      }

      findings.push({
        id: rule.id,
        severity: "high",
        title: rule.title,
        file: relativePath,
        line: index + 1,
        evidence: redact(lines[index]),
        recommendation: rule.recommendation
      });
      break;
    }
  }

  if (isSensitiveFileName(basename)) {
    findings.push(...scanGenericSecretAssignments(relativePath, lines));
  }

  return findings;
}

function scanDangerousShell(relativePath, content) {
  if (!/\.(?:sh|ps1|bash|zsh|cmd|bat)$/i.test(relativePath)) {
    return [];
  }

  return scanDangerousCommandLines(relativePath, content, "script.dangerous_command");
}

function scanPackageJson(relativePath, basename, content) {
  if (basename !== "package.json") {
    return [];
  }

  let parsed;
  try {
    parsed = JSON.parse(content);
  } catch {
    return [
      {
        id: "package.invalid_json",
        severity: "low",
        title: "package.json could not be parsed",
        file: relativePath,
        line: null,
        evidence: "Invalid JSON",
        recommendation: "Fix package.json so AgentReady and package managers can inspect scripts and dependencies."
      }
    ];
  }

  const findings = [];
  const scripts = parsed.scripts || {};
  for (const [name, command] of Object.entries(scripts)) {
    const commandFindings = classifyDangerousCommand(String(command));
    for (const commandFinding of commandFindings) {
      findings.push({
        id: `package.script.${commandFinding.id}`,
        severity: commandFinding.severity,
        title: `Risky npm script: ${name}`,
        file: relativePath,
        line: findLine(content, `"${name}"`),
        evidence: `${name}: ${redact(String(command))}`,
        recommendation: commandFinding.recommendation
      });
    }
  }

  for (const lifecycle of ["preinstall", "install", "postinstall", "prepare"]) {
    if (scripts[lifecycle]) {
      findings.push({
        id: "package.lifecycle_script",
        severity: lifecycle === "postinstall" ? "medium" : "low",
        title: `Package lifecycle script detected: ${lifecycle}`,
        file: relativePath,
        line: findLine(content, `"${lifecycle}"`),
        evidence: `${lifecycle}: ${redact(String(scripts[lifecycle]))}`,
        recommendation: "Review lifecycle scripts before allowing agents or CI to install dependencies automatically."
      });
    }
  }

  return findings;
}

function scanGitHubActions(relativePath, content) {
  if (!relativePath.startsWith(".github/workflows/") || !/\.(?:yml|yaml)$/i.test(relativePath)) {
    return [];
  }

  const findings = [];
  const lines = content.split(/\r?\n/);
  let inRunBlock = false;
  let runBlockIndent = 0;

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const trimmed = line.trim();
    const indent = getIndent(line);

    if (inRunBlock) {
      if (!trimmed) {
        continue;
      }

      if (indent <= runBlockIndent) {
        inRunBlock = false;
      } else {
        findings.push(...scanGitHubActionRunCommand(relativePath, line, index + 1));
        continue;
      }
    }

    if (/\bpull_request_target\s*:/.test(line) || /^\s*on\s*:\s*pull_request_target\s*$/.test(line)) {
      findings.push({
        id: "github_actions.pull_request_target",
        severity: "high",
        title: "GitHub Actions uses pull_request_target",
        file: relativePath,
        line: index + 1,
        evidence: line.trim(),
        recommendation: "Avoid pull_request_target for untrusted code, or heavily restrict checkout, scripts, and secrets."
      });
    }

    if (/permissions\s*:\s*write-all/.test(line)) {
      findings.push({
        id: "github_actions.write_all",
        severity: "medium",
        title: "GitHub Actions grants write-all permissions",
        file: relativePath,
        line: index + 1,
        evidence: line.trim(),
        recommendation: "Use least-privilege permissions such as contents: read unless write access is required."
      });
    }

    const writePermission = line.match(/^\s*(actions|checks|contents|deployments|id-token|issues|packages|pull-requests|statuses)\s*:\s*write\s*$/);
    if (writePermission) {
      findings.push({
        id: "github_actions.write_permission",
        severity: "medium",
        title: `GitHub Actions grants ${writePermission[1]} write permission`,
        file: relativePath,
        line: index + 1,
        evidence: trimmed,
        recommendation: "Use least-privilege permissions and grant write access only to jobs that require it."
      });
    }

    if (/^\s*secrets\s*:\s*inherit\s*$/.test(line)) {
      findings.push({
        id: "github_actions.secrets_inherit",
        severity: "medium",
        title: "GitHub Actions inherits all caller secrets",
        file: relativePath,
        line: index + 1,
        evidence: trimmed,
        recommendation: "Pass only the specific secrets required by the reusable workflow."
      });
    }

    if (/persist-credentials\s*:\s*true/.test(line)) {
      findings.push({
        id: "github_actions.persist_credentials",
        severity: "low",
        title: "actions/checkout persists credentials",
        file: relativePath,
        line: index + 1,
        evidence: line.trim(),
        recommendation: "Set persist-credentials: false when jobs do not need to push to the repository."
      });
    }

    const runMatch = line.match(/^\s*-?\s*run\s*:\s*(.*)$/);
    if (runMatch) {
      const command = runMatch[1].trim();
      if (/^[>|][+-]?$/.test(command)) {
        inRunBlock = true;
        runBlockIndent = indent;
      } else {
        findings.push(...scanGitHubActionRunCommand(relativePath, command, index + 1));
      }
    }
  }

  return findings;
}

function scanMcpConfig(relativePath, basename, content) {
  if (!MCP_CONFIG_NAMES.has(basename) && !relativePath.includes("/mcp")) {
    return [];
  }

  let parsed = null;
  try {
    parsed = JSON.parse(content);
  } catch {
    return [];
  }

  const findings = [];
  const serialized = JSON.stringify(parsed, null, 2);
  const stringValues = collectJsonStrings(parsed);

  if (/\b(cmd|powershell|pwsh|bash|sh)\b/i.test(serialized)) {
    findings.push({
      id: "mcp.shell_tool",
      severity: "medium",
      title: "MCP configuration can launch a shell",
      file: relativePath,
      line: findLine(content, "command"),
      evidence: "Shell-like command found in MCP configuration.",
      recommendation: "Restrict shell-capable MCP servers and require human approval for destructive commands."
    });
  }

  if (stringValues.some(isBroadFilesystemPath)) {
    findings.push({
      id: "mcp.broad_filesystem",
      severity: "medium",
      title: "MCP configuration may expose broad filesystem access",
      file: relativePath,
      line: null,
      evidence: "Absolute or home/root path found in MCP configuration.",
      recommendation: "Limit filesystem MCP servers to the smallest project-specific directories."
    });
  }

  if (/(api[_-]?key|token|secret|password)/i.test(serialized)) {
    findings.push({
      id: "mcp.inline_secret",
      severity: "high",
      title: "MCP configuration appears to contain inline secrets",
      file: relativePath,
      line: null,
      evidence: "Secret-like key name found in MCP configuration.",
      recommendation: "Move secrets out of MCP config files and inject them through scoped environment secret storage."
    });
  }

  return findings;
}

function scanPythonProjectFiles(relativePath, basename, content) {
  const findings = [];

  if (basename === "requirements.txt") {
    const lines = content.split(/\r?\n/);
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index].trim();
      if (!line || line.startsWith("#") || /^-/.test(line)) {
        continue;
      }
      if (!/[=<>~!]=/.test(line)) {
        findings.push({
          id: "python.unpinned_requirement",
          severity: "low",
          title: "Unpinned Python dependency",
          file: relativePath,
          line: index + 1,
          evidence: line,
          recommendation: "Pin dependency versions for reproducible agent and CI runs."
        });
      }
    }
  }

  if (basename === "pyproject.toml" && !/requires-python\s*=/.test(content)) {
    findings.push({
      id: "python.missing_requires_python",
      severity: "info",
      title: "pyproject.toml does not declare requires-python",
      file: relativePath,
      line: null,
      evidence: "requires-python was not found.",
      recommendation: "Declare requires-python so agents select the right interpreter and dependency resolver behavior."
    });
  }

  return findings;
}

function scanDangerousCommandLines(relativePath, content, idPrefix) {
  const findings = [];
  const lines = content.split(/\r?\n/);

  for (let index = 0; index < lines.length; index += 1) {
    const commandFindings = classifyDangerousCommand(lines[index]);
    for (const commandFinding of commandFindings) {
      findings.push({
        id: `${idPrefix}.${commandFinding.id}`,
        severity: commandFinding.severity,
        title: "Risky command detected",
        file: relativePath,
        line: index + 1,
        evidence: redact(lines[index].trim()),
        recommendation: commandFinding.recommendation
      });
    }
  }

  return findings;
}

function scanGitHubActionRunCommand(relativePath, command, line) {
  return classifyDangerousCommand(command).map((commandFinding) => ({
    id: `github_actions.run.${commandFinding.id}`,
    severity: commandFinding.severity,
    title: "Risky GitHub Actions run command detected",
    file: relativePath,
    line,
    evidence: redact(String(command).trim()),
    recommendation: commandFinding.recommendation
  }));
}

function classifyDangerousCommand(command) {
  const findings = [];

  if (/\brm\s+-rf\s+(?:\/|\*|~|\$HOME|%USERPROFILE%)/i.test(command)) {
    findings.push({
      id: "recursive_delete",
      severity: "high",
      recommendation: "Guard recursive deletes with explicit path checks and require manual approval before agents run them."
    });
  }

  if (/\b(curl|wget|iwr|Invoke-WebRequest)\b.+\|\s*(sh|bash|zsh|pwsh|powershell|iex|Invoke-Expression)\b/i.test(command)) {
    findings.push({
      id: "remote_code_execution",
      severity: "high",
      recommendation: "Avoid piping remote downloads directly into shells; pin scripts and verify checksums first."
    });
  }

  if (/\bchmod\s+-R\s+777\b/i.test(command)) {
    findings.push({
      id: "world_writable",
      severity: "medium",
      recommendation: "Avoid world-writable permissions and scope chmod to the minimum required mode and path."
    });
  }

  if (/\bsudo\b/i.test(command)) {
    findings.push({
      id: "sudo",
      severity: "medium",
      recommendation: "Require manual approval before agents run commands with elevated privileges."
    });
  }

  return findings;
}

function scanGenericSecretAssignments(relativePath, lines) {
  const findings = [];
  const pattern = /^\s*([A-Z0-9_-]*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|PRIVATE[_-]?KEY)[A-Z0-9_-]*)\s*[:=]\s*["']?([^"'\s#]{8,})/i;

  for (let index = 0; index < lines.length; index += 1) {
    const match = lines[index].match(pattern);
    if (!match) {
      continue;
    }

    if (isPlaceholderSecret(match[2])) {
      continue;
    }

    findings.push({
      id: "secret.generic_assignment",
      severity: "high",
      title: "Secret-like assignment is present",
      file: relativePath,
      line: index + 1,
      evidence: `${match[1]}=[redacted]`,
      recommendation: "Move secret values out of repository files, rotate exposed credentials, and keep them outside agent-readable paths."
    });
  }

  return findings;
}

function isSensitiveFileName(basename) {
  return SENSITIVE_FILE_PATTERNS.some((pattern) => pattern.test(basename));
}

function isPlaceholderSecret(value) {
  return /^(example|changeme|change_me|replace_me|placeholder|dummy|test|todo|xxx+|your_|<)/i.test(String(value));
}

function getIndent(line) {
  return line.match(/^\s*/)?.[0].length || 0;
}

function findLine(content, needle) {
  const lines = content.split(/\r?\n/);
  const index = lines.findIndex((line) => line.includes(needle));
  return index === -1 ? null : index + 1;
}

function redact(value) {
  return String(value)
    .replace(/\bgh[pousr]_[A-Za-z0-9_]{8,}\b/g, (match) => `${match.slice(0, 8)}...[redacted]`)
    .replace(/\bsk-ant-[A-Za-z0-9_-]{8,}\b/g, "sk-ant-...[redacted]")
    .replace(/\bsk-[A-Za-z0-9_-]{8,}\b/g, "sk-...[redacted]")
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, "AKIA...[redacted]");
}

function collectJsonStrings(value, collected = []) {
  if (typeof value === "string") {
    collected.push(value);
    return collected;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      collectJsonStrings(item, collected);
    }
    return collected;
  }

  if (value && typeof value === "object") {
    for (const item of Object.values(value)) {
      collectJsonStrings(item, collected);
    }
  }

  return collected;
}

function isBroadFilesystemPath(value) {
  const normalized = String(value).trim();

  if (/^[A-Za-z]:[\\/]?$/.test(normalized)) {
    return true;
  }

  if (/^[A-Za-z]:[\\/]Users[\\/][^\\/]+[\\/]?$/.test(normalized)) {
    return true;
  }

  if (normalized === "/" || normalized === "~" || normalized === "~/" || normalized === "~\\") {
    return true;
  }

  if (/^\/(?:Users|home)\/[^/]+\/?$/.test(normalized)) {
    return true;
  }

  if (/^\/(?:root|mnt|var|etc)(?:\/?$)/.test(normalized)) {
    return true;
  }

  return false;
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
