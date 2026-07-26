import path from "node:path";
import { redact, splitLines } from "./utils.js";

const SHELL_LIKE_FILE_NAMES = new Set([
  ".bash_profile",
  ".bashrc",
  ".profile",
  ".zprofile",
  ".zshrc",
  "Brewfile",
  "Dockerfile",
  "dockerfile",
  "Justfile",
  "Makefile",
  "makefile",
  "Procfile",
  "Rakefile",
  "Taskfile",
  "Vagrantfile"
]);

export function scanDangerousShell(relativePath, content) {
  const basename = path.basename(relativePath);
  if (!/\.(?:sh|ps1|bash|zsh|cmd|bat)$/i.test(relativePath) && !SHELL_LIKE_FILE_NAMES.has(basename)) {
    return [];
  }

  return scanDangerousCommandLines(relativePath, content, "script.dangerous_command");
}

export function scanDangerousCommandLines(relativePath, content, idPrefix) {
  const findings = [];
  const lines = splitLines(content);

  for (let index = 0; index < lines.length; index += 1) {
    const trimmed = lines[index].trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("::") || /^rem\b/i.test(trimmed)) {
      continue;
    }

    const commandFindings = classifyDangerousCommand(trimmed);
    for (const commandFinding of commandFindings) {
      findings.push({
        id: `${idPrefix}.${commandFinding.id}`,
        severity: commandFinding.severity,
        title: "Risky command detected",
        file: relativePath,
        line: index + 1,
        evidence: redact(trimmed),
        recommendation: commandFinding.recommendation
      });
    }
  }

  return findings;
}

export function classifyDangerousCommand(command) {
  const findings = [];

  // A line that only prints text is not executing anything: install scripts
  // commonly echo instructions like `echo "run: sudo systemctl ..."`. Only
  // skip when no shell separator could chain a real command after the echo.
  if (/^\s*(echo|printf)\b/i.test(command) && !/(\&\&|\|\||;|\||\$\(|`)/.test(command)) {
    return findings;
  }

  // Detect recursive delete: rm -rf, rm -fr, rm -r -f, rm --recursive --force
  // Covers combined flags (-rf, -fr), separated flags (-r -f), and long forms.
  // A scoped temp subdirectory (/tmp/<name>, /var/tmp/<name>) is routine CI
  // cleanup, not a broad delete, so the bare-slash target excludes it;
  // deleting /tmp itself still matches.
  if (
    /\brm\s+(?:-[A-Za-z]*r[A-Za-z]*\s+-[A-Za-z]*f[A-Za-z]*|-[A-Za-z]*f[A-Za-z]*\s+-[A-Za-z]*r[A-Za-z]*|-(?=[A-Za-z]*r)(?=[A-Za-z]*f)[A-Za-z]+|--recursive\s+--force|--force\s+--recursive)/i.test(command) &&
    /\brm\s+.+\s+["']?(?:\/(?!(?:var\/)?tmp\/[^\s"'])|\*|~|\$(?:HOME|\{HOME\})|%USERPROFILE%|[A-Za-z]:[\\/])/i.test(command) ||
    /\brm\s+(?:-[A-Za-z]*r[A-Za-z]*\s+-[A-Za-z]*f[A-Za-z]*|-[A-Za-z]*f[A-Za-z]*\s+-[A-Za-z]*r[A-Za-z]*|-(?=[A-Za-z]*r)(?=[A-Za-z]*f)[A-Za-z]+)\s+["']?(?:\/(?!(?:var\/)?tmp\/[^\s"'])|\*|~|\$(?:HOME|\{HOME\})|%USERPROFILE%)/i.test(command)
  ) {
    findings.push({
      id: "recursive_delete",
      severity: "high",
      recommendation: "Guard recursive deletes with explicit path checks and require manual approval before agents run them."
    });
  }

  // Detect remote download piped to shell (curl/wget | sh/bash) or process substitution bash <(curl ...)
  if (
    /\b(curl|wget|iwr|Invoke-WebRequest)\b.+\|\s*(sh|bash|zsh|pwsh|powershell|iex|Invoke-Expression)\b/i.test(command) ||
    /\b(bash|sh|zsh)\s+<\s*\(\s*(curl|wget)\b/i.test(command)
  ) {
    findings.push({
      id: "remote_code_execution",
      severity: "high",
      recommendation: "Avoid piping remote downloads directly into shells; pin scripts and verify checksums first."
    });
  }

  // Detect world-writable permissions: chmod -R 777, chmod 777 -R, chmod --recursive 777, chmod -R a+rwx
  if (/\bchmod\s+(?:-R\s+(?:777|0777|a\+rwx)|(?:777|0777|a\+rwx)\s+-R|--recursive\s+(?:777|0777|a\+rwx))/i.test(command)) {
    findings.push({
      id: "world_writable",
      severity: "medium",
      recommendation: "Avoid world-writable permissions and scope chmod to the minimum required mode and path."
    });
  }

  // Detect sudo usage (requires elevated privileges)
  if (/\bsudo\b/i.test(command)) {
    findings.push({
      id: "sudo",
      severity: "medium",
      recommendation: "Require manual approval before agents run commands with elevated privileges."
    });
  }

  return findings;
}
