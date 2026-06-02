import { redact, splitLines } from "./utils.js";

export function scanDangerousShell(relativePath, content) {
  if (!/\.(?:sh|ps1|bash|zsh|cmd|bat)$/i.test(relativePath)) {
    return [];
  }

  return scanDangerousCommandLines(relativePath, content, "script.dangerous_command");
}

export function scanDangerousCommandLines(relativePath, content, idPrefix) {
  const findings = [];
  const lines = splitLines(content);

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

export function classifyDangerousCommand(command) {
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
