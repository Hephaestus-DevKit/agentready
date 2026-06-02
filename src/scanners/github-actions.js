import { classifyDangerousCommand } from "./shell.js";
import { redact } from "./utils.js";

export function scanGitHubActions(relativePath, content) {
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

function getIndent(line) {
  return line.match(/^\s*/)?.[0].length || 0;
}
