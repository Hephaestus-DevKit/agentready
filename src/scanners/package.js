import { classifyDangerousCommand } from "./shell.js";
import { findLine, redact } from "./utils.js";

export function scanPackageJson(relativePath, basename, content) {
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
