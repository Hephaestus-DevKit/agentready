import { classifyDangerousCommand } from "./shell.js";
import { createLineFinder, redact } from "./utils.js";

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
  const findLineIn = createLineFinder(content);
  // Search for script names from the "scripts" block onward, so a dependency
  // with the same name earlier in the file does not steal the line number.
  const scriptsLine = findLineIn('"scripts"') ?? 1;
  // Guard: scripts must be a plain object (not array, string, etc.)
  const scripts =
    parsed.scripts && typeof parsed.scripts === "object" && !Array.isArray(parsed.scripts)
      ? parsed.scripts
      : {};
  for (const [name, command] of Object.entries(scripts)) {
    const commandFindings = classifyDangerousCommand(String(command));
    for (const commandFinding of commandFindings) {
      findings.push({
        id: `package.script.${commandFinding.id}`,
        severity: commandFinding.severity,
        title: `Risky npm script: ${name}`,
        file: relativePath,
        line: findLineIn(`"${name}"`, scriptsLine),
        evidence: `${name}: ${redact(String(command))}`,
        recommendation: commandFinding.recommendation
      });
    }
  }

  for (const lifecycle of ["preinstall", "install", "postinstall", "prepare"]) {
    if (scripts[lifecycle]) {
      findings.push({
        id: "package.lifecycle_script",
        severity: "medium",
        title: `Package lifecycle script detected: ${lifecycle}`,
        file: relativePath,
        line: findLineIn(`"${lifecycle}"`, scriptsLine),
        evidence: `${lifecycle}: ${redact(String(scripts[lifecycle]))}`,
        recommendation: "Review lifecycle scripts before allowing agents or CI to install dependencies automatically."
      });
    }
  }

  return findings;
}
