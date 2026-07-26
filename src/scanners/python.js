import { splitLines } from "./utils.js";

export function scanPythonProjectFiles(relativePath, basename, content) {
  const findings = [];

  if (basename === "requirements.txt") {
    const lines = splitLines(content);
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index].trim();
      if (!line || line.startsWith("#") || /^-/.test(line)) {
        continue;
      }
      // Skip URL-based requirements (e.g. https://... or package @ https://...)
      if (/https?:\/\//.test(line) || /\s+@\s+/.test(line)) {
        continue;
      }
      // Any version constraint counts, including bare ranges (`numpy>1.2`):
      // the rule targets requirements with no constraint at all.
      if (!/[=<>~!]=|[<>]/.test(line)) {
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

  if (basename === "pyproject.toml" && !hasRequiresPython(content)) {
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

function hasRequiresPython(content) {
  let inPoetryDependencies = false;
  for (const line of splitLines(content)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }
    if (/^requires-python\s*=/.test(trimmed)) {
      return true;
    }
    if (/^\[/.test(trimmed)) {
      inPoetryDependencies = /^\[tool\.poetry\.dependencies\]/.test(trimmed);
      continue;
    }
    // Poetry projects declare the interpreter as a dependency instead.
    if (inPoetryDependencies && /^python\s*=/.test(trimmed)) {
      return true;
    }
  }
  return false;
}
