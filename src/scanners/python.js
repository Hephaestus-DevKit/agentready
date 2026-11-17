import { redact, splitLines } from "./utils.js";

function isRequirementsFile(relativePath, basename) {
  if (/^requirements(?:[-_.].*)?\.txt$/i.test(basename)) {
    return true;
  }
  const normalized = String(relativePath).replaceAll("\\", "/");
  return /(?:^|\/)requirements\/[^/]+\.txt$/i.test(normalized);
}

export function scanPythonProjectFiles(relativePath, basename, content) {
  const findings = [];

  if (isRequirementsFile(relativePath, basename)) {
    const lines = splitLines(content);
    for (let index = 0; index < lines.length; index += 1) {
      const rawLine = lines[index].trim();
      if (!rawLine || rawLine.startsWith("#")) {
        continue;
      }

      const startLine = index + 1;
      const parts = [rawLine.replace(/\\\s*$/, "").trim()];
      while (/\\\s*$/.test(lines[index]) && index + 1 < lines.length) {
        index += 1;
        const nextLine = lines[index].trim();
        if (!nextLine.startsWith("#")) {
          parts.push(nextLine.replace(/\\\s*$/, "").trim());
        }
      }

      const joined = parts.filter(Boolean).join(" ");
      // Strip inline comments (`pkg # >= 1.0` must not count as pinned).
      const spec = joined.replace(/(?:^|\s)#.*$/, "").trim();
      if (!spec || /^-/.test(spec)) {
        continue;
      }
      // Skip URL-based, VCS, and local-path requirements.
      if (
        /(?:https?|file):\/\//i.test(spec) ||
        /\s+@\s+/.test(spec) ||
        /^(?:git|hg|svn|bzr)\+/i.test(spec) ||
        /^(?:\.{1,2}(?:[\\/]|$)|\/|[A-Za-z]:[\\/])/.test(spec)
      ) {
        continue;
      }
      // Strip PEP 508 environment markers (`tomli; python_version < "3.11"`)
      // and pip `--hash=...` suffixes before checking version constraints.
      const requirementCore = spec.split(";")[0].replace(/\s+--[A-Za-z0-9_-]+=\S+/g, "").trim();
      if (!/[=<>~!]=|[<>]/.test(requirementCore)) {
        findings.push({
          id: "python.unpinned_requirement",
          severity: "low",
          title: "Unpinned Python dependency",
          file: relativePath,
          line: startLine,
          evidence: redact(spec),
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
