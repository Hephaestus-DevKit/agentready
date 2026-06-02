export function scanPythonProjectFiles(relativePath, basename, content) {
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
