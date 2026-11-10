import path from "node:path";

export function formatCommandPath(root) {
  const relative = path.relative(process.cwd(), root);
  const normalized = relative.replaceAll("\\", "/");
  let value = normalized || ".";

  if (value !== "." && !path.isAbsolute(relative) && !value.startsWith(".")) {
    value = `./${value}`;
  }

  // Quote anything outside a conservative safe set: the value is printed as a
  // copy-paste command, so `&`, `;`, `(`, `|`, `>`, `*`, `!`, `#`, or a
  // leading `~` in a directory name must not be interpreted by the shell.
  if (/[^A-Za-z0-9_@+=:,./-]/.test(value) || (process.platform !== "win32" && value.startsWith("~"))) {
    return quoteShellPath(value);
  }

  return value;
}

function quoteShellPath(value) {
  if (process.platform === "win32") {
    // Double quotes work in both cmd.exe and PowerShell; escape embedded double quotes
    return `"${value.replaceAll('"', '""')}"`;
  }

  return `'${value.replaceAll("'", "'\\''")}'`;
}
