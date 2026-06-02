import { findLine } from "./utils.js";

export const MCP_CONFIG_NAMES = new Set([
  "claude_desktop_config.json",
  "mcp.json",
  "mcp-config.json"
]);

export function scanMcpConfig(relativePath, basename, content) {
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
