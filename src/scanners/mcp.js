import { createLineFinder, looksLikePlaceholderValue, redact } from "./utils.js";

export const MCP_CONFIG_NAMES = new Set([
  "claude_desktop_config.json",
  ".mcp.json",
  "mcp.json",
  "mcp-config.json"
]);

export function isMcpConfigPath(relativePath, basename) {
  const lowerBasename = basename.toLowerCase();
  if (MCP_CONFIG_NAMES.has(lowerBasename)) {
    return true;
  }
  if (/^\.?mcp[-_.]/.test(lowerBasename) && lowerBasename.endsWith(".json")) {
    return true;
  }
  // Match mcp/, .mcp/, mcp-servers/ directory segments anywhere in the path,
  // but not names that merely start with "mcp" (e.g. mcparse/).
  const directorySegments = relativePath.split("/").slice(0, -1);
  return directorySegments.some((segment) => /^\.?mcp(?:$|[-_])/i.test(segment));
}

export function scanMcpConfig(relativePath, basename, content) {
  if (!isMcpConfigPath(relativePath, basename)) {
    return [];
  }

  let parsed = null;
  try {
    parsed = JSON.parse(content);
  } catch {
    return [];
  }

  const findings = [];
  const findLineIn = createLineFinder(content);
  const stringValues = collectJsonStrings(parsed);
  const entries = collectJsonEntries(parsed);

  const shellCommand = findShellCommand(entries);
  if (shellCommand) {
    findings.push({
      id: "mcp.shell_tool",
      severity: "medium",
      title: "MCP configuration can launch a shell",
      file: relativePath,
      line: findLineIn(shellCommand),
      evidence: `Shell command "${shellCommand}" found in MCP configuration.`,
      recommendation: "Restrict shell-capable MCP servers and require human approval for destructive commands."
    });
  }

  const broadPath = stringValues.find(isBroadFilesystemPath);
  if (broadPath) {
    findings.push({
      id: "mcp.broad_filesystem",
      severity: "medium",
      title: "MCP configuration may expose broad filesystem access",
      file: relativePath,
      line: findLineIn(broadPath),
      evidence: `Broad filesystem path "${broadPath.trim()}" found in MCP configuration.`,
      recommendation: "Limit filesystem MCP servers to the smallest project-specific directories."
    });
  }

  const inlineSecret = findInlineSecretEntry(entries);
  if (inlineSecret) {
    findings.push({
      id: "mcp.inline_secret",
      severity: "high",
      title: "MCP configuration appears to contain inline secret values",
      file: relativePath,
      line: findLineIn(inlineSecret.key),
      evidence: `Secret-like inline value assigned to "${inlineSecret.key}" in MCP configuration.`,
      recommendation: "Move secrets out of MCP config files and inject them through scoped environment secret storage."
    });
  }

  const authorizationRisk = findAuthorizationPassthrough(entries);
  if (authorizationRisk) {
    findings.push({
      id: "mcp.authorization_passthrough",
      severity: "medium",
      title: "MCP configuration forwards authorization headers",
      file: relativePath,
      line: findLineIn(authorizationRisk.needle),
      evidence: "Authorization header or bearer token forwarding found in MCP configuration.",
      recommendation: "Pass credentials only to reviewed MCP servers and prefer scoped, short-lived tokens."
    });
  }

  const oauthRisk = findOauthClientConfig(entries);
  if (oauthRisk) {
    findings.push({
      id: "mcp.oauth_client_config",
      severity: "medium",
      title: "MCP configuration includes OAuth client settings",
      file: relativePath,
      line: findLineIn(oauthRisk.needle),
      evidence: "OAuth client configuration fields found in MCP configuration.",
      recommendation: "Review OAuth scopes, redirect URIs, token storage, and consent flow before exposing this server to agents."
    });
  }

  const urlRisks = classifyUrlRisks(stringValues);
  for (const risk of urlRisks) {
    findings.push({
      id: risk.id,
      severity: risk.severity,
      title: risk.title,
      file: relativePath,
      line: findLineIn(risk.host),
      evidence: risk.evidence,
      recommendation: risk.recommendation
    });
  }

  return findings;
}

const MAX_JSON_DEPTH = 50;

function collectJsonStrings(value, collected = [], depth = 0) {
  if (depth > MAX_JSON_DEPTH) {
    return collected;
  }

  if (typeof value === "string") {
    collected.push(value);
    return collected;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      collectJsonStrings(item, collected, depth + 1);
    }
    return collected;
  }

  if (value && typeof value === "object") {
    for (const item of Object.values(value)) {
      collectJsonStrings(item, collected, depth + 1);
    }
  }

  return collected;
}

function collectJsonEntries(value, path = [], collected = [], depth = 0) {
  if (depth > MAX_JSON_DEPTH) {
    return collected;
  }

  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      collectJsonEntries(value[index], [...path, String(index)], collected, depth + 1);
    }
    return collected;
  }

  if (!value || typeof value !== "object") {
    return collected;
  }

  for (const [key, item] of Object.entries(value)) {
    const nextPath = [...path, key];
    collected.push({ key, value: item, path: nextPath });
    collectJsonEntries(item, nextPath, collected, depth + 1);
  }

  return collected;
}

const SHELL_COMMAND_NAMES = new Set([
  "cmd", "cmd.exe",
  "powershell", "powershell.exe",
  "pwsh", "pwsh.exe",
  "bash", "bash.exe",
  "sh", "zsh", "dash", "ksh"
]);

function findShellCommand(entries) {
  for (const entry of entries) {
    const key = normalizeKey(entry.key);
    if (key === "command" && typeof entry.value === "string" && isShellExecutable(entry.value)) {
      return entry.value;
    }
    if (key === "args" && Array.isArray(entry.value)) {
      const shellArg = entry.value.find((item) => typeof item === "string" && isShellExecutable(item));
      if (shellArg) {
        return shellArg;
      }
    }
  }
  return null;
}

function isShellExecutable(value) {
  const executable = value.trim().toLowerCase().split(/[\\/]/).pop();
  return SHELL_COMMAND_NAMES.has(executable);
}

function findInlineSecretEntry(entries) {
  return entries.find((entry) => isSecretLikeKey(entry.key) && isInlineSecretString(entry.value)) || null;
}

function findAuthorizationPassthrough(entries) {
  for (const entry of entries) {
    if (isAuthorizationHeaderKey(entry.key)) {
      return { needle: entry.key };
    }

    if (typeof entry.value === "string" && isBearerValue(entry.value)) {
      return { needle: entry.value.includes("Bearer") ? "Bearer" : entry.key };
    }
  }

  return null;
}

function findOauthClientConfig(entries) {
  const matched = new Set();
  let firstNeedle = null;

  for (const entry of entries) {
    const key = normalizeKey(entry.key);
    if (key === "oauth") {
      return { needle: entry.key };
    }

    if (OAUTH_CLIENT_KEYS.has(key)) {
      matched.add(key);
      firstNeedle ||= entry.key;
    }
  }

  return matched.size >= 2 ? { needle: firstNeedle || "oauth" } : null;
}

const OAUTH_CLIENT_KEYS = new Set([
  "authorizationurl",
  "tokenurl",
  "clientid",
  "clientsecret",
  "redirecturi",
  "scope",
  "scopes"
]);

function isAuthorizationHeaderKey(key) {
  const normalized = normalizeKey(key);
  return normalized === "authorization" || normalized === "authorizationheader";
}

function isBearerValue(value) {
  return /\bBearer\s+(?:\$\{?[A-Za-z_]|%[A-Z_][A-Z0-9_]*%|[A-Za-z0-9._~+/=-]{8,})/i.test(String(value));
}

function normalizeKey(key) {
  return String(key).replace(/[-_\s]/g, "").toLowerCase();
}

const SECRET_KEY_SEGMENTS = new Set([
  "token", "secret", "password", "passwd", "authorization", "credential", "credentials", "apikey"
]);

function isSecretLikeKey(key) {
  const normalized = normalizeKey(key);
  if (normalized === "tokenurl" || normalized === "authorizationurl") {
    return false;
  }
  // Match whole word segments only (split on separators and camelCase),
  // so keys like "tokenizer" don't flag on the embedded "token".
  const segments = String(key)
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(/[-_\s.]+/)
    .filter(Boolean);
  if (segments.some((segment) => SECRET_KEY_SEGMENTS.has(segment))) {
    return true;
  }
  return segments.some((segment, index) => segment === "api" && segments[index + 1] === "key");
}

function isInlineSecretString(value) {
  if (typeof value !== "string") {
    return false;
  }

  const trimmed = value.trim();
  if (trimmed.length < 8) {
    return false;
  }

  if (looksLikePlaceholderValue(trimmed)) {
    return false;
  }

  if (/^(\$\{?(?:env:)?[A-Z_][A-Z0-9_]*\}?|%[A-Z_][A-Z0-9_]*%|process\.env\.|env\.|secrets\.|vars\.)/i.test(trimmed)) {
    return false;
  }

  if (/^Bearer\s+(\$\{?(?:env:)?[A-Z_][A-Z0-9_]*\}?|%[A-Z_][A-Z0-9_]*%|process\.env\.|env\.|secrets\.|vars\.)/i.test(trimmed)) {
    return false;
  }

  return true;
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

function classifyUrlRisks(values) {
  const seen = new Set();
  const risks = [];

  for (const value of values) {
    for (const url of extractUrls(value)) {
      const parsed = parseUrl(url);
      if (!parsed) {
        continue;
      }

      const host = parsed.hostname.toLowerCase();
      if (isMetadataHost(host)) {
        pushRisk(risks, seen, {
          id: "mcp.metadata_endpoint",
          severity: "high",
          title: "MCP configuration references a cloud metadata endpoint",
          host,
          evidence: `${parsed.protocol}//${redact(host)}`,
          recommendation: "Remove metadata endpoint access from MCP configuration and review whether credentials may be exposed."
        });
        continue;
      }

      if (isPrivateNetworkHost(host)) {
        pushRisk(risks, seen, {
          id: "mcp.private_network_url",
          severity: "medium",
          title: "MCP configuration references a private network URL",
          host,
          evidence: `${parsed.protocol}//${redact(host)}`,
          recommendation: "Review private network MCP endpoints and expose only services intended for agent use."
        });
        continue;
      }

      pushRisk(risks, seen, {
        id: "mcp.remote_url",
        severity: "medium",
        title: "MCP configuration references a remote server URL",
        host,
        evidence: `${parsed.protocol}//${redact(host)}`,
        recommendation: "Review remote MCP servers before exposing agent tools or repository context."
      });
    }
  }

  return risks;
}

function pushRisk(risks, seen, risk) {
  const key = `${risk.id}:${risk.host}`;
  if (seen.has(key)) {
    return;
  }
  seen.add(key);
  risks.push(risk);
}

function extractUrls(value) {
  return String(value).match(/\b(?:https?|wss?):\/\/[^\s"'<>),]+/gi) || [];
}

function parseUrl(value) {
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

function isMetadataHost(host) {
  return [
    "169.254.169.254",
    "169.254.170.2",
    "metadata.google.internal"
  ].includes(host);
}

function isPrivateNetworkHost(host) {
  const normalizedHost = host.replace(/^\[|\]$/g, "");
  if (normalizedHost === "localhost" || normalizedHost === "127.0.0.1" || normalizedHost === "::1") {
    return true;
  }

  if (/^127\./.test(normalizedHost) || /^10\./.test(normalizedHost) || /^192\.168\./.test(normalizedHost)) {
    return true;
  }

  const match = normalizedHost.match(/^172\.(\d+)\./);
  if (match) {
    const secondOctet = Number(match[1]);
    return secondOctet >= 16 && secondOctet <= 31;
  }

  return normalizedHost.endsWith(".local");
}
