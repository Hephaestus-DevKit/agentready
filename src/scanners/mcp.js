import { createLineFinder, looksLikePlaceholderValue, redact } from "./utils.js";

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
  const findLineIn = createLineFinder(content);
  const serialized = JSON.stringify(parsed, null, 2);
  const stringValues = collectJsonStrings(parsed);
  const entries = collectJsonEntries(parsed);

  if (/\b(cmd|powershell|pwsh|bash|sh)\b/i.test(serialized)) {
    findings.push({
      id: "mcp.shell_tool",
      severity: "medium",
      title: "MCP configuration can launch a shell",
      file: relativePath,
      line: findLineIn("command"),
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

  if (hasInlineSecretValue(parsed)) {
    findings.push({
      id: "mcp.inline_secret",
      severity: "high",
      title: "MCP configuration appears to contain inline secret values",
      file: relativePath,
      line: null,
      evidence: "Secret-like inline value found in MCP configuration.",
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

function hasInlineSecretValue(value) {
  if (Array.isArray(value)) {
    return value.some((item) => hasInlineSecretValue(item));
  }

  if (!value || typeof value !== "object") {
    return false;
  }

  return Object.entries(value).some(([key, item]) => {
    if (isSecretLikeKey(key) && isInlineSecretString(item)) {
      return true;
    }
    return hasInlineSecretValue(item);
  });
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
  return /\bBearer\s+(?:\$\{|%[A-Z_][A-Z0-9_]*%|[A-Za-z0-9._~+/=-]{8,})/i.test(String(value));
}

function normalizeKey(key) {
  return String(key).replace(/[-_\s]/g, "").toLowerCase();
}

function isSecretLikeKey(key) {
  const normalized = normalizeKey(key);
  if (normalized === "tokenurl" || normalized === "authorizationurl") {
    return false;
  }
  // Apply regex to normalized key so spaces/separators don't cause misses
  return /(api_?key|apikey|token|secret|password|authorization)/i.test(normalized);
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
