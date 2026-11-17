import {
  createLineFinder,
  isEnvironmentReference,
  looksLikePlaceholderValue,
  redact,
  splitLines
} from "./utils.js";

export const MCP_CONFIG_NAMES = new Set([
  "claude_desktop_config.json",
  "claude_desktop_config.jsonc",
  ".mcp.json",
  ".mcp.jsonc",
  "mcp.json",
  "mcp.jsonc",
  "mcp-config.json",
  "mcp-config.jsonc"
]);

export function isMcpConfigPath(relativePath, basename) {
  const lowerBasename = basename.toLowerCase();
  if (MCP_CONFIG_NAMES.has(lowerBasename)) {
    return true;
  }
  if (/^\.?mcp[-_.]/.test(lowerBasename) && /\.(?:json|jsonc)$/.test(lowerBasename)) {
    return true;
  }
  // Match mcp/, .mcp/, mcp-servers/ directory segments anywhere in the path,
  // but not names that merely start with "mcp" (e.g. mcparse/).
  if (!/\.(?:json|jsonc)$/.test(lowerBasename)) {
    return false;
  }
  const directorySegments = String(relativePath).replaceAll("\\", "/").split("/").slice(0, -1);
  return directorySegments.some((segment) => /^\.?mcp(?:$|[-_])/i.test(segment));
}

export function scanMcpConfig(relativePath, basename, content) {
  if (!isMcpConfigPath(relativePath, basename)) {
    return [];
  }

  const parsed = parseJsonOrJsonc(content);
  if (!parsed || typeof parsed !== "object") {
    return [];
  }

  const findings = [];
  const findLineIn = createLineFinder(content);
  const lines = splitLines(content);
  const findCaseInsensitiveLine = (needle) => {
    const lower = String(needle).toLowerCase();
    for (let index = 0; index < lines.length; index += 1) {
      if (lines[index].toLowerCase().includes(lower)) {
        return index + 1;
      }
    }
    return null;
  };
  const findJsonTokenLine = (rawValue) =>
    findLineIn(JSON.stringify(rawValue)) ?? findLineIn(rawValue);

  const entries = collectJsonEntries(parsed);
  const stringValues = collectNonSchemaStrings(parsed);

  for (const shellCommand of findShellCommands(entries)) {
    findings.push({
      id: "mcp.shell_tool",
      severity: "medium",
      title: "MCP configuration can launch a shell",
      file: relativePath,
      line: findJsonTokenLine(shellCommand),
      evidence: `Shell command "${redact(shellCommand)}" found in MCP configuration.`,
      recommendation: "Restrict shell-capable MCP servers and require human approval for destructive commands."
    });
  }

  for (const broadPath of findBroadFilesystemPaths(stringValues)) {
    findings.push({
      id: "mcp.broad_filesystem",
      severity: "medium",
      title: "MCP configuration may expose broad filesystem access",
      file: relativePath,
      line: findJsonTokenLine(broadPath),
      evidence: `Broad filesystem path "${broadPath.trim()}" found in MCP configuration.`,
      recommendation: "Limit filesystem MCP servers to the smallest project-specific directories."
    });
  }

  for (const inlineSecret of findInlineSecretEntries(entries)) {
    findings.push({
      id: "mcp.inline_secret",
      severity: "high",
      title: "MCP configuration appears to contain inline secret values",
      file: relativePath,
      line: findJsonTokenLine(inlineSecret.key),
      evidence: `Secret-like inline value assigned to "${inlineSecret.key}" in MCP configuration.`,
      recommendation: "Move secrets out of MCP config files and inject them through scoped environment secret storage."
    });
  }

  for (const authorizationRisk of findAuthorizationPassthroughs(entries)) {
    findings.push({
      id: "mcp.authorization_passthrough",
      severity: "medium",
      title: "MCP configuration forwards authorization headers",
      file: relativePath,
      line: findJsonTokenLine(authorizationRisk.needle) ?? findCaseInsensitiveLine(authorizationRisk.needle),
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
      line: findJsonTokenLine(oauthRisk.needle),
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
      line: findLineIn(risk.rawHost) ?? findCaseInsensitiveLine(risk.rawHost) ?? findLineIn(risk.host),
      evidence: risk.evidence,
      recommendation: risk.recommendation
    });
  }

  return findings;
}

function parseJsonOrJsonc(content) {
  const withoutBom = String(content).replace(/^\uFEFF/, "");
  try {
    return JSON.parse(withoutBom);
  } catch {
    try {
      return JSON.parse(stripJsonc(withoutBom));
    } catch {
      return null;
    }
  }
}

// Strip // and /* */ comments and trailing commas outside JSON strings while
// preserving line breaks so line numbers continue to match the original file.
function stripJsonc(source) {
  let out = "";
  let inString = false;
  for (let i = 0; i < source.length; i += 1) {
    const ch = source[i];
    const next = source[i + 1];
    if (inString) {
      out += ch;
      if (ch === "\\" && i + 1 < source.length) {
        out += next;
        i += 1;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }
    if (ch === '"') {
      inString = true;
      out += ch;
      continue;
    }
    if (ch === "/" && next === "/") {
      i += 2;
      while (i < source.length && source[i] !== "\n" && source[i] !== "\r") {
        i += 1;
      }
      i -= 1;
      continue;
    }
    if (ch === "/" && next === "*") {
      i += 2;
      while (i < source.length && !(source[i] === "*" && source[i + 1] === "/")) {
        if (source[i] === "\n" || source[i] === "\r") {
          out += source[i];
        }
        i += 1;
      }
      i += 1;
      continue;
    }
    out += ch;
  }

  // Remove trailing commas outside strings by scanning the comment-free JSON.
  let cleaned = "";
  inString = false;
  for (let i = 0; i < out.length; i += 1) {
    const ch = out[i];
    if (inString) {
      cleaned += ch;
      if (ch === "\\" && i + 1 < out.length) {
        cleaned += out[i + 1];
        i += 1;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }
    if (ch === '"') {
      inString = true;
      cleaned += ch;
      continue;
    }
    if (ch === ",") {
      let lookahead = i + 1;
      while (lookahead < out.length && /\s/.test(out[lookahead])) {
        lookahead += 1;
      }
      if (out[lookahead] === "}" || out[lookahead] === "]") {
        continue;
      }
    }
    cleaned += ch;
  }
  return cleaned;
}

const MAX_JSON_DEPTH = 50;

function collectNonSchemaStrings(value, collected = [], depth = 0) {
  if (depth > MAX_JSON_DEPTH) {
    return collected;
  }

  if (typeof value === "string") {
    collected.push(value);
    return collected;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      collectNonSchemaStrings(item, collected, depth + 1);
    }
    return collected;
  }

  if (value && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      if (key === "$schema") {
        continue;
      }
      collectNonSchemaStrings(item, collected, depth + 1);
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

function findShellCommands(entries) {
  const seen = new Set();
  const commands = [];
  for (const entry of entries) {
    const key = normalizeKey(entry.key);
    if (key === "command" && typeof entry.value === "string" && isShellExecutable(entry.value)) {
      if (!seen.has(entry.value)) {
        seen.add(entry.value);
        commands.push(entry.value);
      }
    }
    if (key === "args" && Array.isArray(entry.value)) {
      for (const item of entry.value) {
        if (typeof item === "string" && isShellExecutable(item) && !seen.has(item)) {
          seen.add(item);
          commands.push(item);
        }
      }
    }
  }
  return commands;
}

function isShellExecutable(value) {
  const trimmed = value.trim();
  const fullTail = trimmed.toLowerCase().split(/[\\/]/).pop();
  if (SHELL_COMMAND_NAMES.has(fullTail)) {
    return true;
  }
  const firstToken = trimmed.split(/\s+/)[0] || "";
  const tokenTail = firstToken.replace(/^['"]|['"]$/g, "").toLowerCase().split(/[\\/]/).pop();
  return SHELL_COMMAND_NAMES.has(tokenTail);
}

function findBroadFilesystemPaths(values) {
  const seen = new Set();
  const paths = [];
  for (const value of values) {
    if (isBroadFilesystemPath(value) && !seen.has(value)) {
      seen.add(value);
      paths.push(value);
    }
  }
  return paths;
}

function findInlineSecretEntries(entries) {
  return entries.filter((entry) => isSecretLikeKey(entry.key) && isInlineSecretString(entry.value));
}

function findAuthorizationPassthroughs(entries) {
  const risks = [];
  for (const entry of entries) {
    if (isAuthorizationHeaderKey(entry.key)) {
      risks.push({ needle: entry.key });
      continue;
    }

    if (typeof entry.value === "string" && isBearerValue(entry.value)) {
      risks.push({ needle: entry.value.includes("Bearer") ? "Bearer" : entry.key });
    }
  }

  return risks;
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

  if (isEnvironmentReference(trimmed)) {
    return false;
  }

  const bearerMatch = trimmed.match(/^Bearer\s+(.+)$/i);
  if (bearerMatch) {
    const bearerToken = bearerMatch[1].trim();
    if (looksLikePlaceholderValue(bearerToken) || isEnvironmentReference(bearerToken)) {
      return false;
    }
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
      const rawHost = extractRawHost(url) || host;
      if (isMetadataHost(host)) {
        pushRisk(risks, seen, {
          id: "mcp.metadata_endpoint",
          severity: "high",
          title: "MCP configuration references a cloud metadata endpoint",
          host,
          rawHost,
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
          rawHost,
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
        rawHost,
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

function extractRawHost(urlString) {
  const match = String(urlString).match(/^[A-Za-z][A-Za-z0-9+.-]*:\/\/(?:\[([^\]]+)\]|([^/:?#]+))/);
  return match ? match[1] || match[2] : null;
}

function isMetadataHost(host) {
  const normalized = host.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
  return [
    "169.254.169.254",
    "169.254.170.2",
    "100.100.100.200",
    "metadata.google.internal",
    "fd00:ec2::254",
    "::ffff:a9fe:a9fe",
    "::ffff:a9fe:aa02",
    "::ffff:169.254.169.254",
    "::ffff:169.254.170.2"
  ].includes(normalized);
}

function isPrivateNetworkHost(host) {
  const normalizedHost = host.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
  if (
    normalizedHost === "localhost" ||
    normalizedHost === "0.0.0.0" ||
    normalizedHost === "127.0.0.1" ||
    normalizedHost === "::1" ||
    normalizedHost === "::"
  ) {
    return true;
  }

  // IPv4-mapped IPv6 addresses (`::ffff:7f00:1`, `::ffff:a00:1`, `::ffff:c0a8:101`, `::ffff:ac10:1`..`::ffff:ac1f:1`)
  if (/^::ffff:(?:7f[0-9a-f]{0,2}:|a[0-9a-f]{0,2}:|c0a8:|ac1[0-9a-f]:|127\.|10\.|192\.168\.)/i.test(normalizedHost)) {
    return true;
  }

  // IPv6 Unique Local (`fc00::/7`) and Link-Local (`fe80::/10`)
  if (/^(?:f[cd][0-9a-f]{2}:|fe[89ab][0-9a-f]:)/i.test(normalizedHost)) {
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
