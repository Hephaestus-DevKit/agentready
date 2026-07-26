import { SECRET_TOKEN_RULES, isTestPath, looksLikePlaceholderValue, redact, splitLines } from "./utils.js";

const TEST_CONTEXT_WHY =
  "Secret-shaped value found in a test file or fixture; these are usually deliberate fakes, but verify no real credential was committed.";

const SENSITIVE_FILE_PATTERNS = [
  /^\.env(?:[.-]|rc$|$)/i,
  /^\.npmrc$/i,
  /^\.pypirc$/i,
  /^\.netrc$/i,
  /(?:^|[._-])secret(?:s)?(?:[._-]|$).*\.(?:json|ya?ml|toml|ini|txt|env)$/i,
  /(?:^|[._-])credential(?:s)?(?:[._-]|$).*\.(?:json|ya?ml|toml|ini|txt|env)$/i,
  /\.(?:pem|key|p12|pfx)$/i
];

// Detection metadata (including redaction) lives in SECRET_TOKEN_RULES in
// ./utils.js so the scanner and redact() can never drift apart.

export function scanSensitiveFileName(relativePath, basename) {
  if (!isSensitivePath(relativePath, basename) || isTemplateSensitiveFileName(basename)) {
    return [];
  }

  // Same reasoning as secret content: sensitive-looking names under test or
  // fixture paths are usually deliberate test data, so report at low severity.
  const inTestContext = isTestPath(relativePath);

  return [
    {
      id: "secret.sensitive_filename",
      severity: inTestContext ? "low" : "medium",
      title: "Sensitive-looking file is agent-readable",
      file: relativePath,
      line: null,
      evidence: relativePath,
      recommendation: "Keep this file out of git and add it to .agentignore unless agents explicitly need it.",
      ...(inTestContext ? { why: TEST_CONTEXT_WHY } : {})
    }
  ];
}

export function scanSecretContent(relativePath, basename, content) {
  const findings = [];
  const lines = splitLines(content);
  // Secret-shaped values in test code are usually deliberate fakes (for
  // example fixtures for a redaction test suite). Keep reporting them so a
  // real committed credential is still visible, but at low severity so they
  // do not fail CI at the default medium threshold.
  const inTestContext = isTestPath(relativePath);

  for (const rule of SECRET_TOKEN_RULES) {
    for (let index = 0; index < lines.length; index += 1) {
      if (!rule.detect.test(lines[index])) {
        continue;
      }

      findings.push({
        id: rule.id,
        severity: inTestContext ? "low" : rule.severity || "high",
        title: rule.title,
        file: relativePath,
        line: index + 1,
        evidence: redact(lines[index]),
        recommendation: rule.recommendation,
        ...(inTestContext ? { why: TEST_CONTEXT_WHY } : {})
      });
      // Do NOT break — report ALL occurrences of each secret pattern in the file
    }
  }

  if (isSensitivePath(relativePath, basename)) {
    findings.push(...scanGenericSecretAssignments(relativePath, basename, lines, inTestContext ? "low" : "high", inTestContext));
  }

  return findings;
}

function isSensitiveFileName(basename) {
  return SENSITIVE_FILE_PATTERNS.some((pattern) => pattern.test(basename));
}

export function isSensitivePath(relativePath, basename) {
  const normalized = String(relativePath).replaceAll("\\", "/");
  return isSensitiveFileName(basename) || /(^|\/)(secrets?|credentials?|private|backups?)(\/|$)/i.test(normalized);
}

function isTemplateSensitiveFileName(basename) {
  return /(?:^|[._-])(example|sample|template|dummy)(?:[._-]|$)/i.test(basename);
}

function scanGenericSecretAssignments(relativePath, basename, lines, severity = "high", inTestContext = false) {
  const findings = [];

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index].trim();
    if (!line || line.startsWith("#")) {
      continue;
    }

    const match = matchSecretAssignment(line, basename);
    if (!match) {
      continue;
    }

    if (isPlaceholderSecret(match[2])) {
      continue;
    }

    findings.push({
      id: "secret.generic_assignment",
      severity,
      title: "Secret-like assignment is present",
      file: relativePath,
      line: index + 1,
      evidence: `${match[1]}=[redacted]`,
      recommendation: "Move secret values out of repository files, rotate exposed credentials, and keep them outside agent-readable paths.",
      ...(inTestContext ? { why: TEST_CONTEXT_WHY } : {})
    });
  }

  return findings;
}

const ASSIGNMENT_PATTERNS = [
  /^(?:export\s+)?[{,]?\s*["']?([A-Z0-9_-]*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|PRIVATE[_-]?KEY)[A-Z0-9_-]*)["']?\s*[:=]\s*["']?([^"',}\s#]{8,})/i,
  /(?:^|:)([A-Z0-9_-]*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|PRIVATE[_-]?KEY)[A-Z0-9_-]*)\s*=\s*["']?([^"'\s#]{8,})/i
];

// The space-separated `password <value>` form is netrc syntax; in any other
// file it matches English prose ("password rotation policy is ..."), so gate
// it to actual netrc files.
const NETRC_FILE_NAMES = new Set([".netrc", "_netrc", "netrc"]);

function matchSecretAssignment(line, basename) {
  if (NETRC_FILE_NAMES.has(String(basename).toLowerCase())) {
    const netrcPassword = line.match(/\b(password)\s+([^\s#]{8,})/i);
    if (netrcPassword) {
      return netrcPassword;
    }
  }

  for (const pattern of ASSIGNMENT_PATTERNS) {
    const match = line.match(pattern);
    if (match) {
      return match;
    }
  }

  return null;
}

function isPlaceholderSecret(value) {
  const str = String(value);
  // Obvious placeholder prefixes (shared with the MCP scanner)
  if (looksLikePlaceholderValue(str)) {
    return true;
  }
  // Environment variable references like $VAR, ${VAR}, %VAR%
  if (/^(\$\{?[A-Z_][A-Z0-9_]*\}?|%[A-Z_][A-Z0-9_]*%)/i.test(str)) {
    return true;
  }
  // URL values are not secrets
  if (/^https?:\/\//i.test(str)) {
    return true;
  }
  // Absolute file paths are not secrets
  if (/^\/[^\s]|^[A-Za-z]:[/\\]/.test(str)) {
    return true;
  }
  // Boolean or null literals
  if (/^(true|false|null|none|undefined)$/i.test(str)) {
    return true;
  }
  return false;
}
