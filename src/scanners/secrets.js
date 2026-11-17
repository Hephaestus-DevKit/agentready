import {
  SECRET_TOKEN_RULES,
  isEnvironmentReference,
  isTestPath,
  looksLikePlaceholderValue,
  redact,
  splitLines
} from "./utils.js";

const TEST_CONTEXT_WHY =
  "Secret-shaped value found in a test file or fixture; these are usually deliberate fakes, but verify no real credential was committed.";

const SENSITIVE_FILE_PATTERNS = [
  /^\.env(?:[.-]|rc$|$)/i,
  /^\.npmrc$/i,
  /^\.pypirc$/i,
  /^\.netrc$/i,
  /^id_(?:rsa|dsa|ecdsa|ecdsa_sk|ed25519|ed25519_sk)$/i,
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

    for (const assignment of findSecretAssignments(line, basename)) {
      if (isPlaceholderSecret(assignment.value)) {
        continue;
      }

      findings.push({
        id: "secret.generic_assignment",
        severity,
        title: "Secret-like assignment is present",
        file: relativePath,
        line: index + 1,
        evidence: `${assignment.key}=[redacted]`,
        recommendation: "Move secret values out of repository files, rotate exposed credentials, and keep them outside agent-readable paths.",
        ...(inTestContext ? { why: TEST_CONTEXT_WHY } : {})
      });
    }
  }

  return findings;
}

// Linear key-value scanner: captures the identifier once with `[A-Za-z0-9_-]+`
// and classifies the key in JS so long lines with repeated `TOKEN_` segments
// never trigger polynomial regex backtracking, and multi-key JSON lines report
// every secret assignment instead of stopping at the first key.
const KEY_VALUE_ASSIGNMENT =
  /(?:^|[\s{,;:])["']?([A-Za-z0-9_-]+)["']?\s*[:=]\s*(?:"([^"\r\n]*)"|'([^'\r\n]*)'|([^\s"',}#]+))/g;
const SECRET_ASSIGNMENT_KEY =
  /(?:api[_-]?key|private[_-]?key|password|passwd|secret|(?<![A-Za-z])token(?![A-Za-z]))/i;
const CAMEL_TOKEN_KEY = /[a-z0-9]Token(?:$|[A-Z0-9_-])/;

// The space-separated `password <value>` form is netrc syntax; in any other
// file it matches English prose ("password rotation policy is ..."), so gate
// it to actual netrc files.
const NETRC_FILE_NAMES = new Set([".netrc", "_netrc", "netrc"]);

function isSecretAssignmentKey(key) {
  const normalized = key.replace(/[-_]/g, "").toLowerCase();
  if (normalized === "tokenurl" || normalized === "authorizationurl") {
    return false;
  }
  return SECRET_ASSIGNMENT_KEY.test(key) || CAMEL_TOKEN_KEY.test(key);
}

function findSecretAssignments(line, basename) {
  const matches = [];

  if (NETRC_FILE_NAMES.has(String(basename).toLowerCase())) {
    for (const netrcMatch of line.matchAll(/\b(password)\s+([^\s#]{8,})/gi)) {
      matches.push({ key: netrcMatch[1], value: netrcMatch[2] });
    }
    if (matches.length > 0) {
      return matches;
    }
  }

  for (const match of line.matchAll(KEY_VALUE_ASSIGNMENT)) {
    const key = match[1];
    const value = (match[2] ?? match[3] ?? match[4] ?? "").trim();
    if (value.length >= 8 && isSecretAssignmentKey(key)) {
      matches.push({ key, value });
    }
  }

  return matches;
}

function isPlaceholderSecret(value) {
  const str = String(value).trim();
  // Obvious placeholder prefixes (shared with the MCP scanner)
  if (looksLikePlaceholderValue(str)) {
    return true;
  }
  // Full-string environment variable references like $VAR, ${VAR}, %VAR%
  if (isEnvironmentReference(str)) {
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
