import { isTestPath, looksLikePlaceholderValue, redact, splitLines } from "./utils.js";

const TEST_CONTEXT_WHY =
  "Secret-shaped value found in a test file or fixture; these are usually deliberate fakes, but verify no real credential was committed.";

export const SENSITIVE_FILE_PATTERNS = [
  /^\.env(?:[.-]|rc$|$)/i,
  /^\.npmrc$/i,
  /^\.pypirc$/i,
  /^\.netrc$/i,
  /(?:^|[._-])secret(?:s)?(?:[._-]|$).*\.(?:json|ya?ml|toml|ini|txt|env)$/i,
  /(?:^|[._-])credential(?:s)?(?:[._-]|$).*\.(?:json|ya?ml|toml|ini|txt|env)$/i,
  /\.(?:pem|key|p12|pfx)$/i
];

const SECRET_PATTERNS = [
  {
    id: "secret.private_key",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/,
    title: "Private key material is present",
    recommendation: "Remove private keys from the repository and rotate any exposed credentials."
  },
  {
    id: "secret.github_token",
    pattern: /\bgh[pousr]_[A-Za-z0-9_]{30,}\b/,
    title: "GitHub token-like value is present",
    recommendation: "Move the token to a secret manager, rotate it, and keep it outside agent-readable files."
  },
  {
    id: "secret.anthropic_key",
    pattern: /\bsk-ant-[A-Za-z0-9_-]{32,}\b/,
    title: "Anthropic-style API key is present",
    recommendation: "Move API keys to environment secrets and add the file to .agentignore and .gitignore."
  },
  {
    id: "secret.openai_key",
    pattern: /\bsk-(?!ant-)[A-Za-z0-9_-]{32,}\b/,
    title: "OpenAI-style API key is present",
    recommendation: "Move API keys to environment secrets and add the file to .agentignore and .gitignore."
  },
  {
    id: "secret.aws_access_key",
    pattern: /\bAKIA[0-9A-Z]{16}\b/,
    title: "AWS access key-like value is present",
    recommendation: "Rotate the key, remove it from the repository, and use scoped secret storage."
  },
  {
    id: "secret.stripe_key",
    pattern: /\bsk_live_[A-Za-z0-9]{24,}\b/,
    title: "Stripe live API key is present",
    recommendation: "Rotate the Stripe key and move it to scoped secret storage."
  },
  {
    id: "secret.google_api_key",
    pattern: /\bAIzaSy[A-Za-z0-9_-]{33}\b/,
    title: "Google API key is present",
    recommendation: "Restrict the API key scope in Google Cloud Console and move it to secret storage."
  },
  {
    id: "secret.slack_token",
    pattern: /\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{20,}\b/,
    title: "Slack bot token is present",
    recommendation: "Rotate the Slack token and use scoped secret storage."
  },
  {
    id: "secret.slack_app_token",
    pattern: /\bxapp-[0-9]-[A-Za-z0-9]+-[0-9]+-[A-Za-z0-9]+\b/,
    title: "Slack app-level token is present",
    recommendation: "Rotate the Slack app token and use scoped secret storage."
  },
  {
    id: "secret.jwt_token",
    pattern: /\beyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+\b/,
    title: "Hardcoded JWT token detected",
    recommendation: "Remove hardcoded JWT tokens; generate them dynamically at runtime."
  }
];

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
  const severity = inTestContext ? "low" : "high";

  for (const rule of SECRET_PATTERNS) {
    for (let index = 0; index < lines.length; index += 1) {
      if (!rule.pattern.test(lines[index])) {
        continue;
      }

      findings.push({
        id: rule.id,
        severity,
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
    findings.push(...scanGenericSecretAssignments(relativePath, lines, severity, inTestContext));
  }

  return findings;
}

export function isSensitiveFileName(basename) {
  return SENSITIVE_FILE_PATTERNS.some((pattern) => pattern.test(basename));
}

export function isSensitivePath(relativePath, basename) {
  const normalized = String(relativePath).replaceAll("\\", "/");
  return isSensitiveFileName(basename) || /(^|\/)(secrets?|credentials?|private|backups?)(\/|$)/i.test(normalized);
}

function isTemplateSensitiveFileName(basename) {
  return /(?:^|[._-])(example|sample|template|dummy)(?:[._-]|$)/i.test(basename);
}

function scanGenericSecretAssignments(relativePath, lines, severity = "high", inTestContext = false) {
  const findings = [];

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index].trim();
    if (!line || line.startsWith("#")) {
      continue;
    }

    const match = matchSecretAssignment(line);
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

function matchSecretAssignment(line) {
  const netrcPassword = line.match(/\b(password)\s+([^\s#]{8,})/i);
  if (netrcPassword) {
    return netrcPassword;
  }

  const patterns = [
    /^(?:export\s+)?[{,]?\s*["']?([A-Z0-9_-]*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|PRIVATE[_-]?KEY)[A-Z0-9_-]*)["']?\s*[:=]\s*["']?([^"',}\s#]{8,})/i,
    /(?:^|:)([A-Z0-9_-]*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|PRIVATE[_-]?KEY)[A-Z0-9_-]*)\s*=\s*["']?([^"'\s#]{8,})/i
  ];

  for (const pattern of patterns) {
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
