import { redact, splitLines } from "./utils.js";

export const SENSITIVE_FILE_PATTERNS = [
  /^\.env(?:\.|$)/,
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
  }
];

export function scanSensitiveFileName(relativePath, basename) {
  if (!isSensitiveFileName(basename)) {
    return [];
  }

  return [
    {
      id: "secret.sensitive_filename",
      severity: "medium",
      title: "Sensitive-looking file is agent-readable",
      file: relativePath,
      line: null,
      evidence: basename,
      recommendation: "Keep this file out of git and add it to .agentignore unless agents explicitly need it."
    }
  ];
}

export function scanSecretContent(relativePath, basename, content) {
  const findings = [];
  const lines = splitLines(content);

  for (const rule of SECRET_PATTERNS) {
    for (let index = 0; index < lines.length; index += 1) {
      if (!rule.pattern.test(lines[index])) {
        continue;
      }

      findings.push({
        id: rule.id,
        severity: "high",
        title: rule.title,
        file: relativePath,
        line: index + 1,
        evidence: redact(lines[index]),
        recommendation: rule.recommendation
      });
      break;
    }
  }

  if (isSensitiveFileName(basename)) {
    findings.push(...scanGenericSecretAssignments(relativePath, lines));
  }

  return findings;
}

export function isSensitiveFileName(basename) {
  return SENSITIVE_FILE_PATTERNS.some((pattern) => pattern.test(basename));
}

function scanGenericSecretAssignments(relativePath, lines) {
  const findings = [];
  const pattern = /^\s*([A-Z0-9_-]*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|PRIVATE[_-]?KEY)[A-Z0-9_-]*)\s*[:=]\s*["']?([^"'\s#]{8,})/i;

  for (let index = 0; index < lines.length; index += 1) {
    const match = lines[index].match(pattern);
    if (!match) {
      continue;
    }

    if (isPlaceholderSecret(match[2])) {
      continue;
    }

    findings.push({
      id: "secret.generic_assignment",
      severity: "high",
      title: "Secret-like assignment is present",
      file: relativePath,
      line: index + 1,
      evidence: `${match[1]}=[redacted]`,
      recommendation: "Move secret values out of repository files, rotate exposed credentials, and keep them outside agent-readable paths."
    });
  }

  return findings;
}

function isPlaceholderSecret(value) {
  return /^(example|changeme|change_me|replace_me|placeholder|dummy|test|todo|xxx+|your_|<)/i.test(String(value));
}
