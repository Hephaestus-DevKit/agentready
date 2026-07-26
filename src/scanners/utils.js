/**
 * Split `content` once and return a finder that reports the 1-based line number
 * of the first line containing a needle (or null). Preferred over repeated
 * findLine calls on the same content, which would re-split the file each time.
 * `fromLine` (1-based) restricts the search to that line onward, so callers can
 * disambiguate needles that also occur earlier in the file.
 */
export function createLineFinder(content) {
  const lines = splitLines(content);
  return (needle, fromLine = 1) => {
    for (let index = Math.max(0, fromLine - 1); index < lines.length; index += 1) {
      if (lines[index].includes(needle)) {
        return index + 1;
      }
    }
    return null;
  };
}

/**
 * One table drives both detection (secrets scanner) and evidence redaction, so
 * a newly added token type can never be detected but leak unmasked into
 * reports. `detect` is the strict finding trigger; `redactPattern` is looser
 * (shorter tails) so truncated or wrapped tokens still get masked.
 */
export const SECRET_TOKEN_RULES = [
  {
    id: "secret.private_key",
    detect: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/,
    redactPattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g,
    redactWith: "-----BEGIN PRIVATE KEY-----...[redacted]-----END PRIVATE KEY-----",
    title: "Private key material is present",
    recommendation: "Remove private keys from the repository and rotate any exposed credentials."
  },
  {
    id: "secret.github_token",
    detect: /\bgh[pousr]_[A-Za-z0-9_]{30,}\b/,
    redactPattern: /\bgh[pousr]_[A-Za-z0-9_]{8,}\b/g,
    redactWith: (match) => `${match.slice(0, 8)}...[redacted]`,
    title: "GitHub token-like value is present",
    recommendation: "Move the token to a secret manager, rotate it, and keep it outside agent-readable files."
  },
  {
    id: "secret.anthropic_key",
    detect: /\bsk-ant-[A-Za-z0-9_-]{32,}\b/,
    redactPattern: /\bsk-ant-[A-Za-z0-9_-]{8,}\b/g,
    redactWith: "sk-ant-...[redacted]",
    title: "Anthropic-style API key is present",
    recommendation: "Move API keys to environment secrets and add the file to .agentignore and .gitignore."
  },
  {
    id: "secret.stripe_key",
    detect: /\bsk_live_[A-Za-z0-9]{24,}\b/,
    redactPattern: /\bsk_live_[A-Za-z0-9]{8,}\b/g,
    redactWith: "sk_live_...[redacted]",
    title: "Stripe live API key is present",
    recommendation: "Rotate the Stripe key and move it to scoped secret storage."
  },
  {
    id: "secret.openai_key",
    detect: /\bsk-(?!ant-)[A-Za-z0-9_-]{32,}\b/,
    redactPattern: /\bsk-[A-Za-z0-9_-]{8,}\b/g,
    redactWith: "sk-...[redacted]",
    title: "OpenAI-style API key is present",
    recommendation: "Move API keys to environment secrets and add the file to .agentignore and .gitignore."
  },
  {
    id: "secret.aws_access_key",
    detect: /\bAKIA[0-9A-Z]{16}\b/,
    redactPattern: /\bAKIA[0-9A-Z]{16}\b/g,
    redactWith: "AKIA...[redacted]",
    title: "AWS access key-like value is present",
    recommendation: "Rotate the key, remove it from the repository, and use scoped secret storage."
  },
  {
    id: "secret.google_api_key",
    detect: /\bAIzaSy[A-Za-z0-9_-]{33}\b/,
    redactPattern: /\bAIzaSy[A-Za-z0-9_-]{8,}\b/g,
    redactWith: "AIzaSy...[redacted]",
    title: "Google API key is present",
    recommendation: "Restrict the API key scope in Google Cloud Console and move it to secret storage."
  },
  {
    id: "secret.slack_token",
    detect: /\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{20,}\b/,
    redactPattern: /\bxoxb-[0-9A-Za-z-]{8,}\b/g,
    redactWith: "xoxb-...[redacted]",
    title: "Slack bot token is present",
    recommendation: "Rotate the Slack token and use scoped secret storage."
  },
  {
    id: "secret.slack_app_token",
    detect: /\bxapp-[0-9]-[A-Za-z0-9]+-[0-9]+-[A-Za-z0-9]+\b/,
    redactPattern: /\bxapp-[0-9A-Za-z-]{8,}\b/g,
    redactWith: "xapp-...[redacted]",
    title: "Slack app-level token is present",
    recommendation: "Rotate the Slack app token and use scoped secret storage."
  },
  {
    id: "secret.jwt_token",
    detect: /\beyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+\b/,
    redactPattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_.-]{8,}\b/g,
    redactWith: "eyJ...[redacted]",
    severity: "medium",
    title: "Hardcoded JWT token detected",
    recommendation: "Remove hardcoded JWT tokens; generate them dynamically at runtime."
  }
];

export function redact(value) {
  let result = String(value);
  for (const rule of SECRET_TOKEN_RULES) {
    result = result.replace(rule.redactPattern, rule.redactWith);
  }
  return result;
}

export function splitLines(content) {
  // Handle \r\n (Windows), \r (old Mac), and \n (Unix) line endings
  return content.split(/\r\n|\r|\n/);
}

/**
 * Values that are clearly instructions rather than credentials. Shared by the
 * secrets and MCP scanners so placeholder handling stays consistent.
 * Dogfood evidence: ".env.example" files commonly use values like
 * "change-this-for-remote-admin", which the earlier "changeme" pattern missed.
 * GitHub Actions template expressions (`${{ secrets.X }}`) reference secret
 * storage instead of containing a secret, so they are placeholders too.
 */
const PLACEHOLDER_VALUE_PATTERN = /^(example|sample|changeme|change[-_]|replace[-_]|placeholder|dummy|test|todo|xxx+|your[-_]?|<|fill[-_]?in|insert[-_]|\$\{\{)/i;

export function looksLikePlaceholderValue(value) {
  return PLACEHOLDER_VALUE_PATTERN.test(String(value).trim());
}

/**
 * Paths that are conventionally test code or test fixtures. Secret-shaped
 * values found here are usually deliberate fakes (for example a redaction
 * test suite), so findings are reported at reduced severity instead of high.
 */
const TEST_PATH_PATTERN = /(^|\/)(tests?|__tests__|__mocks__|spec|fixtures?)(\/|$)|\.(test|spec)\.[^/]+$|_test\.[^/]+$|(^|\/)conftest\.py$/i;

export function isTestPath(relativePath) {
  return TEST_PATH_PATTERN.test(String(relativePath).replaceAll("\\", "/"));
}
