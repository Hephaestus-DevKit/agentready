/**
 * Split `content` once and return a finder that reports the 1-based line number
 * of the first line containing a needle (or null). Preferred over repeated
 * findLine calls on the same content, which would re-split the file each time.
 */
export function createLineFinder(content) {
  const lines = splitLines(content);
  return (needle) => {
    const index = lines.findIndex((line) => line.includes(needle));
    return index === -1 ? null : index + 1;
  };
}

export function redact(value) {
  return String(value)
    .replace(/\bgh[pousr]_[A-Za-z0-9_]{8,}\b/g, (match) => `${match.slice(0, 8)}...[redacted]`)
    .replace(/\bsk-ant-[A-Za-z0-9_-]{8,}\b/g, "sk-ant-...[redacted]")
    .replace(/\bsk_live_[A-Za-z0-9]{8,}\b/g, "sk_live_...[redacted]")
    .replace(/\bsk-[A-Za-z0-9_-]{8,}\b/g, "sk-...[redacted]")
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, "AKIA...[redacted]")
    .replace(/\bAIzaSy[A-Za-z0-9_-]{8,}\b/g, "AIzaSy...[redacted]")
    .replace(/\bxoxb-[0-9A-Za-z-]{8,}\b/g, "xoxb-...[redacted]")
    .replace(/\bxapp-[0-9A-Za-z-]{8,}\b/g, "xapp-...[redacted]")
    .replace(/-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g, "-----BEGIN PRIVATE KEY-----...[redacted]-----END PRIVATE KEY-----");
}

export function splitLines(content) {
  // Handle \r\n (Windows), \r (old Mac), and \n (Unix) line endings
  return content.split(/\r\n|\r|\n/);
}

// Re-export the canonical implementation from ../utils.js so there is a single
// source of truth; existing scanner consumers keep importing it from here.
export { escapeRegExp } from "../utils.js";

/**
 * Values that are clearly instructions rather than credentials. Shared by the
 * secrets and MCP scanners so placeholder handling stays consistent.
 * Dogfood evidence: ".env.example" files commonly use values like
 * "change-this-for-remote-admin", which the earlier "changeme" pattern missed.
 */
const PLACEHOLDER_VALUE_PATTERN = /^(example|sample|changeme|change[-_]|replace[-_]|placeholder|dummy|test|todo|xxx+|your[-_]?|<|fill[-_]?in|insert[-_])/i;

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
