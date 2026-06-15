export function findLine(content, needle) {
  const lines = content.split(/\r\n|\r|\n/);
  const index = lines.findIndex((line) => line.includes(needle));
  return index === -1 ? null : index + 1;
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

export function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
