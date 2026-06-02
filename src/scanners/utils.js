export function findLine(content, needle) {
  const lines = content.split(/\r?\n/);
  const index = lines.findIndex((line) => line.includes(needle));
  return index === -1 ? null : index + 1;
}

export function redact(value) {
  return String(value)
    .replace(/\bgh[pousr]_[A-Za-z0-9_]{8,}\b/g, (match) => `${match.slice(0, 8)}...[redacted]`)
    .replace(/\bsk-ant-[A-Za-z0-9_-]{8,}\b/g, "sk-ant-...[redacted]")
    .replace(/\bsk-[A-Za-z0-9_-]{8,}\b/g, "sk-...[redacted]")
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, "AKIA...[redacted]");
}

export function splitLines(content) {
  return content.split(/\r?\n/);
}
