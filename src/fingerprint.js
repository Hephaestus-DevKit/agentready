import { createHash } from "node:crypto";

export function addFingerprints(findings) {
  return findings.map((finding) => ({
    ...finding,
    fingerprint: fingerprintFinding(finding)
  }));
}

export function fingerprintFinding(finding) {
  const stableParts = [
    finding.id || "",
    finding.file || "",
    finding.line || "",
    finding.evidence || "",
    finding.title || ""
  ];

  return createHash("sha256").update(stableParts.join("\u001f")).digest("hex").slice(0, 24);
}
