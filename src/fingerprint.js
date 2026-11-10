import { createHash } from "node:crypto";

/**
 * Attach fingerprints to every finding.
 *
 * `fingerprint` includes the line number and is what existing baselines and
 * SARIF consumers already store, so it must not change.
 *
 * `stableFingerprint` omits the line number so inserting or deleting lines
 * above a baselined finding does not turn it into a "new" finding. Findings
 * that share rule, file, evidence, and title (the same risky command on two
 * lines) are told apart by their order of occurrence.
 */
export function addFingerprints(findings) {
  const occurrences = new Map();
  return findings.map((finding) => {
    const group = stableParts(finding).join("\u001f");
    const occurrence = occurrences.get(group) ?? 0;
    occurrences.set(group, occurrence + 1);
    return {
      ...finding,
      fingerprint: fingerprintFinding(finding),
      stableFingerprint: hash(`${group}\u001f${occurrence}`)
    };
  });
}

export function fingerprintFinding(finding) {
  const stableParts = [
    finding.id || "",
    finding.file || "",
    // Use ?? "" so line number 0 is preserved (not coerced to falsy)
    String(finding.line ?? ""),
    finding.evidence || "",
    finding.title || ""
  ];

  return hash(stableParts.join("\u001f"));
}

function stableParts(finding) {
  return [finding.id || "", finding.file || "", finding.evidence || "", finding.title || ""];
}

function hash(value) {
  return createHash("sha256").update(value).digest("hex").slice(0, 24);
}
