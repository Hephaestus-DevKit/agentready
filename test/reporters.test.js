import { test } from "node:test";
import assert from "node:assert/strict";
import { formatSarif } from "../src/reporters.js";

test("formatSarif emits valid SARIF with rule and location data", () => {
  const sarif = JSON.parse(
    formatSarif({
      root: "/tmp/project",
      scannedAt: "2026-06-02T00:00:00.000Z",
      filesScanned: 1,
      summary: { high: 1, medium: 0, low: 0, info: 0 },
      findings: [
        {
          id: "secret.github_token",
          severity: "high",
          title: "GitHub token-like value is present",
          file: "src/index.js",
          line: 12,
          evidence: "ghp_123...[redacted]",
          recommendation: "Move the token to a secret manager.",
          fingerprint: "abc123def456abc123def456"
        }
      ]
    })
  );

  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs[0].tool.driver.rules[0].id, "secret.github_token");
  assert.equal(sarif.runs[0].results[0].level, "error");
  assert.equal(sarif.runs[0].results[0].partialFingerprints.primaryLocationLineHash, "abc123def456abc123def456");
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine, 12);
});
