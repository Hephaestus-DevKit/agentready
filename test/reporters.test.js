import { test } from "node:test";
import assert from "node:assert/strict";
import { formatBaselineDiff, formatJson, formatMarkdown, formatSarif, formatText } from "../src/reporters.js";

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
  assert.equal(sarif.runs[0].tool.driver.informationUri, "https://github.com/Hephaestus-DevKit/agentready");
  assert.ok(sarif.runs[0].tool.driver.rules.some((rule) => rule.id === "secret.github_token"));
  assert.equal(sarif.runs[0].originalUriBaseIds.PROJECTROOT.uri.startsWith("file:"), true);
  assert.equal(sarif.runs[0].results[0].level, "error");
  assert.equal(sarif.runs[0].results[0].partialFingerprints.primaryLocationLineHash, "abc123def456abc123def456");
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uriBaseId, "PROJECTROOT");
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine, 12);
});

test("formatText surfaces status, config, threshold, and review report next step", () => {
  const output = formatText({
    root: "/tmp/project",
    scannedAt: "2026-06-02T00:00:00.000Z",
    durationMs: 12,
    filesScanned: 2,
    filesSkipped: {
      unsupportedType: 3,
      oversized: 1,
      binary: 1
    },
    config: {
      configPath: "/tmp/project/.agentready.json",
      failOn: "medium"
    },
    summary: { high: 0, medium: 1, low: 0, info: 0 },
    findings: [
      {
        id: "package.lifecycle_script",
        severity: "medium",
        title: "Lifecycle script runs during install",
        category: "package",
        file: "package.json",
        evidence: "postinstall",
        recommendation: "Review the script before agent-assisted installs."
      }
    ]
  });

  assert.match(output, /Status: review recommended/);
  assert.match(output, /Files skipped: 5 \(unsupported-type=3 oversized=1 binary=1\)/);
  assert.match(output, /Config: \/tmp\/project\/\.agentready\.json/);
  assert.match(output, /CI fail threshold: medium/);
  assert.match(output, /Save a markdown report/);
});

test("formatMarkdown surfaces ready status and quickstart next step for defaults", () => {
  const output = formatMarkdown({
    root: "/tmp/project",
    scannedAt: "2026-06-02T00:00:00.000Z",
    durationMs: 12,
    filesScanned: 2,
    config: {
      configPath: null,
      failOn: "medium"
    },
    summary: { high: 0, medium: 0, low: 0, info: 0 },
    findings: []
  });

  assert.match(output, /- Status: ready/);
  assert.match(output, /- Config: `\(defaults\)`/);
  assert.match(output, /Run agentready quickstart \./);
});

test("formatText includes next step for configuration warnings", () => {
  const output = formatText({
    root: "/tmp/project",
    scannedAt: "2026-06-02T00:00:00.000Z",
    durationMs: 12,
    filesScanned: 2,
    config: {
      configPath: "/tmp/project/.agentready.json",
      failOn: "medium"
    },
    configWarnings: ["Unknown configuration field ignored: failon"],
    summary: { high: 0, medium: 0, low: 0, info: 0 },
    findings: []
  });

  assert.match(output, /Fix configuration warnings/);
  assert.match(output, /agentready config validate \./);
});

test("formatJson includes machine-readable next steps", () => {
  const output = formatJson({
    root: "/tmp/project",
    scannedAt: "2026-06-02T00:00:00.000Z",
    durationMs: 12,
    filesScanned: 2,
    config: {
      configPath: "/tmp/project/.agentready.json",
      failOn: "medium"
    },
    summary: { high: 1, medium: 0, low: 0, info: 0 },
    findings: [
      {
        id: "secret.generic_assignment",
        severity: "high",
        title: "Secret-like assignment is present",
        category: "secrets",
        file: ".env",
        evidence: "SERVICE_TOKEN=[redacted]",
        recommendation: "Move secret values out of repository files."
      }
    ]
  });
  const parsed = JSON.parse(output);

  assert.ok(Array.isArray(parsed.nextSteps));
  assert.match(parsed.nextSteps[0], /Fix high severity/);
});

test("formatMarkdown can group findings by category and show report limits", () => {
  const output = formatMarkdown(
    {
      root: "/tmp/project",
      scannedAt: "2026-06-02T00:00:00.000Z",
      durationMs: 12,
      filesScanned: 2,
      config: {
        configPath: "/tmp/project/.agentready.json",
        failOn: "medium"
      },
      report: {
        totalFindings: 2,
        displayedFindings: 1,
        omittedFindings: 1,
        groupBy: "category"
      },
      summary: { high: 0, medium: 2, low: 0, info: 0 },
      findings: [
        {
          id: "package.lifecycle_script",
          severity: "medium",
          title: "Lifecycle script runs during install",
          category: "package",
          file: "package.json",
          evidence: "postinstall",
          recommendation: "Review the script before agent-assisted installs."
        }
      ]
    },
    { groupBy: "category" }
  );

  assert.match(output, /## Findings By Category/);
  assert.match(output, /### package/);
  assert.match(output, /Findings displayed: 1 of 2/);
  assert.match(output, /1 finding\(s\) hidden/);
});

test("formatBaselineDiff emits reviewable text", () => {
  const output = formatBaselineDiff(
    {
      baselinePath: "/tmp/project/.agentready-baseline.json",
      summary: {
        baseline: 2,
        current: 1,
        matched: 1,
        new: 1,
        stale: 1,
        severity: {
          new: { high: 1, medium: 0, low: 0, info: 0 },
          stale: { high: 0, medium: 1, low: 0, info: 0 }
        }
      },
      newFindings: [
        {
          id: "secret.generic_assignment",
          severity: "high",
          title: "Secret-like assignment is present",
          file: ".env",
          line: 1
        }
      ],
      staleFindings: [
        {
          id: "package.lifecycle_script",
          severity: "medium",
          title: "Package lifecycle script detected",
          file: "package.json",
          line: 4
        }
      ]
    },
    "text"
  );

  assert.match(output, /AgentReady Baseline Diff/);
  assert.match(output, /New: 1/);
  assert.match(output, /Stale: 1/);
  assert.match(output, /New severity: high=1 medium=0 low=0 info=0/);
});
