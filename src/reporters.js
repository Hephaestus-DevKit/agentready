import path from "node:path";
import { SEVERITIES } from "./constants.js";

export function formatJson(result) {
  return `${JSON.stringify(result, null, 2)}\n`;
}

export function formatSarif(result) {
  const rules = new Map();

  for (const finding of result.findings) {
    if (!rules.has(finding.id)) {
      rules.set(finding.id, {
        id: finding.id,
        name: finding.title,
        shortDescription: {
          text: finding.title
        },
        fullDescription: {
          text: finding.recommendation
        },
        help: {
          text: finding.why || finding.recommendation,
          markdown: `${finding.why || finding.recommendation}\n\n${finding.recommendation}`
        },
        defaultConfiguration: {
          level: toSarifLevel(finding.severity)
        },
        properties: {
          category: finding.category || "general",
          precision: finding.severity === "info" ? "medium" : "high",
          severity: finding.severity,
          tags: [finding.category || "general", finding.severity]
        }
      });
    }
  }

  const sarif = {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "AgentReady",
            rules: [...rules.values()]
          }
        },
        results: result.findings.map((finding) => toSarifResult(finding))
      }
    ]
  };

  return `${JSON.stringify(sarif, null, 2)}\n`;
}

export function formatMarkdown(result) {
  const lines = [
    "# AgentReady Security Report",
    "",
    "## Summary",
    "",
    `- Root: \`${result.root}\``,
    `- Generated: ${result.scannedAt}`,
    `- Duration: ${formatDuration(result.durationMs)}`,
    `- Files scanned: ${result.filesScanned}`,
    result.baseline?.path ? `- Baseline suppressed: ${result.baseline.suppressed} of ${result.baseline.entries}` : null,
    "",
    "| Severity | Count |",
    "| --- | ---: |",
    ...SEVERITIES.map((severity) => `| ${severity} | ${result.summary[severity]} |`),
    ""
  ].filter((line) => line !== null);

  appendConfigWarnings(lines, result, true);

  if (result.findings.length === 0) {
    lines.push("## Result", "", "No findings detected.", "");
    appendNextSteps(lines, result, true);
    return `${lines.join("\n")}\n`;
  }

  lines.push("## Top Risks", "");
  for (const finding of topRisks(result.findings)) {
    lines.push(`- **${finding.severity.toUpperCase()}** \`${formatLocation(finding)}\` ${finding.title}`);
  }
  lines.push("");

  lines.push("## Findings", "");
  for (const severity of SEVERITIES) {
    const findings = result.findings.filter((finding) => finding.severity === severity);
    if (findings.length === 0) {
      continue;
    }

    lines.push(`### ${severity.toUpperCase()}`, "");
    for (const finding of findings) {
      lines.push(`#### ${finding.title}`);
      lines.push("");
      lines.push(`- Rule: \`${finding.id}\``);
      lines.push(`- Category: ${finding.category || "general"}`);
      if (finding.file) {
        lines.push(`- Location: \`${formatLocation(finding)}\``);
      }
      if (finding.evidence) {
        lines.push(`- Evidence: ${escapeMarkdown(finding.evidence)}`);
      }
      if (finding.why) {
        lines.push(`- Why it matters: ${escapeMarkdown(finding.why)}`);
      }
      lines.push(`- Recommendation: ${escapeMarkdown(finding.recommendation)}`);
      lines.push("");
    }
  }

  appendNextSteps(lines, result, true);
  return `${lines.join("\n")}\n`;
}

export function formatText(result, options = {}) {
  if (options.quiet) {
    return `AgentReady: high=${result.summary.high} medium=${result.summary.medium} low=${result.summary.low} info=${result.summary.info}`;
  }

  const lines = [
    "AgentReady Report",
    `Root: ${result.root}`,
    `Generated: ${result.scannedAt}`,
    `Duration: ${formatDuration(result.durationMs)}`,
    `Files scanned: ${result.filesScanned}`,
    result.baseline?.path ? `Baseline suppressed: ${result.baseline.suppressed} of ${result.baseline.entries}` : null,
    `Summary: high=${result.summary.high} medium=${result.summary.medium} low=${result.summary.low} info=${result.summary.info}`,
    ""
  ].filter((line) => line !== null);

  appendConfigWarnings(lines, result, false);

  if (result.findings.length === 0) {
    lines.push("No findings detected.", "");
    appendNextSteps(lines, result, false);
    return lines.join("\n");
  }

  lines.push("Top risks:");
  for (const finding of topRisks(result.findings)) {
    lines.push(`- [${finding.severity.toUpperCase()}] ${formatLocation(finding)} ${finding.title}`);
  }
  lines.push("");

  for (const severity of SEVERITIES) {
    const findings = result.findings.filter((finding) => finding.severity === severity);
    if (findings.length === 0) {
      continue;
    }

    lines.push(`${severity.toUpperCase()} (${findings.length})`);
    for (const finding of findings) {
      lines.push(`- ${finding.title}`);
      lines.push(`  Rule: ${finding.id}`);
      lines.push(`  Category: ${finding.category || "general"}`);
      if (finding.file) {
        lines.push(`  Location: ${formatLocation(finding)}`);
      }
      if (finding.evidence) {
        lines.push(`  Evidence: ${finding.evidence}`);
      }
      if (finding.why) {
        lines.push(`  Why: ${finding.why}`);
      }
      lines.push(`  Fix: ${finding.recommendation}`);
      if (options.verbose && finding.fingerprint) {
        lines.push(`  Fingerprint: ${finding.fingerprint}`);
      }
    }
    lines.push("");
  }

  appendNextSteps(lines, result, false);
  return lines.join("\n").trimEnd();
}

function appendConfigWarnings(lines, result, markdown) {
  if (!result.configWarnings?.length) {
    return;
  }

  lines.push(markdown ? "## Config Warnings" : "Config warnings:", "");
  for (const warning of result.configWarnings) {
    lines.push(`- ${markdown ? escapeMarkdown(warning) : warning}`);
  }
  lines.push("");
}

function appendNextSteps(lines, result, markdown) {
  lines.push(markdown ? "## Next Steps" : "Next steps:");
  lines.push("");
  for (const step of nextSteps(result)) {
    lines.push(`- ${step}`);
  }
}

function formatLocation(finding) {
  if (!finding.file) {
    return "(project)";
  }
  return finding.line ? `${finding.file}:${finding.line}` : finding.file;
}

function escapeMarkdown(value) {
  return String(value).replaceAll("|", "\\|").replaceAll("\n", " ");
}

export function toRelative(root, filePath) {
  return path.relative(root, filePath).replaceAll("\\", "/");
}

function formatDuration(durationMs) {
  if (typeof durationMs !== "number") {
    return "unknown";
  }

  if (durationMs < 1000) {
    return `${durationMs}ms`;
  }

  return `${(durationMs / 1000).toFixed(1)}s`;
}

function topRisks(findings, limit = 5) {
  const rank = new Map(SEVERITIES.map((severity, index) => [severity, index]));
  return [...findings]
    .sort((left, right) => {
      const severityDelta = rank.get(left.severity) - rank.get(right.severity);
      if (severityDelta !== 0) {
        return severityDelta;
      }
      return String(left.file || "").localeCompare(String(right.file || ""));
    })
    .slice(0, limit);
}

function nextSteps(result) {
  const steps = [];

  if (result.summary.high > 0) {
    steps.push("Fix high severity findings before giving an AI agent broad repository access.");
  }

  if (result.summary.medium > 0) {
    steps.push("Review medium severity findings and decide whether to fix, baseline, or explicitly configure exceptions.");
  }

  if (result.summary.high === 0 && result.summary.medium === 0 && result.summary.low === 0 && result.summary.info === 0) {
    steps.push("Run agentready init . if this project does not already define agent boundaries.");
    steps.push("Run agentready scan . --format markdown --output agentready-report.md when you need a shareable report.");
  }

  if (result.baseline?.suppressed > 0) {
    steps.push("Review baseline debt periodically; commit baseline files only after human review.");
  } else if (result.summary.high + result.summary.medium > 0) {
    steps.push("For legacy projects, create a reviewed baseline with agentready baseline . --output .agentready-baseline.json.");
  }

  if (steps.length === 0) {
    steps.push("Consider adding AgentReady to CI with agentready scan . --ci.");
  }

  return steps;
}

function toSarifResult(finding) {
  const result = {
    ruleId: finding.id,
    level: toSarifLevel(finding.severity),
    message: {
      text: `${finding.title}. ${finding.recommendation}`
    },
    properties: {
      category: finding.category || "general",
      severity: finding.severity,
      evidence: finding.evidence || "",
      fingerprint: finding.fingerprint || ""
    }
  };

  if (finding.fingerprint) {
    result.partialFingerprints = {
      primaryLocationLineHash: finding.fingerprint
    };
  }

  if (finding.file) {
    result.locations = [
      {
        physicalLocation: {
          artifactLocation: {
            uri: finding.file
          }
        }
      }
    ];

    if (finding.line) {
      result.locations[0].physicalLocation.region = {
        startLine: finding.line
      };
    }
  }

  return result;
}

function toSarifLevel(severity) {
  if (severity === "high" || severity === "medium") {
    return "error";
  }

  if (severity === "low") {
    return "warning";
  }

  return "note";
}
