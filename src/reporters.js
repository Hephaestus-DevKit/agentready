import path from "node:path";
import { pathToFileURL } from "node:url";
import { SEVERITIES } from "./constants.js";
import { RULE_CATALOG } from "./rules.js";
import { toRelative as utilToRelative, sortFindings, escapeMarkdown } from "./utils.js";

const TOOL_INFORMATION_URI = "https://github.com/Hephaestus-DevKit/agentready";
const RULE_HELP_URI = `${TOOL_INFORMATION_URI}/blob/main/docs/RULES.md`;
const SKIP_REASON_LABELS = {
  ignoredPath: "ignored-path",
  ignoredDirectory: "ignored-directory",
  oversized: "oversized",
  binary: "binary",
  unsupportedType: "unsupported-type",
  unreadableDirectory: "unreadable-directory",
  unreadableFile: "unreadable-file"
};

export function formatJson(result) {
  const enriched = result.nextSteps ? result : { ...result, nextSteps: nextSteps(result) };
  return `${JSON.stringify(enriched, null, 2)}\n`;
}

export function formatSarif(result) {
  const rules = new Map(RULE_CATALOG.map((rule) => [rule.id, toSarifRule(rule)]));

  for (const finding of result.findings) {
    if (!rules.has(finding.id)) {
      rules.set(finding.id, toSarifRule({
        id: finding.id,
        defaultSeverity: finding.severity,
        category: finding.category || "general",
        description: finding.title,
        recommendation: finding.recommendation,
        why: finding.why || finding.recommendation
      }));
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
            fullName: "AgentReady preflight security scanner",
            version: result.toolVersion || "0.1.0",
            semanticVersion: result.toolVersion || "0.1.0",
            informationUri: TOOL_INFORMATION_URI,
            rules: [...rules.values()]
          }
        },
        automationDetails: {
          id: "agentready/scan"
        },
        invocations: [
          {
            executionSuccessful: true,
            endTimeUtc: result.scannedAt
          }
        ],
        originalUriBaseIds: {
          PROJECTROOT: {
            uri: toSarifBaseUri(result.root)
          }
        },
        results: result.findings.map((finding) => toSarifResult(finding))
      }
    ]
  };

  return `${JSON.stringify(sarif, null, 2)}\n`;
}

export function formatMarkdown(result, options = {}) {
  const groupBy = options.groupBy || result.report?.groupBy || "severity";
  const lines = [
    "# AgentReady Security Report",
    "",
    "## Summary",
    "",
    `- Root: \`${result.root}\``,
    `- Generated: ${result.scannedAt}`,
    `- Duration: ${formatDuration(result.durationMs)}`,
    `- Files scanned: ${result.filesScanned}`,
    totalSkipped(result.filesSkipped) > 0 ? `- Files skipped: ${formatSkippedFiles(result.filesSkipped)}` : null,
    `- Status: ${statusLabel(result.summary)}`,
    `- Config: \`${formatConfigPath(result.config)}\``,
    `- CI fail threshold: ${result.config?.failOn || "medium"}`,
    result.report ? `- Findings displayed: ${result.report.displayedFindings} of ${result.report.totalFindings}` : null,
    result.baseline?.path ? `- Baseline suppressed: ${result.baseline.suppressed} of ${result.baseline.entries}` : null,
    "",
    "| Severity | Count |",
    "| --- | ---: |",
    ...SEVERITIES.map((severity) => `| ${severity} | ${result.summary[severity]} |`),
    ""
  ].filter((line) => line !== null);

  appendConfigWarnings(lines, result, true);

  if (result.report?.summaryOnly) {
    lines.push("## Findings", "", "Findings hidden by `--summary-only`.", "");
    appendNextSteps(lines, result, true);
    return `${lines.join("\n")}\n`;
  }

  if (result.findings.length === 0) {
    lines.push("## Result", "", result.report?.totalFindings > 0 ? "No findings displayed by the current report limit." : "No findings detected.", "");
    appendNextSteps(lines, result, true);
    return `${lines.join("\n")}\n`;
  }

  lines.push("## Top Risks", "");
  for (const finding of topRisks(result.findings)) {
    lines.push(`- **${finding.severity.toUpperCase()}** \`${formatLocation(finding)}\` ${finding.title}`);
  }
  lines.push("");

  if (groupBy === "category") {
    appendMarkdownFindingsByCategory(lines, result.findings);
  } else {
    appendMarkdownFindingsBySeverity(lines, result.findings);
  }

  if (result.report?.omittedFindings > 0) {
    lines.push(`_${result.report.omittedFindings} finding(s) hidden by the current report limit._`, "");
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
    totalSkipped(result.filesSkipped) > 0 ? `Files skipped: ${formatSkippedFiles(result.filesSkipped)}` : null,
    `Status: ${statusLabel(result.summary)}`,
    `Config: ${formatConfigPath(result.config)}`,
    `CI fail threshold: ${result.config?.failOn || "medium"}`,
    result.report ? `Findings displayed: ${result.report.displayedFindings} of ${result.report.totalFindings}` : null,
    result.baseline?.path ? `Baseline suppressed: ${result.baseline.suppressed} of ${result.baseline.entries}` : null,
    `Summary: high=${result.summary.high} medium=${result.summary.medium} low=${result.summary.low} info=${result.summary.info}`,
    ""
  ].filter((line) => line !== null);

  appendConfigWarnings(lines, result, false);

  if (result.report?.summaryOnly) {
    lines.push("Findings hidden by --summary-only.", "");
    appendNextSteps(lines, result, false);
    return lines.join("\n").trimEnd();
  }

  if (result.findings.length === 0) {
    lines.push(result.report?.totalFindings > 0 ? "No findings displayed by the current report limit." : "No findings detected.", "");
    appendNextSteps(lines, result, false);
    return lines.join("\n").trimEnd();
  }

  lines.push("Top risks:");
  for (const finding of topRisks(result.findings)) {
    lines.push(`- [${finding.severity.toUpperCase()}] ${formatLocation(finding)} ${finding.title}`);
  }
  lines.push("");

  if ((options.groupBy || result.report?.groupBy) === "category") {
    appendTextFindingsByCategory(lines, result.findings, options);
  } else {
    appendTextFindingsBySeverity(lines, result.findings, options);
  }

  if (result.report?.omittedFindings > 0) {
    lines.push(`${result.report.omittedFindings} finding(s) hidden by the current report limit.`, "");
  }

  appendNextSteps(lines, result, false);
  return lines.join("\n").trimEnd();
}

export function formatBaselineDiff(diff, format = "text") {
  if (format === "json") {
    return `${JSON.stringify(diff, null, 2)}\n`;
  }

  if (format === "markdown") {
    const lines = [
      "# AgentReady Baseline Diff",
      "",
      "## Summary",
      "",
      `- Baseline file: \`${diff.baselinePath}\``,
      `- Baseline entries: ${diff.summary.baseline}`,
      `- Current findings: ${diff.summary.current}`,
      `- Matched: ${diff.summary.matched}`,
      `- New: ${diff.summary.new}`,
      `- Stale: ${diff.summary.stale}`,
      diff.summary.severity ? `- New severity: ${formatSeveritySummary(diff.summary.severity.new)}` : null,
      diff.summary.severity ? `- Stale severity: ${formatSeveritySummary(diff.summary.severity.stale)}` : null,
      ""
    ].filter((line) => line !== null);

    appendBaselineDiffSection(lines, "New Findings", diff.newFindings, true);
    appendBaselineDiffSection(lines, "Stale Baseline Entries", diff.staleFindings, true);
    return `${lines.join("\n")}\n`;
  }

  const lines = [
    "AgentReady Baseline Diff",
    `Baseline file: ${diff.baselinePath}`,
    `Baseline entries: ${diff.summary.baseline}`,
    `Current findings: ${diff.summary.current}`,
    `Matched: ${diff.summary.matched}`,
    `New: ${diff.summary.new}`,
    `Stale: ${diff.summary.stale}`,
    diff.summary.severity ? `New severity: ${formatSeveritySummary(diff.summary.severity.new)}` : null,
    diff.summary.severity ? `Stale severity: ${formatSeveritySummary(diff.summary.severity.stale)}` : null,
    ""
  ].filter((line) => line !== null);

  appendBaselineDiffSection(lines, "New findings", diff.newFindings, false);
  appendBaselineDiffSection(lines, "Stale baseline entries", diff.staleFindings, false);
  return lines.join("\n").trimEnd();
}

export function formatBaselineDebt(debt, format = "text") {
  if (format === "json") {
    return `${JSON.stringify(debt, null, 2)}\n`;
  }

  if (format === "markdown") {
    const lines = [
      "# AgentReady Baseline Debt",
      "",
      "## Summary",
      "",
      `- Baseline file: \`${debt.baselinePath}\``,
      `- Entries: ${debt.entries}`,
      `- Severity: ${formatSeveritySummary(debt.severity)}`,
      `- Oldest age: ${formatAge(debt.oldestAgeDays)}`,
      `- Average age: ${formatAge(debt.averageAgeDays)}`,
      ""
    ];

    appendDebtCounts(lines, "Rules", debt.byRule, true);
    appendDebtCounts(lines, "Files", debt.byFile, true);
    appendDebtFindings(lines, debt.findings, true);
    return `${lines.join("\n")}\n`;
  }

  const lines = [
    "AgentReady Baseline Debt",
    `Baseline file: ${debt.baselinePath}`,
    `Entries: ${debt.entries}`,
    `Severity: ${formatSeveritySummary(debt.severity)}`,
    `Oldest age: ${formatAge(debt.oldestAgeDays)}`,
    `Average age: ${formatAge(debt.averageAgeDays)}`,
    ""
  ];

  appendDebtCounts(lines, "Rules", debt.byRule, false);
  appendDebtCounts(lines, "Files", debt.byFile, false);
  appendDebtFindings(lines, debt.findings, false);
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

function appendMarkdownFindingsBySeverity(lines, findings) {
  lines.push("## Findings", "");
  for (const severity of SEVERITIES) {
    const group = findings.filter((finding) => finding.severity === severity);
    if (group.length === 0) {
      continue;
    }

    lines.push(`### ${severity.toUpperCase()}`, "");
    for (const finding of group) {
      appendMarkdownFinding(lines, finding);
    }
  }
}

function appendMarkdownFindingsByCategory(lines, findings) {
  lines.push("## Findings By Category", "");
  for (const category of categoriesFor(findings)) {
    const group = sortFindings(findings.filter((finding) => (finding.category || "general") === category));
    lines.push(`### ${category}`, "");
    for (const finding of group) {
      appendMarkdownFinding(lines, finding);
    }
  }
}

function appendMarkdownFinding(lines, finding) {
  lines.push(`#### ${finding.title}`);
  lines.push("");
  lines.push(`- Rule: \`${finding.id}\``);
  lines.push(`- Severity: ${finding.severity}`);
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

function appendTextFindingsBySeverity(lines, findings, options) {
  for (const severity of SEVERITIES) {
    const group = findings.filter((finding) => finding.severity === severity);
    if (group.length === 0) {
      continue;
    }

    lines.push(`${severity.toUpperCase()} (${group.length})`);
    for (const finding of group) {
      appendTextFinding(lines, finding, options);
    }
    lines.push("");
  }
}

function appendTextFindingsByCategory(lines, findings, options) {
  for (const category of categoriesFor(findings)) {
    const group = sortFindings(findings.filter((finding) => (finding.category || "general") === category));
    lines.push(`${category} (${group.length})`);
    for (const finding of group) {
      appendTextFinding(lines, finding, options);
    }
    lines.push("");
  }
}

function appendTextFinding(lines, finding, options) {
  lines.push(`- ${finding.title}`);
  lines.push(`  Rule: ${finding.id}`);
  lines.push(`  Severity: ${finding.severity}`);
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

function appendBaselineDiffSection(lines, title, findings, markdown) {
  if (markdown) {
    lines.push(`## ${title}`, "");
    if (findings.length === 0) {
      lines.push("None.", "");
      return;
    }
    for (const finding of findings) {
      lines.push(`- **${finding.severity.toUpperCase()}** \`${formatLocation(finding)}\` ${finding.title} (\`${finding.id}\`)`);
    }
    lines.push("");
    return;
  }

  lines.push(`${title}:`);
  if (findings.length === 0) {
    lines.push("- none", "");
    return;
  }
  for (const finding of findings) {
    lines.push(`- [${finding.severity.toUpperCase()}] ${formatLocation(finding)} ${finding.title} (${finding.id})`);
  }
  lines.push("");
}

function appendDebtCounts(lines, title, counts, markdown) {
  lines.push(markdown ? `## ${title}` : `${title}:`, "");
  if (!counts?.length) {
    lines.push("- none", "");
    return;
  }

  for (const item of counts) {
    lines.push(`- ${markdown ? `\`${escapeMarkdown(item.key)}\`` : item.key}: ${item.count}`);
  }
  lines.push("");
}

function appendDebtFindings(lines, findings, markdown) {
  lines.push(markdown ? "## Findings" : "Findings:", "");
  if (!findings?.length) {
    lines.push("- none", "");
    return;
  }

  for (const finding of findings) {
    const age = formatAge(finding.ageDays);
    const location = formatLocation(finding);
    if (markdown) {
      lines.push(`- **${finding.severity.toUpperCase()}** \`${location}\` ${finding.title} (\`${finding.id}\`, age ${age})`);
    } else {
      lines.push(`- [${finding.severity.toUpperCase()}] ${location} ${finding.title} (${finding.id}, age ${age})`);
    }
  }
  lines.push("");
}

function categoriesFor(findings) {
  return [...new Set(findings.map((finding) => finding.category || "general"))].sort();
}

// sortFindings is imported from utils.js

function formatLocation(finding) {
  if (!finding.file) {
    return "(project)";
  }
  return finding.line ? `${finding.file}:${finding.line}` : finding.file;
}

// escapeMarkdown is imported from utils.js

function formatConfigPath(config = {}) {
  return config.configPath || "(defaults)";
}

function statusLabel(summary) {
  if (summary.high > 0) {
    return "action required";
  }

  if (summary.medium > 0) {
    return "review recommended";
  }

  if (summary.low > 0 || summary.info > 0) {
    return "ready with notes";
  }

  return "ready";
}

// Re-exported from utils.js for backward compatibility
export { utilToRelative as toRelative };

function formatDuration(durationMs) {
  if (typeof durationMs !== "number") {
    return "unknown";
  }

  if (durationMs < 1000) {
    return `${durationMs}ms`;
  }

  return `${(durationMs / 1000).toFixed(1)}s`;
}

function totalSkipped(filesSkipped = {}) {
  return Object.values(filesSkipped).reduce((total, count) => total + (Number(count) || 0), 0);
}

function formatSkippedFiles(filesSkipped = {}) {
  const total = totalSkipped(filesSkipped);
  const details = Object.entries(filesSkipped)
    .filter(([, count]) => count > 0)
    .map(([reason, count]) => `${SKIP_REASON_LABELS[reason] || reason}=${count}`)
    .join(" ");

  return details ? `${total} (${details})` : String(total);
}

function formatSeveritySummary(summary = {}) {
  return `high=${summary.high || 0} medium=${summary.medium || 0} low=${summary.low || 0} info=${summary.info || 0}`;
}

function formatAge(ageDays) {
  return typeof ageDays === "number" ? `${ageDays}d` : "unknown";
}

function topRisks(findings, limit = 5) {
  return sortFindings(findings).slice(0, limit);
}

function nextSteps(result) {
  const steps = [];

  if (result.configWarnings?.length) {
    steps.push("Fix configuration warnings before relying on CI gating; run agentready config validate .");
  }

  if (result.summary.high > 0) {
    steps.push("Fix high severity findings before giving an AI agent broad repository access.");
  }

  if (result.summary.medium > 0) {
    steps.push("Review medium severity findings and decide whether to fix, baseline, or explicitly configure exceptions.");
  }

  if (result.summary.high === 0 && result.summary.medium === 0 && result.summary.low === 0 && result.summary.info === 0) {
    if (!result.config?.configPath) {
      steps.push("Run agentready quickstart . to preview the recommended setup path.");
    } else {
      steps.push("Keep AgentReady in CI with agentready scan . --ci.");
    }
    steps.push("Run agentready scan . --format markdown --output agentready-report.md when you need a shareable report.");
  }

  if (result.baseline?.suppressed > 0) {
    steps.push("Review baseline debt periodically; commit baseline files only after human review.");
  } else if (result.summary.high + result.summary.medium > 0) {
    steps.push("Save a markdown report with agentready scan . --format markdown --output agentready-report.md for review.");
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
            uri: finding.file,
            uriBaseId: "PROJECTROOT"
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

function toSarifBaseUri(root) {
  const resolved = path.resolve(root || ".");
  const href = pathToFileURL(resolved).href;
  return href.endsWith("/") ? href : `${href}/`;
}

function toSarifRule(rule) {
  return {
    id: rule.id,
    name: rule.id,
    shortDescription: {
      text: rule.description
    },
    fullDescription: {
      text: rule.recommendation
    },
    helpUri: RULE_HELP_URI,
    help: {
      text: rule.why || rule.recommendation,
      markdown: `${rule.why || rule.recommendation}\n\n${rule.recommendation}`
    },
    defaultConfiguration: {
      level: toSarifLevel(rule.defaultSeverity)
    },
    properties: {
      category: rule.category || "general",
      precision: rule.defaultSeverity === "info" ? "medium" : "high",
      severity: rule.defaultSeverity,
      tags: [rule.category || "general", rule.defaultSeverity]
    }
  };
}

function toSarifLevel(severity) {
  if (severity === "high") {
    return "error";
  }

  if (severity === "medium") {
    return "warning";
  }

  if (severity === "low") {
    return "warning";
  }

  return "note";
}
