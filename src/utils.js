import path from "node:path";
import { SEVERITIES } from "./constants.js";

/**
 * Convert an absolute file path to a forward-slash relative path from root.
 */
export function toRelative(root, filePath) {
  return path.relative(root, filePath).replaceAll("\\", "/");
}

/**
 * Produce a severity count summary from a list of findings.
 * Shared by scanner, doctor, and baseline modules.
 */
export function summarizeSeverities(findings) {
  return findings.reduce(
    (summary, finding) => {
      // Guard against unknown severity values to avoid NaN
      if (Object.hasOwn(summary, finding.severity)) {
        summary[finding.severity] += 1;
      }
      return summary;
    },
    { high: 0, medium: 0, low: 0, info: 0 }
  );
}

/**
 * Sort findings by severity (high → info), then file path, then line number.
 */
export function sortFindings(findings) {
  const rank = new Map(SEVERITIES.map((severity, index) => [severity, index]));
  return [...findings].sort((left, right) => {
    const severityDelta = rank.get(left.severity) - rank.get(right.severity);
    if (severityDelta !== 0) {
      return severityDelta;
    }
    const fileDelta = String(left.file || "").localeCompare(String(right.file || ""));
    if (fileDelta !== 0) {
      return fileDelta;
    }
    return (left.line || 0) - (right.line || 0);
  });
}

/**
 * Escape pipe and newline characters for safe Markdown table cell content.
 */
export function escapeMarkdown(value) {
  return String(value).replaceAll("|", "\\|").replaceAll("\n", " ");
}

/**
 * Escape special regex characters in a string for use in new RegExp().
 */
export function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
