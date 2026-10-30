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

// C0/C1 control characters except tab. Scanned repositories control finding
// titles, evidence, and file names, so printing them raw would let a hostile
// repo inject terminal escape sequences (screen clears, title changes).
const CONTROL_CHARS = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g;
const LINE_BREAKS = /\r\n|[\r\n\u2028\u2029]/g;

/**
 * Remove control characters so repository-controlled text is safe to print to
 * a terminal. Newlines are kept; callers that need a single line should use
 * escapeMarkdown or collapse them first.
 */
export function stripControlChars(value) {
  return String(value).replace(CONTROL_CHARS, "");
}

/**
 * Escape repository-controlled text for inline Markdown (table cells, list
 * items, headings). Neutralizes HTML, links/images, code spans, and table
 * cells, and collapses line breaks so the text cannot open a new block such as
 * a heading.
 */
export function escapeMarkdown(value) {
  return stripControlChars(String(value).replace(LINE_BREAKS, " "))
    .replace(/[\\`<>[\]|]/g, "\\$&");
}

/**
 * Wrap text in a Markdown code span that cannot be closed early: the fence is
 * one backtick longer than the longest backtick run inside the value.
 */
export function markdownCode(value) {
  const text = stripControlChars(String(value).replace(LINE_BREAKS, " "));
  const longestRun = Math.max(0, ...(text.match(/`+/g) || []).map((run) => run.length));
  const fence = "`".repeat(longestRun + 1);
  const padding = text.startsWith("`") || text.endsWith("`") ? " " : "";
  return `${fence}${padding}${text}${padding}${fence}`;
}

/**
 * Escape special regex characters in a string for use in new RegExp().
 */
export function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Major version of the running Node.js runtime.
 * Shared by doctor and quickstart runtime checks.
 */
export function nodeMajor() {
  return Number(process.versions.node.split(".")[0]);
}
