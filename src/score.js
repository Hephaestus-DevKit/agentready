/**
 * Agent Readiness Score
 *
 * Computes a numeric score (0–100) from scan findings and maps it to a
 * human-readable grade with an associated colour suitable for shields.io
 * badges.
 */

/** Points deducted per finding, keyed by severity. */
const DEDUCTION_PER_SEVERITY = {
  high: 10,
  medium: 4,
  low: 1,
  info: 0
};

/** Grade thresholds, checked top-down (first match wins). */
const GRADE_TABLE = [
  { min: 90, grade: "ready",      color: "brightgreen" },
  { min: 70, grade: "acceptable", color: "green" },
  { min: 50, grade: "needs-work", color: "yellow" },
  { min: 30, grade: "at-risk",    color: "orange" },
  { min: 0,  grade: "critical",   color: "red" }
];

/**
 * Calculate an Agent Readiness Score from a list of findings.
 *
 * @param {Array<{ severity: string }>} findings
 * @returns {{ score: number, grade: string, color: string, deductions: { high: number, medium: number, low: number } }}
 */
export function calculateScore(findings) {
  const deductions = { high: 0, medium: 0, low: 0 };

  for (const finding of findings) {
    const points = DEDUCTION_PER_SEVERITY[finding.severity];
    if (points !== undefined && points > 0) {
      deductions[finding.severity] += points;
    }
  }

  const totalDeduction = deductions.high + deductions.medium + deductions.low;
  const score = Math.max(0, 100 - totalDeduction);

  const { grade, color } = GRADE_TABLE.find((entry) => score >= entry.min);

  return { score, grade, color, deductions };
}

/**
 * Build a shields.io badge URL for the given score.
 *
 * @param {number} score
 * @param {string} color
 * @returns {string}
 */
export function formatBadgeUrl(score, color) {
  return `https://img.shields.io/badge/AgentReady-Score_${score}-${color}`;
}

/**
 * Build a Markdown image embed for the shields.io badge.
 *
 * @param {number} score
 * @param {string} color
 * @returns {string}
 */
export function formatBadgeMarkdown(score, color) {
  return `![AgentReady Score: ${score}](${formatBadgeUrl(score, color)})`;
}
