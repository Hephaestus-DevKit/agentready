import { test } from "node:test";
import assert from "node:assert/strict";
import { calculateScore, formatBadgeUrl, formatBadgeMarkdown } from "../src/score.js";

// -- calculateScore -----------------------------------------------------------

test("perfect score when there are no findings", () => {
  const result = calculateScore([]);
  assert.equal(result.score, 100);
  assert.equal(result.grade, "ready");
  assert.equal(result.color, "brightgreen");
  assert.deepEqual(result.deductions, { high: 0, medium: 0, low: 0 });
});

test("high severity deducts 10 points per finding", () => {
  const findings = [{ severity: "high" }, { severity: "high" }];
  const { score, deductions } = calculateScore(findings);
  assert.equal(score, 80);
  assert.equal(deductions.high, 20);
});

test("medium severity deducts 4 points per finding", () => {
  const findings = [{ severity: "medium" }, { severity: "medium" }, { severity: "medium" }];
  const { score, deductions } = calculateScore(findings);
  assert.equal(score, 88);
  assert.equal(deductions.medium, 12);
});

test("low severity deducts 1 point per finding", () => {
  const findings = [{ severity: "low" }, { severity: "low" }];
  const { score, deductions } = calculateScore(findings);
  assert.equal(score, 98);
  assert.equal(deductions.low, 2);
});

test("info severity causes no deduction", () => {
  const findings = [{ severity: "info" }, { severity: "info" }, { severity: "info" }];
  const { score } = calculateScore(findings);
  assert.equal(score, 100);
});

test("mixed severities are deducted correctly", () => {
  const findings = [
    { severity: "high" },
    { severity: "medium" },
    { severity: "low" },
    { severity: "info" }
  ];
  // 100 - 10 - 4 - 1 - 0 = 85
  const { score, deductions } = calculateScore(findings);
  assert.equal(score, 85);
  assert.deepEqual(deductions, { high: 10, medium: 4, low: 1 });
});

test("score floors at 0, never goes negative", () => {
  const findings = Array.from({ length: 50 }, () => ({ severity: "high" }));
  const { score } = calculateScore(findings);
  assert.equal(score, 0);
});

// -- grade thresholds ---------------------------------------------------------

test("score 90 → grade ready (lower boundary)", () => {
  // 100 - 10 = 90 → one high finding
  const { grade, color } = calculateScore([{ severity: "high" }]);
  assert.equal(grade, "ready");
  assert.equal(color, "brightgreen");
});

test("score 89 → grade acceptable", () => {
  // 100 - 10 - 1 = 89
  const findings = [{ severity: "high" }, { severity: "low" }];
  const { grade, color } = calculateScore(findings);
  assert.equal(grade, "acceptable");
  assert.equal(color, "green");
});

test("score 70 → grade acceptable (lower boundary)", () => {
  // 100 - 30 = 70 → three high findings
  const findings = Array.from({ length: 3 }, () => ({ severity: "high" }));
  const { grade, color } = calculateScore(findings);
  assert.equal(grade, "acceptable");
  assert.equal(color, "green");
});

test("score 69 → grade needs-work", () => {
  // 100 - 30 - 1 = 69
  const findings = [
    ...Array.from({ length: 3 }, () => ({ severity: "high" })),
    { severity: "low" }
  ];
  const { grade, color } = calculateScore(findings);
  assert.equal(grade, "needs-work");
  assert.equal(color, "yellow");
});

test("score 50 → grade needs-work (lower boundary)", () => {
  // 100 - 50 = 50 → five high findings
  const findings = Array.from({ length: 5 }, () => ({ severity: "high" }));
  const { grade, color } = calculateScore(findings);
  assert.equal(grade, "needs-work");
  assert.equal(color, "yellow");
});

test("score 49 → grade at-risk", () => {
  // 100 - 50 - 1 = 49
  const findings = [
    ...Array.from({ length: 5 }, () => ({ severity: "high" })),
    { severity: "low" }
  ];
  const { grade, color } = calculateScore(findings);
  assert.equal(grade, "at-risk");
  assert.equal(color, "orange");
});

test("score 30 → grade at-risk (lower boundary)", () => {
  // 100 - 70 = 30 → seven high findings
  const findings = Array.from({ length: 7 }, () => ({ severity: "high" }));
  const { grade, color } = calculateScore(findings);
  assert.equal(grade, "at-risk");
  assert.equal(color, "orange");
});

test("score 29 → grade critical", () => {
  // 100 - 70 - 1 = 29
  const findings = [
    ...Array.from({ length: 7 }, () => ({ severity: "high" })),
    { severity: "low" }
  ];
  const { grade, color } = calculateScore(findings);
  assert.equal(grade, "critical");
  assert.equal(color, "red");
});

test("score 0 → grade critical", () => {
  const findings = Array.from({ length: 10 }, () => ({ severity: "high" }));
  const { grade, color } = calculateScore(findings);
  assert.equal(grade, "critical");
  assert.equal(color, "red");
});

// -- formatBadgeUrl / formatBadgeMarkdown -------------------------------------

test("formatBadgeUrl returns a shields.io URL", () => {
  const url = formatBadgeUrl(92, "brightgreen");
  assert.equal(url, "https://img.shields.io/badge/AgentReady-Score_92-brightgreen");
});

test("formatBadgeMarkdown returns markdown image embed", () => {
  const md = formatBadgeMarkdown(0, "red");
  assert.equal(
    md,
    "![AgentReady Score: 0](https://img.shields.io/badge/AgentReady-Score_0-red)"
  );
});
