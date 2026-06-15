import { test } from "node:test";
import assert from "node:assert/strict";
import { toRelative, summarizeSeverities, sortFindings, escapeMarkdown, escapeRegExp } from "../src/utils.js";
import path from "node:path";

test("toRelative produces forward-slash paths", () => {
  const root = path.resolve("/project");
  const file = path.join(root, "src", "index.js");
  const result = toRelative(root, file);
  assert.equal(result, "src/index.js");
  assert.ok(!result.includes("\\"));
});

test("toRelative returns empty string for root itself", () => {
  const root = path.resolve("/project");
  assert.equal(toRelative(root, root), "");
});

test("summarizeSeverities counts findings by severity", () => {
  const findings = [
    { severity: "high" },
    { severity: "high" },
    { severity: "medium" },
    { severity: "low" },
    { severity: "info" },
    { severity: "info" }
  ];
  const result = summarizeSeverities(findings);
  assert.deepStrictEqual(result, { high: 2, medium: 1, low: 1, info: 2 });
});

test("summarizeSeverities ignores unknown severity values", () => {
  const findings = [
    { severity: "high" },
    { severity: "critical" },
    { severity: "unknown" }
  ];
  const result = summarizeSeverities(findings);
  assert.deepStrictEqual(result, { high: 1, medium: 0, low: 0, info: 0 });
});

test("summarizeSeverities returns zeroes for empty findings", () => {
  const result = summarizeSeverities([]);
  assert.deepStrictEqual(result, { high: 0, medium: 0, low: 0, info: 0 });
});

test("sortFindings orders by severity then file then line", () => {
  const findings = [
    { severity: "low", file: "b.js", line: 1 },
    { severity: "high", file: "a.js", line: 10 },
    { severity: "high", file: "a.js", line: 1 },
    { severity: "medium", file: "c.js", line: 1 },
    { severity: "info", file: "d.js", line: 1 }
  ];
  const sorted = sortFindings(findings);
  assert.equal(sorted[0].severity, "high");
  assert.equal(sorted[0].line, 1);
  assert.equal(sorted[1].severity, "high");
  assert.equal(sorted[1].line, 10);
  assert.equal(sorted[2].severity, "medium");
  assert.equal(sorted[3].severity, "low");
  assert.equal(sorted[4].severity, "info");
});

test("sortFindings does not mutate the original array", () => {
  const findings = [
    { severity: "low", file: "b.js", line: 1 },
    { severity: "high", file: "a.js", line: 1 }
  ];
  const sorted = sortFindings(findings);
  assert.notStrictEqual(sorted, findings);
  assert.equal(findings[0].severity, "low");
});

test("escapeMarkdown escapes pipes and newlines", () => {
  assert.equal(escapeMarkdown("a|b"), "a\\|b");
  assert.equal(escapeMarkdown("line1\nline2"), "line1 line2");
  assert.equal(escapeMarkdown("a|b\nc|d"), "a\\|b c\\|d");
});

test("escapeRegExp escapes special regex characters", () => {
  assert.equal(escapeRegExp("file.js"), "file\\.js");
  assert.equal(escapeRegExp("a+b*c?d"), "a\\+b\\*c\\?d");
  assert.equal(escapeRegExp("(test)"), "\\(test\\)");
  assert.equal(escapeRegExp("[abc]"), "\\[abc\\]");
  assert.equal(escapeRegExp("a{1,2}"), "a\\{1,2\\}");
  assert.equal(escapeRegExp("$HOME"), "\\$HOME");
});
