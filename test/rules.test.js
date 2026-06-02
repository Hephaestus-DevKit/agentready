import { test } from "node:test";
import assert from "node:assert/strict";
import { formatRules, RULE_CATALOG } from "../src/rules.js";

test("rule catalog exposes unique ids", () => {
  const ids = RULE_CATALOG.map((rule) => rule.id);
  assert.equal(new Set(ids).size, ids.length);
});

test("formatRules supports json and markdown output", () => {
  const json = JSON.parse(formatRules("json"));
  const markdown = formatRules("markdown");

  assert.equal(json.length, RULE_CATALOG.length);
  assert.match(markdown, /AgentReady Rule Catalog/);
  assert.match(markdown, /package\.lifecycle_script/);
});
