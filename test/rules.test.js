import { readFile } from "node:fs/promises";
import { test } from "node:test";
import assert from "node:assert/strict";
import { repoPath } from "./helpers.js";
import { formatRules, RULE_CATALOG } from "../src/rules.js";

test("rule catalog exposes unique ids", () => {
  const ids = RULE_CATALOG.map((rule) => rule.id);
  assert.equal(new Set(ids).size, ids.length);
});

test("every catalog rule is documented in docs/RULES.md", async () => {
  const docs = await readFile(repoPath("docs", "RULES.md"), "utf8");
  for (const rule of RULE_CATALOG) {
    assert.ok(docs.includes(`\`${rule.id}\``), `docs/RULES.md is missing ${rule.id}`);
  }
});

test("formatRules supports json and markdown output", () => {
  const json = JSON.parse(formatRules("json"));
  const markdown = formatRules("markdown");

  assert.equal(json.length, RULE_CATALOG.length);
  assert.match(markdown, /AgentReady Rule Catalog/);
  assert.match(markdown, /package\.lifecycle_script/);
});
