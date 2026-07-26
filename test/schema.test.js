import { readFile, writeFile } from "node:fs/promises";
import { makeTempDir, repoPath, writeLifecyclePackage } from "./helpers.js";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { formatJson } from "../src/reporters.js";
import { scanProject } from "../src/scanner.js";
import { writeBaseline } from "../src/baseline.js";

test("scan result schema matches current JSON contract", async () => {
  const schema = JSON.parse(await readFile(repoPath("schema", "agentready-result.schema.json"), "utf8"));
  const root = await makeTempDir("agentready-schema-");
  const result = JSON.parse(formatJson(await scanProject(root)));

  assert.equal(schema.properties.schemaVersion.const, result.schemaVersion);
  assertContract(result, schema);
});

test("baseline schema matches current baseline contract", async () => {
  const schema = JSON.parse(await readFile(repoPath("schema", "agentready-baseline.schema.json"), "utf8"));
  const root = await makeTempDir("agentready-schema-");
  await writeLifecyclePackage(root);

  const scan = await scanProject(root);
  const baselinePath = path.join(root, ".agentready-baseline.json");
  const baseline = await writeBaseline(baselinePath, scan);

  assertContract(baseline, schema);
});

function assertContract(value, schema, rootSchema = schema) {
  if (schema.$ref) {
    assertContract(value, resolveRef(rootSchema, schema.$ref), rootSchema);
    return;
  }

  if (schema.required) {
    for (const field of schema.required) {
      assert.ok(Object.hasOwn(value, field), `missing required field: ${field}`);
    }
  }

  if (schema.const !== undefined) {
    assert.equal(value, schema.const);
  }

  if (schema.enum) {
    assert.ok(schema.enum.includes(value), `unexpected enum value: ${value}`);
  }

  if (schema.type) {
    assertType(value, schema.type);
  }

  if (schema.type === "object" && schema.properties && value && typeof value === "object") {
    for (const [field, childSchema] of Object.entries(schema.properties)) {
      if (value[field] !== undefined) {
        assertContract(value[field], childSchema, rootSchema);
      }
    }
  }

  if (schema.type === "array" && Array.isArray(value) && schema.items) {
    for (const item of value) {
      assertContract(item, schema.items, rootSchema);
    }
  }
}

function resolveRef(schema, ref) {
  const parts = ref.replace(/^#\//, "").split("/");
  return parts.reduce((current, part) => current[part], schema);
}

function assertType(value, type) {
  const types = Array.isArray(type) ? type : [type];
  const ok = types.some((candidate) => {
    if (candidate === "array") {
      return Array.isArray(value);
    }
    if (candidate === "integer") {
      return Number.isInteger(value);
    }
    if (candidate === "null") {
      return value === null;
    }
    return typeof value === candidate;
  });

  assert.equal(ok, true, `expected ${JSON.stringify(type)}, got ${typeof value}`);
}

