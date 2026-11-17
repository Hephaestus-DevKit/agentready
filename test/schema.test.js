import { readFile } from "node:fs/promises";
import { makeTempDir, repoPath, writeLifecyclePackage } from "./helpers.js";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { formatJson } from "../src/reporters.js";
import { scanProject } from "../src/scanner.js";
import { runDoctor } from "../src/doctor.js";
import { runInit } from "../src/init.js";
import { diffBaseline, loadBaselineFile, writeBaseline, writePrunedBaseline } from "../src/baseline.js";

test("config schema matches starter config written by init", async () => {
  const schema = JSON.parse(await readFile(repoPath("schema", "agentready.schema.json"), "utf8"));
  const root = await makeTempDir("agentready-schema-");
  await runInit(root, { preset: "strict" });
  const generatedConfig = JSON.parse(await readFile(path.join(root, ".agentready.json"), "utf8"));

  assertContract(generatedConfig, schema);
});

test("scan and doctor result schemas match current JSON contract", async () => {
  const schema = JSON.parse(await readFile(repoPath("schema", "agentready-result.schema.json"), "utf8"));
  const root = await makeTempDir("agentready-schema-");
  const result = JSON.parse(formatJson(await scanProject(root)));
  const doctorResult = JSON.parse(formatJson(await runDoctor(root)));

  assert.equal(schema.properties.schemaVersion.const, result.schemaVersion);
  assertContract(result, schema);
  assertContract(doctorResult, schema);
});

test("baseline schema matches written and pruned baseline contracts", async () => {
  const schema = JSON.parse(await readFile(repoPath("schema", "agentready-baseline.schema.json"), "utf8"));
  const root = await makeTempDir("agentready-schema-");
  await writeLifecyclePackage(root);

  const scan = await scanProject(root);
  const baselinePath = path.join(root, ".agentready-baseline.json");
  const baseline = await writeBaseline(baselinePath, scan);
  assertContract(baseline, schema);

  const loaded = await loadBaselineFile(root, ".agentready-baseline.json");
  const pruned = await writePrunedBaseline(baselinePath, diffBaseline(scan.findings, loaded));
  assertContract(pruned, schema);
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

  if (typeof value === "number" && schema.minimum !== undefined) {
    assert.ok(value >= schema.minimum, `expected ${value} >= ${schema.minimum}`);
  }

  if (typeof value === "string" && schema.minLength !== undefined) {
    assert.ok(value.length >= schema.minLength, `expected length >= ${schema.minLength}`);
  }

  if (schema.type === "object" && value && typeof value === "object" && !Array.isArray(value)) {
    if (schema.additionalProperties === false && schema.properties) {
      for (const field of Object.keys(value)) {
        assert.ok(Object.hasOwn(schema.properties, field), `unexpected additional property: ${field}`);
      }
    }
    if (schema.properties) {
      for (const [field, childSchema] of Object.entries(schema.properties)) {
        if (value[field] !== undefined) {
          assertContract(value[field], childSchema, rootSchema);
        }
      }
    }
    if (schema.additionalProperties && typeof schema.additionalProperties === "object") {
      for (const [field, childValue] of Object.entries(value)) {
        if (!schema.properties || !Object.hasOwn(schema.properties, field)) {
          assertContract(childValue, schema.additionalProperties, rootSchema);
        }
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

