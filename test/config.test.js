import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { applyCliOverrides, loadConfig, matchesAnyPath, shouldFail } from "../src/config.js";
import { scanProject } from "../src/scanner.js";

test("loadConfig applies ignore rules, ignore paths, severity overrides, and fail threshold", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  await writeFile(
    path.join(root, ".agentready.json"),
    JSON.stringify({
      failOn: "high",
      ignoreRules: ["package.lifecycle_script"],
      ignorePaths: ["ignored/**"],
      severityOverrides: {
        "agent.missing_agentignore": "info"
      },
      maxFileBytes: 1024
    }),
    "utf8"
  );
  await writeFile(
    path.join(root, "package.json"),
    JSON.stringify({
      scripts: {
        postinstall: "node setup.js"
      }
    }),
    "utf8"
  );

  const { config } = await loadConfig(root);
  const result = await scanProject(root, { config });
  const ids = result.findings.map((finding) => finding.id);
  const missingAgentIgnore = result.findings.find((finding) => finding.id === "agent.missing_agentignore");

  assert.equal(config.failOn, "high");
  assert.equal(config.maxFileBytes, 1024);
  assert.equal(shouldFail(result.summary, config.failOn), false);
  assert.equal(ids.includes("package.lifecycle_script"), false);
  assert.equal(missingAgentIgnore?.severity, "info");
});

test("loadConfig trims configured ignore arrays", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  await writeFile(
    path.join(root, ".agentready.json"),
    JSON.stringify({
      ignoreRules: [" agent.missing_agents_md "],
      ignorePaths: [" ignored/** "]
    }),
    "utf8"
  );

  const { config } = await loadConfig(root);

  assert.deepEqual(config.ignoreRules, ["agent.missing_agents_md"]);
  assert.deepEqual(config.ignorePaths, ["ignored/**"]);
});

test("applyCliOverrides augments loaded config", () => {
  const config = applyCliOverrides(
    {
      ignorePaths: [],
      ignoreRules: [],
      severityOverrides: {},
      failOn: "medium",
      maxFileBytes: 524288
    },
    {
      ignorePaths: ["tmp/**"],
      ignoreRules: ["agent.missing_agents_md"],
      failOn: "none",
      maxFileSize: "4096"
    }
  );

  assert.deepEqual(config.ignorePaths, ["tmp/**"]);
  assert.deepEqual(config.ignoreRules, ["agent.missing_agents_md"]);
  assert.equal(config.failOn, "none");
  assert.equal(config.maxFileBytes, 4096);
});

test("applyCliOverrides trims CLI ignore values", () => {
  const config = applyCliOverrides(
    {
      ignorePaths: [],
      ignoreRules: [],
      severityOverrides: {},
      failOn: "medium",
      maxFileBytes: 524288
    },
    {
      ignorePaths: [" tmp/** "],
      ignoreRules: [" agent.missing_agents_md "]
    }
  );

  assert.deepEqual(config.ignorePaths, ["tmp/**"]);
  assert.deepEqual(config.ignoreRules, ["agent.missing_agents_md"]);
});

test("loadConfig warns on invalid maxFileBytes", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  await writeFile(
    path.join(root, ".agentready.json"),
    JSON.stringify({
      maxFileBytes: 0
    }),
    "utf8"
  );

  const { config, warnings } = await loadConfig(root);

  assert.equal(config.maxFileBytes, 524288);
  assert.deepEqual(warnings, ["maxFileBytes must be a positive integer and was ignored."]);
});

test("matchesAnyPath supports exact, directory, and glob-style patterns", () => {
  assert.equal(matchesAnyPath(["secrets"], "secrets/prod.env"), true);
  assert.equal(matchesAnyPath(["**/*.pem"], "private.pem"), true);
  assert.equal(matchesAnyPath(["**/*.pem"], "config/private.pem"), true);
  assert.equal(matchesAnyPath(["**/secrets/**"], "secrets/prod.env"), true);
  assert.equal(matchesAnyPath(["**/secrets/**"], "config/secrets/prod.env"), true);
  assert.equal(matchesAnyPath(["src/*.js"], "src/index.js"), true);
  assert.equal(matchesAnyPath(["src/*.js"], "src/nested/index.js"), false);
});

test("loadConfig reports unknown rule ids as warnings", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  await writeFile(
    path.join(root, ".agentready.json"),
    JSON.stringify({
      ignoreRules: ["missing.rule"],
      severityOverrides: {
        "also.missing": "low"
      }
    }),
    "utf8"
  );

  const { warnings } = await loadConfig(root);

  assert.deepEqual(warnings, [
    "Unknown rule id in ignoreRules: missing.rule",
    "Unknown rule id in severityOverrides: also.missing"
  ]);
});

test("loadConfig reports unknown top-level fields", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  await writeFile(
    path.join(root, ".agentready.json"),
    JSON.stringify({
      failon: "high",
      failOn: "medium"
    }),
    "utf8"
  );

  const { config, warnings } = await loadConfig(root);

  assert.equal(config.failOn, "medium");
  assert.deepEqual(warnings, ["Unknown configuration field ignored: failon"]);
});

test("loadConfig handles non-object configuration roots", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  await writeFile(path.join(root, ".agentready.json"), "[]", "utf8");

  const { config, warnings } = await loadConfig(root);

  assert.equal(config.failOn, "medium");
  assert.deepEqual(warnings, ["Configuration root must be an object; defaults were used."]);
});

test("matchesAnyPath supports ? single-character wildcard", () => {
  assert.ok(matchesAnyPath(["src/?.js"], "src/a.js"));
  assert.ok(!matchesAnyPath(["src/?.js"], "src/ab.js"));
  assert.ok(matchesAnyPath(["test-?.txt"], "test-1.txt"));
  assert.ok(!matchesAnyPath(["test-?.txt"], "test-12.txt"));
});

test("matchesAnyPath ? does not match path separator", () => {
  assert.ok(!matchesAnyPath(["src?file.js"], "src/file.js"));
});

test("matchesAnyPath handles combined ** and ? patterns", () => {
  assert.ok(matchesAnyPath(["**/?.js"], "deep/nested/a.js"));
  assert.ok(!matchesAnyPath(["**/?.js"], "deep/nested/ab.js"));
});
