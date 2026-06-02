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
      }
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
  assert.equal(shouldFail(result.summary, config.failOn), false);
  assert.equal(ids.includes("package.lifecycle_script"), false);
  assert.equal(missingAgentIgnore?.severity, "info");
});

test("applyCliOverrides augments loaded config", () => {
  const config = applyCliOverrides(
    {
      ignorePaths: [],
      ignoreRules: [],
      severityOverrides: {},
      failOn: "medium"
    },
    {
      ignorePaths: ["tmp/**"],
      ignoreRules: ["agent.missing_agents_md"],
      failOn: "none"
    }
  );

  assert.deepEqual(config.ignorePaths, ["tmp/**"]);
  assert.deepEqual(config.ignoreRules, ["agent.missing_agents_md"]);
  assert.equal(config.failOn, "none");
});

test("matchesAnyPath supports exact, directory, and glob-style patterns", () => {
  assert.equal(matchesAnyPath(["secrets"], "secrets/prod.env"), true);
  assert.equal(matchesAnyPath(["**/*.pem"], "config/private.pem"), true);
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
