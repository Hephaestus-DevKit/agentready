import { readFile } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";

test("release workflow is configured for npm Trusted Publishing", async () => {
  const workflow = await readFile(path.join(".github", "workflows", "release.yml"), "utf8");

  assert.match(workflow, /id-token:\s*write/);
  assert.match(workflow, /actions\/checkout@v7/);
  assert.match(workflow, /actions\/setup-node@v6/);
  assert.match(workflow, /node-version:\s*24/);
  assert.match(workflow, /package-manager-cache:\s*false/);
  assert.match(workflow, /Verify release tag matches package version/);
  assert.match(workflow, /RELEASE_TAG:\s*\$\{\{\s*github\.event\.release\.tag_name\s*\}\}/);
  assert.match(workflow, /expectedTag = "v" \+ packageJson\.version/);
  assert.match(workflow, /npm 11\.5\.1 or newer/);
  assert.match(workflow, /npm run market:check/);
  assert.match(workflow, /npm publish --provenance --access public/);
  assert.doesNotMatch(workflow, new RegExp(["NODE_AUTH_TOKEN", ["NPM", "TOKEN"].join("_")].join("|")));
});

test("composite action exposes scan-size and SARIF controls", async () => {
  const action = await readFile("action.yml", "utf8");

  assert.match(action, /max-file-size:/);
  assert.match(action, /AGENTREADY_INPUT_MAX_FILE_SIZE/);
  assert.match(action, /AGENTREADY_INPUT_UPLOAD_SARIF/);
  assert.match(action, /--max-file-size/);
  assert.match(action, /upload-sarif:/);
  assert.match(action, /upload-sarif requires format=sarif and output to be set/);
  assert.match(action, /inputs\.upload-sarif == 'true'\s*\|\|\s*inputs\.upload-sarif == '1'/);
  assert.match(action, /!cancelled\(\)\s*&&\s*\(inputs\.upload-sarif/);
  assert.match(action, /github\/codeql-action\/upload-sarif@v4/);
});

test("ci workflow uses the supported Node matrix and current action versions", async () => {
  const workflow = await readFile(path.join(".github", "workflows", "ci.yml"), "utf8");

  assert.match(workflow, /node-version:\s*\[20,\s*22,\s*24\]/);
  assert.doesNotMatch(workflow, /actions\/checkout@v4/);
  assert.doesNotMatch(workflow, /actions\/setup-node@v4/);
  assert.match(workflow, /actions\/checkout@v7/);
  assert.match(workflow, /actions\/setup-node@v6/);
  assert.match(workflow, /actions\/dependency-review-action@v4/);
});

test("repository settings match CI matrix and trusted publisher fields", async () => {
  const settings = await readFile(path.join("docs", "REPOSITORY_SETTINGS.md"), "utf8");

  for (const os of ["ubuntu-latest", "windows-latest", "macos-latest"]) {
    for (const nodeVersion of [20, 22, 24]) {
      assert.match(settings, new RegExp(`test \\(${os}, node ${nodeVersion}\\)`));
    }
  }

  assert.match(settings, /Workflow: `release\.yml`/);
  assert.match(settings, /release tag equals `v` plus/);
  assert.match(settings, /Keep the tag aligned with `package\.json` version/);
  assert.doesNotMatch(settings, /Workflow: `\.github\/workflows\/release\.yml`/);
});

test("scorecard workflow uploads SARIF with current action versions", async () => {
  const workflow = await readFile(path.join(".github", "workflows", "scorecard.yml"), "utf8");

  assert.match(workflow, /actions\/checkout@v7/);
  assert.match(workflow, /ossf\/scorecard-action@v2\.4\.3/);
  assert.match(workflow, /github\/codeql-action\/upload-sarif@v4/);
  assert.match(workflow, /security-events:\s*write/);
});

test("init CI template uses current GitHub action versions", async () => {
  const source = await readFile(path.join("src", "init.js"), "utf8");

  assert.match(source, /actions\/checkout@v7/);
  assert.match(source, /actions\/setup-node@v6/);
  assert.match(source, /github\/codeql-action\/upload-sarif@v4/);
  assert.doesNotMatch(source, /if:\s*always\(\)/);
  assert.match(source, /if:\s*\\\$\{\{\s*!cancelled\(\)\s*\}\}/);
});

test("package exposes the market readiness gate", async () => {
  const manifest = JSON.parse(await readFile("package.json", "utf8"));

  assert.equal(manifest.scripts["market:check"], "node ./scripts/market-check.mjs");
  assert.equal(manifest.scripts.prepublishOnly, "npm run market:check");
  assert.ok(manifest.files.includes("scripts/"));
});

test("market readiness gate guards recursive temp cleanup", async () => {
  const script = await readFile(path.join("scripts", "market-check.mjs"), "utf8");

  assert.match(script, /function safeRemoveTempDir/);
  assert.match(script, /Refusing to remove unexpected temp path/);
  assert.match(script, /agentready-market-/);
  assert.match(script, /rmSync\(resolvedTempRoot,\s*\{\s*recursive:\s*true,\s*force:\s*true\s*\}\)/);
});

test("market readiness gate blocks stale public workflow patterns", async () => {
  const script = await readFile(path.join("scripts", "market-check.mjs"), "utf8");

  assert.match(script, /actions\/checkout@/);
  assert.match(script, /actions\/setup-node@/);
  assert.match(script, /github\/codeql-action\/upload-sarif@/);
  assert.match(script, /ossf\/scorecard-action@/);
  assert.ok(script.includes('always\\\\(\\\\)'));
});
