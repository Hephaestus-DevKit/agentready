import { readFile } from "node:fs/promises";
import { repoPath } from "./helpers.js";
import { test } from "node:test";
import assert from "node:assert/strict";

// Repository workflows and the composite action pin external actions to full
// commit SHAs with a version comment, e.g. `owner/repo@<40-hex> # v7.0.1`.
const pinned = (action, versionPattern) =>
  new RegExp(`${action.replace(/[/.-]/g, "\\$&")}@[a-f0-9]{40} # ${versionPattern}`);

test("every external action reference in workflows and action.yml is SHA-pinned", async () => {
  const files = [
    repoPath(".github", "workflows", "ci.yml"),
    repoPath(".github", "workflows", "release.yml"),
    repoPath(".github", "workflows", "scorecard.yml"),
    repoPath("action.yml")
  ];

  for (const file of files) {
    const content = await readFile(file, "utf8");
    for (const match of content.matchAll(/^\s*(?:-\s*)?uses:\s*(.+)$/gm)) {
      const reference = match[1].trim();
      if (reference.startsWith("./")) {
        continue; // local composite action
      }
      assert.match(
        reference,
        /^[^@]+@[a-f0-9]{40} # v\d/,
        `${file}: "${reference}" must be pinned to a full commit SHA with a version comment`
      );
    }
  }
});

test("release workflow is configured for npm Trusted Publishing", async () => {
  const workflow = await readFile(repoPath(".github", "workflows", "release.yml"), "utf8");

  assert.match(workflow, /id-token:\s*write/);
  assert.match(workflow, pinned("actions/checkout", "v7"));
  assert.match(workflow, pinned("actions/setup-node", "v7"));
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
  const action = await readFile(repoPath("action.yml"), "utf8");

  assert.match(action, /max-file-size:/);
  assert.match(action, /AGENTREADY_INPUT_MAX_FILE_SIZE/);
  assert.match(action, /AGENTREADY_INPUT_UPLOAD_SARIF/);
  assert.match(action, /--max-file-size/);
  assert.match(action, /upload-sarif:/);
  assert.match(action, /upload-sarif requires format=sarif and output to be set/);
  assert.match(action, /inputs\.upload-sarif == 'true'\s*\|\|\s*inputs\.upload-sarif == '1'/);
  assert.match(action, /!cancelled\(\)\s*&&\s*\(inputs\.upload-sarif/);
  assert.match(action, pinned("github/codeql-action/upload-sarif", "v4"));
});

test("ci workflow uses the supported Node matrix and current action versions", async () => {
  const workflow = await readFile(repoPath(".github", "workflows", "ci.yml"), "utf8");

  assert.match(workflow, /node-version:\s*\[20,\s*22,\s*24\]/);
  assert.match(workflow, pinned("actions/checkout", "v7"));
  assert.match(workflow, pinned("actions/setup-node", "v7"));
  assert.match(workflow, pinned("actions/dependency-review-action", "v5"));
});

test("repository settings match CI matrix and trusted publisher fields", async () => {
  const settings = await readFile(repoPath("docs", "REPOSITORY_SETTINGS.md"), "utf8");

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
  const workflow = await readFile(repoPath(".github", "workflows", "scorecard.yml"), "utf8");

  assert.match(workflow, pinned("actions/checkout", "v7"));
  assert.match(workflow, pinned("ossf/scorecard-action", "v2\\.4\\.4"));
  assert.match(workflow, pinned("github/codeql-action/upload-sarif", "v4"));
  assert.match(workflow, /security-events:\s*write/);
});

test("init CI template uses current GitHub action versions", async () => {
  const source = await readFile(repoPath("src", "init.js"), "utf8");

  assert.match(source, /actions\/checkout@v7/);
  assert.match(source, /actions\/setup-node@v7/);
  assert.match(source, /github\/codeql-action\/upload-sarif@v4/);
  assert.doesNotMatch(source, /if:\s*always\(\)/);
  assert.match(source, /if:\s*\\\$\{\{\s*!cancelled\(\)\s*\}\}/);
});

test("init CI template runs the published scoped package via npx", async () => {
  const source = await readFile(repoPath("src", "init.js"), "utf8");
  const manifest = JSON.parse(await readFile(repoPath("package.json"), "utf8"));

  // The generated workflow has no install step, so npx fetches from the
  // registry: the package spec must match the real published name. A bare
  // "npx agentready" would run an unrelated package that squats the
  // unscoped name.
  assert.match(source, new RegExp(`npx ${manifest.name.replace(/[/\\]/g, "\\$&")} scan`));
  assert.doesNotMatch(source, /npx agentready /);
});

test("package exposes the market readiness gate", async () => {
  const manifest = JSON.parse(await readFile(repoPath("package.json"), "utf8"));

  assert.equal(manifest.scripts["market:check"], "node ./scripts/market-check.mjs");
  assert.equal(manifest.scripts.prepublishOnly, "npm run market:check");
  // The gate is repo-only tooling: it must not ship to npm consumers.
  assert.ok(!manifest.files.includes("scripts/"));
  assert.ok(!manifest.files.includes(".agentignore"));
});

test("market readiness gate guards recursive temp cleanup", async () => {
  const script = await readFile(repoPath("scripts", "market-check.mjs"), "utf8");

  assert.match(script, /function safeRemoveTempDir/);
  assert.match(script, /Refusing to remove unexpected temp path/);
  assert.match(script, /agentready-market-/);
  assert.match(script, /rmSync\(resolvedTempRoot,\s*\{\s*recursive:\s*true,\s*force:\s*true\s*\}\)/);
});

test("market readiness gate blocks stale public workflow patterns", async () => {
  const script = await readFile(repoPath("scripts", "market-check.mjs"), "utf8");

  assert.match(script, /actions\/checkout@/);
  assert.match(script, /actions\/setup-node@/);
  assert.match(script, /github\/codeql-action\/upload-sarif@/);
  assert.match(script, /ossf\/scorecard-action@/);
  assert.ok(script.includes('always\\\\(\\\\)'));
});
