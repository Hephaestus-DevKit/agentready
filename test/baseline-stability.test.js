import { readFile, writeFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { makeTempDir, repoPath } from "./helpers.js";
import { addFingerprints } from "../src/fingerprint.js";

const execFileAsync = promisify(execFile);
const CLI_PATH = repoPath("bin", "agentready.js");

const run = (args) =>
  execFileAsync(process.execPath, [CLI_PATH, ...args]).then(
    (result) => ({ code: 0, ...result }),
    (error) => ({ code: error.code, stdout: error.stdout, stderr: error.stderr })
  );

async function project(script) {
  const root = await makeTempDir("agentready-stable-");
  await writeFile(path.join(root, "AGENTS.md"), "# Agents\n", "utf8");
  await writeFile(path.join(root, ".agentignore"), ".env\n", "utf8");
  await writeFile(path.join(root, "a.sh"), script, "utf8");
  return root;
}

// -- fingerprints -------------------------------------------------------------

test("stable fingerprint ignores line numbers; exact fingerprint does not", () => {
  const base = { id: "r", file: "a.sh", line: 1, evidence: "sudo ls", title: "t" };
  const [first] = addFingerprints([base]);
  const [moved] = addFingerprints([{ ...base, line: 9 }]);
  assert.notEqual(first.fingerprint, moved.fingerprint);
  assert.equal(first.stableFingerprint, moved.stableFingerprint);
});

test("repeated identical findings keep distinct stable fingerprints", () => {
  const base = { id: "r", file: "a.sh", evidence: "sudo ls", title: "t" };
  const [one, two] = addFingerprints([{ ...base, line: 1 }, { ...base, line: 2 }]);
  assert.notEqual(one.stableFingerprint, two.stableFingerprint);
});

// -- baseline survives line shifts --------------------------------------------

test("a baselined finding stays suppressed after lines are inserted above it", async () => {
  const root = await project("sudo ls\n");
  const baselinePath = path.join(root, ".agentready-baseline.json");
  assert.equal((await run(["baseline", root])).code, 0);

  await writeFile(path.join(root, "a.sh"), "# a new comment\n# another\nsudo ls\n", "utf8");

  const scan = await run(["scan", root, "--ci", "--baseline", baselinePath, "--quiet"]);
  assert.equal(scan.code, 0, scan.stdout);

  const diff = JSON.parse((await run(["baseline", "diff", root, "--baseline", baselinePath, "--format", "json"])).stdout);
  assert.equal(diff.summary.new, 0);
  assert.equal(diff.summary.stale, 0);
  assert.equal(diff.summary.matched, diff.summary.baseline);
});

test("a genuinely new finding is still reported alongside a shifted baselined one", async () => {
  const root = await project("sudo ls\n");
  const baselinePath = path.join(root, ".agentready-baseline.json");
  await run(["baseline", root]);

  await writeFile(path.join(root, "a.sh"), "# shift\nsudo ls\nsudo reboot\n", "utf8");
  const scan = await run(["scan", root, "--ci", "--baseline", baselinePath, "--quiet"]);
  assert.equal(scan.code, 1);
  assert.match(scan.stdout, /medium=1/);
});

test("baselines written before stable fingerprints still match exactly", async () => {
  const root = await project("sudo ls\n");
  const baselinePath = path.join(root, ".agentready-baseline.json");
  await run(["baseline", root]);

  const baseline = JSON.parse(await readFile(baselinePath, "utf8"));
  for (const entry of baseline.findings) {
    delete entry.stableFingerprint;
  }
  await writeFile(baselinePath, JSON.stringify(baseline), "utf8");

  const scan = await run(["scan", root, "--ci", "--baseline", baselinePath, "--quiet"]);
  assert.equal(scan.code, 0, scan.stdout);
});

test("regenerating a baseline preserves firstSeenAt", async () => {
  const root = await project("sudo ls\n");
  const baselinePath = path.join(root, ".agentready-baseline.json");
  await run(["baseline", root]);

  const baseline = JSON.parse(await readFile(baselinePath, "utf8"));
  for (const entry of baseline.findings) {
    entry.firstSeenAt = "2025-01-01T00:00:00.000Z";
  }
  await writeFile(baselinePath, JSON.stringify(baseline), "utf8");

  await run(["baseline", root]);
  const regenerated = JSON.parse(await readFile(baselinePath, "utf8"));
  assert.ok(regenerated.findings.length > 0);
  for (const entry of regenerated.findings) {
    assert.equal(entry.firstSeenAt, "2025-01-01T00:00:00.000Z");
    assert.notEqual(entry.lastSeenAt, "2025-01-01T00:00:00.000Z");
  }
});

// -- CLI conveniences ---------------------------------------------------------

test("baseline diff --ci fails only when new findings reach the threshold", async () => {
  const root = await project("echo ok\n");
  const baselinePath = path.join(root, ".agentready-baseline.json");
  await run(["baseline", root]);

  assert.equal((await run(["baseline", "diff", root, "--baseline", baselinePath, "--ci"])).code, 0);

  await writeFile(path.join(root, "a.sh"), "echo ok\nsudo reboot\n", "utf8");
  assert.equal((await run(["baseline", "diff", root, "--baseline", baselinePath])).code, 0, "without --ci diff stays informational");
  assert.equal((await run(["baseline", "diff", root, "--baseline", baselinePath, "--ci"])).code, 1);
  assert.equal((await run(["baseline", "diff", root, "--baseline", baselinePath, "--ci", "--fail-on", "high"])).code, 0);
});

test("--help on any command prints usage", async () => {
  for (const command of ["scan", "baseline", "init", "doctor"]) {
    const result = await run([command, "--help"]);
    assert.equal(result.code, 0, command);
    assert.match(result.stdout, /Usage:/);
  }
});
