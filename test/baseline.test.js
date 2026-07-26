import { readFile, writeFile } from "node:fs/promises";
import { makeLifecycleProject, makeTempDir, writeLifecyclePackage } from "./helpers.js";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { diffBaseline, loadBaseline, loadBaselineFile, writeBaseline, writePrunedBaseline } from "../src/baseline.js";
import { scanProject } from "../src/scanner.js";

test("baseline suppresses matching findings by fingerprint", async () => {
  const root = await makeLifecycleProject();

  const firstScan = await scanProject(root);
  const baselinePath = path.join(root, ".agentready-baseline.json");
  await writeBaseline(baselinePath, firstScan);

  const baseline = await loadBaseline(root, ".agentready-baseline.json");
  const secondScan = await scanProject(root, { baseline });

  assert.ok(firstScan.findings.length > 0);
  assert.equal(secondScan.findings.length, 0);
  assert.equal(secondScan.baseline.suppressed, firstScan.findings.length);
});

test("writeBaseline stores stable finding metadata", async () => {
  const root = await makeTempDir();
  const scan = await scanProject(root);
  const baselinePath = path.join(root, ".agentready-baseline.json");
  await writeBaseline(baselinePath, scan);

  const parsed = JSON.parse(await readFile(baselinePath, "utf8"));

  assert.equal(parsed.version, 1);
  assert.equal(parsed.findings.length, scan.findings.length);
  assert.match(parsed.findings[0].fingerprint, /^[a-f0-9]{24}$/);
  assert.match(parsed.findings[0].firstSeenAt, /^\d{4}-\d{2}-\d{2}T/);
  assert.match(parsed.findings[0].lastSeenAt, /^\d{4}-\d{2}-\d{2}T/);
});

test("writePrunedBaseline preserves firstSeenAt and refreshes lastSeenAt", async () => {
  const root = await makeTempDir();
  const baselinePath = path.join(root, ".agentready-baseline.json");
  await writeLifecyclePackage(root);

  const scan = await scanProject(root);
  await writeBaseline(baselinePath, scan);

  const original = JSON.parse(await readFile(baselinePath, "utf8"));
  original.findings[0].firstSeenAt = "2026-01-01T00:00:00.000Z";
  await writeFile(baselinePath, `${JSON.stringify(original, null, 2)}\n`, "utf8");

  const loaded = await loadBaselineFile(root, ".agentready-baseline.json");
  const diff = diffBaseline(scan.findings, loaded);
  await writePrunedBaseline(baselinePath, diff);

  const pruned = JSON.parse(await readFile(baselinePath, "utf8"));
  const matching = pruned.findings.find((finding) => finding.fingerprint === original.findings[0].fingerprint);

  assert.equal(matching.firstSeenAt, "2026-01-01T00:00:00.000Z");
  assert.match(matching.lastSeenAt, /^\d{4}-\d{2}-\d{2}T/);
  assert.ok(pruned.entriesPreserved > 0);
});

test("loadBaseline rejects invalid baseline structure", async () => {
  const root = await makeTempDir();
  await writeFile(path.join(root, ".agentready-baseline.json"), "[]", "utf8");

  await assert.rejects(
    loadBaseline(root, ".agentready-baseline.json"),
    /Baseline file root must be an object/
  );
});

test("loadBaseline rejects missing findings array", async () => {
  const root = await makeTempDir();
  await writeFile(path.join(root, ".agentready-baseline.json"), "{\"version\":1}", "utf8");

  await assert.rejects(
    loadBaseline(root, ".agentready-baseline.json"),
    /Baseline file must contain a findings array/
  );
});
