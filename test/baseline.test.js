import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { loadBaseline, writeBaseline } from "../src/baseline.js";
import { scanProject } from "../src/scanner.js";

test("baseline suppresses matching findings by fingerprint", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  await writeFile(
    path.join(root, "package.json"),
    JSON.stringify({
      scripts: {
        postinstall: "node setup.js"
      }
    }),
    "utf8"
  );

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
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  const scan = await scanProject(root);
  const baselinePath = path.join(root, ".agentready-baseline.json");
  await writeBaseline(baselinePath, scan);

  const parsed = JSON.parse(await readFile(baselinePath, "utf8"));

  assert.equal(parsed.version, 1);
  assert.equal(parsed.findings.length, scan.findings.length);
  assert.match(parsed.findings[0].fingerprint, /^[a-f0-9]{24}$/);
});
