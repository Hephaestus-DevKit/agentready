import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { runDoctor } from "../src/doctor.js";

async function withTempDir(fn) {
  const dir = path.join(tmpdir(), `agentready-doctor-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  await mkdir(dir, { recursive: true });
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test("doctor checks Node.js version and workspace write access", async () => {
  await withTempDir(async (dir) => {
    await writeFile(path.join(dir, "AGENTS.md"), "# Agents", "utf8");
    await writeFile(path.join(dir, ".agentignore"), ".env\n", "utf8");
    await writeFile(path.join(dir, ".agentready.json"), JSON.stringify({ failOn: "medium" }), "utf8");

    const result = await runDoctor(dir);

    assert.ok(result.findings.length > 0);
    const nodeCheck = result.findings.find((f) => f.id === "doctor.node");
    assert.ok(nodeCheck, "should include Node.js runtime check");
    assert.equal(nodeCheck.severity, "info");
    assert.match(nodeCheck.evidence, /Node /);

    const writeCheck = result.findings.find((f) => f.id === "doctor.write");
    assert.ok(writeCheck, "should include write access check");
    assert.equal(writeCheck.severity, "info");

    assert.ok(result.summary);
    assert.equal(typeof result.summary.high, "number");
  });
});

test("doctor detects missing .git directory", async () => {
  await withTempDir(async (dir) => {
    await writeFile(path.join(dir, "AGENTS.md"), "# Agents", "utf8");
    await writeFile(path.join(dir, ".agentignore"), ".env\n", "utf8");

    const result = await runDoctor(dir);
    const gitCheck = result.findings.find((f) => f.id === "doctor.git");
    assert.ok(gitCheck, "should include git check");
    assert.match(gitCheck.evidence, /No .git directory/);
  });
});

test("doctor includes scan findings alongside environment checks", async () => {
  await withTempDir(async (dir) => {
    // No AGENTS.md → should surface as a finding from the scanner
    const result = await runDoctor(dir);
    const agentFinding = result.findings.find((f) => f.id === "agent.missing_agents_md");
    assert.ok(agentFinding, "should include scanner findings");
  });
});

test("doctor findings have fingerprints", async () => {
  await withTempDir(async (dir) => {
    const result = await runDoctor(dir);
    for (const finding of result.findings) {
      assert.ok(finding.fingerprint, `finding ${finding.id} should have a fingerprint`);
    }
  });
});
