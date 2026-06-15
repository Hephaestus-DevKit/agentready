import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { runInit } from "../src/init.js";

async function withTempDir(fn) {
  const dir = path.join(tmpdir(), `agentready-init-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  await mkdir(dir, { recursive: true });
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test("init creates AGENTS.md, .agentignore, and .agentready.json", async () => {
  await withTempDir(async (dir) => {
    const result = await runInit(dir, { preset: "balanced" });
    assert.ok(existsSync(path.join(dir, "AGENTS.md")));
    assert.ok(existsSync(path.join(dir, ".agentignore")));
    assert.ok(existsSync(path.join(dir, ".agentready.json")));
    assert.ok(result.messages.some((m) => m.includes("Created")));
  });
});

test("init skips existing files without --force", async () => {
  await withTempDir(async (dir) => {
    await writeFile(path.join(dir, "AGENTS.md"), "custom agents doc", "utf8");
    const result = await runInit(dir, { preset: "balanced" });
    const content = await readFile(path.join(dir, "AGENTS.md"), "utf8");
    assert.equal(content, "custom agents doc");
    assert.ok(result.messages.some((m) => m.includes("Skipped")));
  });
});

test("init --force overwrites existing files", async () => {
  await withTempDir(async (dir) => {
    await writeFile(path.join(dir, "AGENTS.md"), "old content", "utf8");
    await runInit(dir, { preset: "balanced", force: true });
    const content = await readFile(path.join(dir, "AGENTS.md"), "utf8");
    assert.ok(content.includes("Agent Boundaries"));
    assert.notEqual(content, "old content");
  });
});

test("init --dry-run does not write files", async () => {
  await withTempDir(async (dir) => {
    const result = await runInit(dir, { preset: "balanced", dryRun: true });
    assert.ok(!existsSync(path.join(dir, "AGENTS.md")));
    assert.ok(!existsSync(path.join(dir, ".agentignore")));
    assert.ok(result.messages.some((m) => m.includes("Would create")));
  });
});

test("init --preset strict adds extra ignore patterns", async () => {
  await withTempDir(async (dir) => {
    await runInit(dir, { preset: "strict" });
    const agentignore = await readFile(path.join(dir, ".agentignore"), "utf8");
    assert.ok(agentignore.includes("*.sqlite"));
    assert.ok(agentignore.includes("*.db"));
  });
});

test("init --preset legacy sets failOn to high", async () => {
  await withTempDir(async (dir) => {
    await runInit(dir, { preset: "legacy" });
    const config = JSON.parse(await readFile(path.join(dir, ".agentready.json"), "utf8"));
    assert.equal(config.failOn, "high");
  });
});

test("init rejects invalid preset", async () => {
  await withTempDir(async (dir) => {
    await assert.rejects(() => runInit(dir, { preset: "invalid" }), /Unsupported preset/);
  });
});

test("init --with-ci creates workflow file", async () => {
  await withTempDir(async (dir) => {
    await runInit(dir, { preset: "balanced", withCi: true });
    const workflowPath = path.join(dir, ".github", "workflows", "agentready.yml");
    assert.ok(existsSync(workflowPath));
    const content = await readFile(workflowPath, "utf8");
    assert.ok(content.includes("agentready"));
  });
});
