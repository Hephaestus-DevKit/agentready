import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { runQuickstart } from "../src/onboarding.js";

async function withTempDir(fn) {
  const dir = path.join(tmpdir(), `agentready-quickstart-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  await mkdir(dir, { recursive: true });
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test("quickstart reports missing setup for bare directory", async () => {
  await withTempDir(async (dir) => {
    const result = await runQuickstart(dir);
    assert.ok(result.messages.some((m) => m.includes("missing")));
    assert.ok(result.messages.some((m) => m.includes("init")));
    assert.ok(result.messages.some((m) => m.includes("scan")));
  });
});

test("quickstart detects existing configuration", async () => {
  await withTempDir(async (dir) => {
    await writeFile(path.join(dir, ".agentready.json"), "{}", "utf8");
    await writeFile(path.join(dir, "AGENTS.md"), "# Agents", "utf8");
    await writeFile(path.join(dir, ".agentignore"), ".env\n", "utf8");

    const result = await runQuickstart(dir);
    assert.ok(result.messages.some((m) => m.includes(".agentready.json")));
    assert.ok(result.messages.some((m) => m.includes("validate")));
  });
});

test("quickstart detects pnpm package manager", async () => {
  await withTempDir(async (dir) => {
    await writeFile(path.join(dir, "pnpm-lock.yaml"), "", "utf8");
    const result = await runQuickstart(dir);
    assert.ok(result.messages.some((m) => m.includes("pnpm")));
  });
});

test("quickstart detects yarn package manager", async () => {
  await withTempDir(async (dir) => {
    await writeFile(path.join(dir, "yarn.lock"), "", "utf8");
    const result = await runQuickstart(dir);
    assert.ok(result.messages.some((m) => m.includes("yarn")));
  });
});

test("quickstart detects bun package manager", async () => {
  await withTempDir(async (dir) => {
    await writeFile(path.join(dir, "bun.lock"), "", "utf8");
    const result = await runQuickstart(dir);
    assert.ok(result.messages.some((m) => m.includes("bun")));
  });
});

test("quickstart detects GitHub Actions workflows", async () => {
  await withTempDir(async (dir) => {
    const workflowDir = path.join(dir, ".github", "workflows");
    await mkdir(workflowDir, { recursive: true });
    await writeFile(path.join(workflowDir, "ci.yml"), "name: ci", "utf8");

    const result = await runQuickstart(dir);
    assert.ok(result.messages.some((m) => m.includes("detected")));
  });
});
