import { existsSync } from "node:fs";
import { readFile, mkdtemp, writeFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";

const execFileAsync = promisify(execFile);
const CLI_PATH = path.resolve("bin/agentready.js");

test("CLI CI mode fails on configured threshold and respects CLI ignores", async () => {
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

  await assert.rejects(
    execFileAsync(process.execPath, [CLI_PATH, "scan", root, "--ci"], {
      cwd: process.cwd()
    })
  );

  const ignored = await execFileAsync(
    process.execPath,
    [CLI_PATH, "scan", root, "--ci", "--ignore-rule", "package.lifecycle_script"],
    {
      cwd: process.cwd()
    }
  );

  assert.match(ignored.stdout, /No findings detected|INFO|LOW/);
});

test("CLI fail-on high allows medium findings", async () => {
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

  const result = await execFileAsync(
    process.execPath,
    [CLI_PATH, "scan", root, "--ci", "--fail-on", "high"],
    {
      cwd: process.cwd()
    }
  );

  assert.match(result.stdout, /package\.lifecycle_script/);
});

test("CLI rejects unknown ignored rule ids", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));

  await assert.rejects(
    execFileAsync(process.execPath, [CLI_PATH, "scan", root, "--ignore-rule", "missing.rule"], {
      cwd: process.cwd()
    }),
    /Unknown rule id/
  );
});

test("CLI rejects missing option values", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));

  await assert.rejects(
    execFileAsync(process.execPath, [CLI_PATH, "scan", root, "--fail-on"], {
      cwd: process.cwd()
    }),
    /--fail-on requires a value/
  );
});

test("CLI baseline command writes a baseline usable by scan", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  const baselinePath = path.join(root, ".agentready-baseline.json");
  await writeFile(
    path.join(root, "package.json"),
    JSON.stringify({
      scripts: {
        postinstall: "node setup.js"
      }
    }),
    "utf8"
  );

  await execFileAsync(process.execPath, [CLI_PATH, "baseline", root, "--output", baselinePath], {
    cwd: process.cwd()
  });

  const baseline = JSON.parse(await readFile(baselinePath, "utf8"));
  assert.ok(baseline.findings.length > 0);

  const scan = await execFileAsync(
    process.execPath,
    [CLI_PATH, "scan", root, "--baseline", baselinePath, "--ci"],
    {
      cwd: process.cwd()
    }
  );

  assert.match(scan.stdout, /Baseline suppressed:/);
});

test("CLI version prints package version", async () => {
  const pkg = JSON.parse(await readFile(path.resolve("package.json"), "utf8"));
  const result = await execFileAsync(process.execPath, [CLI_PATH, "version"], {
    cwd: process.cwd()
  });

  assert.equal(result.stdout.trim(), pkg.version);
});

test("CLI scan JSON output is parseable and includes schemaVersion", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  const result = await execFileAsync(process.execPath, [CLI_PATH, "scan", root, "--format", "json"], {
    cwd: process.cwd()
  });
  const parsed = JSON.parse(result.stdout);

  assert.equal(parsed.schemaVersion, "1");
  assert.equal(typeof parsed.durationMs, "number");
});

test("CLI list-rules filters by category and severity", async () => {
  const result = await execFileAsync(
    process.execPath,
    [CLI_PATH, "list-rules", "--format", "json", "--category", "github-actions", "--severity", "high"],
    {
      cwd: process.cwd()
    }
  );
  const rules = JSON.parse(result.stdout);

  assert.ok(rules.length > 0);
  assert.ok(rules.every((rule) => rule.category === "github-actions"));
  assert.ok(rules.every((rule) => rule.defaultSeverity === "high"));
});

test("CLI config validate reports valid configuration", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  await writeFile(path.join(root, ".agentready.json"), JSON.stringify({ failOn: "medium" }), "utf8");

  const result = await execFileAsync(process.execPath, [CLI_PATH, "config", "validate", root], {
    cwd: process.cwd()
  });

  assert.match(result.stdout, /Configuration is valid/);
});

test("CLI init dry-run does not write files and supports CI preview", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  const result = await execFileAsync(
    process.execPath,
    [CLI_PATH, "init", root, "--dry-run", "--preset", "strict", "--with-ci"],
    {
      cwd: process.cwd()
    }
  );

  assert.match(result.stdout, /Would create/);
  assert.equal(existsSync(path.join(root, "AGENTS.md")), false);
  assert.equal(existsSync(path.join(root, ".github", "workflows", "agentready.yml")), false);
});
