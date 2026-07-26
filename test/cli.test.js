import { existsSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import os from "node:os";
import path from "node:path";
import { makeLifecycleProject, makeTempDir, repoPath, writeLifecyclePackage } from "./helpers.js";
import { test } from "node:test";
import assert from "node:assert/strict";

const execFileAsync = promisify(execFile);
const CLI_PATH = repoPath("bin", "agentready.js");

test("CLI CI mode fails on configured threshold and respects CLI ignores", async () => {
  const root = await makeLifecycleProject();

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
  const root = await makeLifecycleProject();

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
  const root = await makeTempDir();

  await assert.rejects(
    execFileAsync(process.execPath, [CLI_PATH, "scan", root, "--ignore-rule", "missing.rule"], {
      cwd: process.cwd()
    }),
    (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /Unknown rule id/);
      return true;
    }
  );
});

test("CLI rejects missing option values", async () => {
  const root = await makeTempDir();

  await assert.rejects(
    execFileAsync(process.execPath, [CLI_PATH, "scan", root, "--fail-on"], {
      cwd: process.cwd()
    }),
    (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /--fail-on requires a value/);
      return true;
    }
  );
});

test("CLI rejects invalid scan format before reading project config", async () => {
  const root = await makeTempDir();
  await writeFile(path.join(root, ".agentready.json"), "{", "utf8");

  await assert.rejects(
    execFileAsync(process.execPath, [CLI_PATH, "scan", root, "--format", "xml"], {
      cwd: process.cwd()
    }),
    (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /Unsupported format/);
      assert.doesNotMatch(error.stderr, /not valid JSON/);
      return true;
    }
  );
});

test("CLI rejects invalid fail threshold before reading project config", async () => {
  const root = await makeTempDir();
  await writeFile(path.join(root, ".agentready.json"), "{", "utf8");

  await assert.rejects(
    execFileAsync(process.execPath, [CLI_PATH, "scan", root, "--fail-on", "critical"], {
      cwd: process.cwd()
    }),
    (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /Unsupported fail threshold/);
      assert.doesNotMatch(error.stderr, /not valid JSON/);
      return true;
    }
  );
});

test("CLI rejects options that are not supported by a command", async () => {
  const root = await makeTempDir();

  await assert.rejects(
    execFileAsync(process.execPath, [CLI_PATH, "init", root, "--format", "json"], {
      cwd: process.cwd()
    }),
    (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /Option --format is not supported/);
      return true;
    }
  );
});

test("CLI baseline command writes a baseline usable by scan", async () => {
  const root = await makeTempDir();
  const baselinePath = path.join(root, ".agentready-baseline.json");
  await writeLifecyclePackage(root);

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

test("CLI baseline diff and prune manage stale baseline debt", async () => {
  const root = await makeTempDir();
  const baselinePath = path.join(root, ".agentready-baseline.json");
  await writeLifecyclePackage(root);

  await execFileAsync(process.execPath, [CLI_PATH, "baseline", root, "--output", baselinePath], {
    cwd: process.cwd()
  });

  await writeFile(path.join(root, "AGENTS.md"), "# AGENTS.md\n", "utf8");
  await writeFile(path.join(root, ".agentignore"), ".env\n", "utf8");
  await writeFile(path.join(root, "package.json"), JSON.stringify({ scripts: {} }), "utf8");

  const diff = await execFileAsync(
    process.execPath,
    [CLI_PATH, "baseline", "diff", root, "--baseline", baselinePath, "--format", "json"],
    {
      cwd: process.cwd()
    }
  );
  const parsedDiff = JSON.parse(diff.stdout);
  assert.equal(parsedDiff.summary.new, 0);
  assert.ok(parsedDiff.summary.stale > 0);

  const diffPath = path.join(root, "reports", "baseline-diff.md");
  await execFileAsync(
    process.execPath,
    [CLI_PATH, "baseline", "diff", root, "--baseline", baselinePath, "--format", "markdown", "--output", diffPath],
    {
      cwd: process.cwd()
    }
  );
  assert.equal(existsSync(diffPath), true);

  await execFileAsync(process.execPath, [CLI_PATH, "baseline", "prune", root, "--baseline", baselinePath], {
    cwd: process.cwd()
  });

  const pruned = JSON.parse(await readFile(baselinePath, "utf8"));
  assert.equal(pruned.findings.length, 0);
  assert.ok(pruned.removedEntries > 0);
});

test("CLI debt command reports reviewed baseline debt", async () => {
  const root = await makeTempDir();
  const baselinePath = path.join(root, ".agentready-baseline.json");
  await writeLifecyclePackage(root);

  await execFileAsync(process.execPath, [CLI_PATH, "baseline", root, "--output", baselinePath], {
    cwd: process.cwd()
  });

  const debt = await execFileAsync(
    process.execPath,
    [CLI_PATH, "debt", root, "--baseline", baselinePath, "--format", "json"],
    {
      cwd: process.cwd()
    }
  );
  const parsed = JSON.parse(debt.stdout);

  assert.equal(parsed.baselinePath, baselinePath);
  assert.ok(parsed.entries > 0);
  assert.ok(parsed.severity.medium >= 1);
  assert.ok(Array.isArray(parsed.byRule));
});

test("CLI doctor respects baseline suppression", async () => {
  const root = await makeTempDir();
  const baselinePath = path.join(root, ".agentready-baseline.json");
  await writeLifecyclePackage(root);

  await execFileAsync(process.execPath, [CLI_PATH, "baseline", root, "--output", baselinePath], {
    cwd: process.cwd()
  });

  const doctor = await execFileAsync(process.execPath, [CLI_PATH, "doctor", root, "--baseline", baselinePath], {
    cwd: process.cwd()
  });

  assert.match(doctor.stdout, /Baseline suppressed:/);
  assert.doesNotMatch(doctor.stdout, /package\.lifecycle_script/);
});

test("CLI baseline command creates missing output directories", async () => {
  const root = await makeTempDir();
  const baselinePath = path.join(root, "reports", "baselines", ".agentready-baseline.json");
  await writeLifecyclePackage(root);

  await execFileAsync(process.execPath, [CLI_PATH, "baseline", root, "--output", baselinePath], {
    cwd: process.cwd()
  });

  assert.equal(existsSync(baselinePath), true);
});

test("CLI reports missing scan target as a clean usage error", async () => {
  await assert.rejects(
    execFileAsync(process.execPath, [CLI_PATH, "scan", path.join(os.tmpdir(), `agentready-missing-${Date.now()}`)], {
      cwd: process.cwd()
    }),
    (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /Scan target does not exist/);
      // Usage errors must not dump a stack trace.
      assert.doesNotMatch(error.stderr, /at scanProject/);
      return true;
    }
  );
});

test("CLI version prints package version", async () => {
  const pkg = JSON.parse(await readFile(repoPath("package.json"), "utf8"));
  const result = await execFileAsync(process.execPath, [CLI_PATH, "version"], {
    cwd: process.cwd()
  });

  assert.equal(result.stdout.trim(), pkg.version);
});

test("CLI scan JSON output is parseable and includes schemaVersion", async () => {
  const root = await makeTempDir();
  const result = await execFileAsync(process.execPath, [CLI_PATH, "scan", root, "--format", "json"], {
    cwd: process.cwd()
  });
  const parsed = JSON.parse(result.stdout);

  assert.equal(parsed.schemaVersion, "1");
  assert.equal(typeof parsed.durationMs, "number");
});

test("CLI scan can cap detailed findings without changing summary counts", async () => {
  const root = await makeTempDir();
  await writeFile(
    path.join(root, "package.json"),
    JSON.stringify({
      scripts: {
        clean: "rm -rf /",
        postinstall: "node setup.js"
      }
    }),
    "utf8"
  );

  const result = await execFileAsync(
    process.execPath,
    [CLI_PATH, "scan", root, "--format", "json", "--max-findings", "1"],
    {
      cwd: process.cwd()
    }
  );
  const parsed = JSON.parse(result.stdout);

  assert.equal(parsed.findings.length, 1);
  assert.equal(parsed.report.displayedFindings, 1);
  assert.ok(parsed.report.totalFindings > 1);
  assert.equal(parsed.summary.high, 1);
});

test("CLI scan can cap scanned file size", async () => {
  const root = await makeTempDir();
  await writeFile(path.join(root, "large.js"), "console.log('too large');\n", "utf8");

  const result = await execFileAsync(
    process.execPath,
    [CLI_PATH, "scan", root, "--format", "json", "--max-file-size", "8"],
    {
      cwd: process.cwd()
    }
  );
  const parsed = JSON.parse(result.stdout);

  assert.equal(parsed.config.maxFileBytes, 8);
  assert.equal(parsed.filesSkipped.oversized, 1);
});

test("CLI scan supports summary-only and category grouping", async () => {
  const root = await makeLifecycleProject();

  const summaryOnly = await execFileAsync(
    process.execPath,
    [CLI_PATH, "scan", root, "--summary-only"],
    {
      cwd: process.cwd()
    }
  );
  assert.match(summaryOnly.stdout, /Findings hidden by --summary-only/);
  assert.doesNotMatch(summaryOnly.stdout, /package\.lifecycle_script/);

  const grouped = await execFileAsync(
    process.execPath,
    [CLI_PATH, "scan", root, "--format", "markdown", "--group-by", "category"],
    {
      cwd: process.cwd()
    }
  );
  assert.match(grouped.stdout, /## Findings By Category/);
  assert.match(grouped.stdout, /### package/);
});

test("CLI scan rejects invalid report control options", async () => {
  const root = await makeTempDir();

  await assert.rejects(
    execFileAsync(process.execPath, [CLI_PATH, "scan", root, "--max-findings", "many"], {
      cwd: process.cwd()
    }),
    (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /--max-findings requires/);
      return true;
    }
  );

  await assert.rejects(
    execFileAsync(process.execPath, [CLI_PATH, "scan", root, "--group-by", "rule"], {
      cwd: process.cwd()
    }),
    (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /Unsupported group-by/);
      return true;
    }
  );

  await assert.rejects(
    execFileAsync(process.execPath, [CLI_PATH, "scan", root, "--max-file-size", "0"], {
      cwd: process.cwd()
    }),
    (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /--max-file-size requires/);
      return true;
    }
  );
});

test("CLI scan output creates missing report directories", async () => {
  const root = await makeTempDir();
  const outputPath = path.join(root, "reports", "agentready", "report.md");

  await execFileAsync(process.execPath, [CLI_PATH, "scan", root, "--format", "markdown", "--output", outputPath], {
    cwd: process.cwd()
  });

  assert.equal(existsSync(outputPath), true);
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

test("CLI list-rules rejects invalid severity filters", async () => {
  await assert.rejects(
    execFileAsync(process.execPath, [CLI_PATH, "list-rules", "--severity", "critical"], {
      cwd: process.cwd()
    }),
    (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /Unsupported severity/);
      return true;
    }
  );
});

test("CLI list-rules rejects invalid category filters", async () => {
  await assert.rejects(
    execFileAsync(process.execPath, [CLI_PATH, "list-rules", "--category", "ci"], {
      cwd: process.cwd()
    }),
    (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /Unsupported category/);
      return true;
    }
  );
});

test("CLI config validate reports valid configuration", async () => {
  const root = await makeTempDir();
  await writeFile(path.join(root, ".agentready.json"), JSON.stringify({ failOn: "medium" }), "utf8");

  const result = await execFileAsync(process.execPath, [CLI_PATH, "config", "validate", root], {
    cwd: process.cwd()
  });

  assert.match(result.stdout, /Configuration is valid/);
});

test("CLI config validate exits with config code on warnings", async () => {
  const root = await makeTempDir();
  await writeFile(path.join(root, ".agentready.json"), JSON.stringify({ failon: "high" }), "utf8");

  await assert.rejects(
    execFileAsync(process.execPath, [CLI_PATH, "config", "validate", root], {
      cwd: process.cwd()
    }),
    (error) => {
      assert.equal(error.code, 3);
      assert.match(error.stdout, /Configuration loaded with 1 warning/);
      assert.match(error.stdout, /Unknown configuration field ignored: failon/);
      return true;
    }
  );
});

test("CLI init dry-run does not write files and supports CI preview", async () => {
  const root = await makeTempDir();
  const result = await execFileAsync(
    process.execPath,
    [CLI_PATH, "init", root, "--dry-run", "--preset", "strict", "--with-ci"],
    {
      cwd: process.cwd()
    }
  );

  assert.match(result.stdout, /Would create/);
  assert.match(result.stdout, /Run agentready config validate .+/);
  assert.doesNotMatch(result.stdout, /Run agentready config validate \.\r?\n/);
  assert.equal(existsSync(path.join(root, "AGENTS.md")), false);
  assert.equal(existsSync(path.join(root, ".github", "workflows", "agentready.yml")), false);
});

test("CLI init writes precise sensitive path patterns", async () => {
  const root = await makeTempDir();

  await execFileAsync(process.execPath, [CLI_PATH, "init", root], {
    cwd: process.cwd()
  });

  const agentignore = await readFile(path.join(root, ".agentignore"), "utf8");
  const agents = await readFile(path.join(root, "AGENTS.md"), "utf8");
  const config = JSON.parse(await readFile(path.join(root, ".agentready.json"), "utf8"));

  assert.match(agentignore, /^secrets\/$/m);
  assert.match(agentignore, /^\.npmrc$/m);
  assert.match(agentignore, /^\.pypirc$/m);
  assert.match(agentignore, /^\.netrc$/m);
  assert.match(agentignore, /^credentials\/$/m);
  assert.match(agentignore, /^\*\*\/secrets\/\*\*$/m);
  assert.match(agentignore, /^\*\*\/credentials\/\*\*$/m);
  assert.match(agentignore, /^\*\*\/private\/\*\*$/m);
  assert.match(agentignore, /^\*\*\/backups\/\*\*$/m);
  assert.doesNotMatch(agentignore, /^\*secret\*$/m);
  assert.doesNotMatch(agentignore, /^\*credential\*$/m);
  assert.match(agents, /^\- \*\*\/\*secret\*\.env$/m);
  assert.match(config.$schema, /agentready\.schema\.json$/);
  assert.equal(config.maxFileBytes, 524288);
});

test("CLI quickstart prints a zero-write setup path", async () => {
  const root = await makeTempDir();
  const result = await execFileAsync(process.execPath, [CLI_PATH, "quickstart", root], {
    cwd: process.cwd()
  });

  assert.match(result.stdout, /AgentReady Quickstart/);
  assert.match(result.stdout, /Configuration: missing/);
  assert.match(result.stdout, /Preview setup: npx @hephaestus-devkit\/agentready init .+ --dry-run --with-ci/);
  assert.doesNotMatch(result.stdout, /Preview setup: npx @hephaestus-devkit\/agentready init \. --dry-run --with-ci/);
  // Bare "npx agentready" would resolve to an unrelated registry package.
  assert.doesNotMatch(result.stdout, /npx agentready /);
  assert.equal(existsSync(path.join(root, "AGENTS.md")), false);
});

test("CLI badge reports score in all formats and rejects bad ones", async () => {
  const root = await makeLifecycleProject();

  const text = await execFileAsync(process.execPath, [CLI_PATH, "badge", root], {
    cwd: process.cwd()
  });
  assert.match(text.stdout, /Agent Readiness Score: 95\/100 \(ready\)/);
  assert.match(text.stdout, /img\.shields\.io\/badge\/AgentReady-Score_95-brightgreen/);

  const json = await execFileAsync(process.execPath, [CLI_PATH, "badge", root, "--format", "json"], {
    cwd: process.cwd()
  });
  const parsed = JSON.parse(json.stdout);
  assert.equal(parsed.score, 95);
  assert.equal(parsed.grade, "ready");
  assert.equal(parsed.deductions.medium, 4);
  assert.match(parsed.badgeMarkdown, /^!\[AgentReady Score: 95\]/);

  await assert.rejects(
    execFileAsync(process.execPath, [CLI_PATH, "badge", root, "--format", "svg"], {
      cwd: process.cwd()
    }),
    (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /Unsupported badge format/);
      return true;
    }
  );
});

test("CLI badge respects a committed baseline like scan does", async () => {
  const root = await makeLifecycleProject();
  const baselinePath = path.join(root, ".agentready-baseline.json");

  await execFileAsync(process.execPath, [CLI_PATH, "baseline", root, "--output", baselinePath], {
    cwd: process.cwd()
  });

  const badge = await execFileAsync(
    process.execPath,
    [CLI_PATH, "badge", root, "--format", "json", "--baseline", baselinePath],
    { cwd: process.cwd() }
  );
  assert.equal(JSON.parse(badge.stdout).score, 100);
});

test("CLI reports broken project config as a clean config error", async () => {
  const root = await makeTempDir();
  await writeFile(path.join(root, ".agentready.json"), "{", "utf8");

  await assert.rejects(
    execFileAsync(process.execPath, [CLI_PATH, "scan", root], { cwd: process.cwd() }),
    (error) => {
      assert.equal(error.code, 3);
      assert.match(error.stderr, /not valid JSON/);
      assert.doesNotMatch(error.stderr, /at .*cli\.js/);
      return true;
    }
  );
});

test("CLI reports missing --config file with config exit code", async () => {
  const root = await makeTempDir();

  await assert.rejects(
    execFileAsync(
      process.execPath,
      [CLI_PATH, "scan", root, "--config", path.join(root, "missing-config.json")],
      { cwd: process.cwd() }
    ),
    (error) => {
      assert.equal(error.code, 3);
      assert.match(error.stderr, /Config file not found/);
      return true;
    }
  );
});

test("CLI reports missing baseline file with config exit code", async () => {
  const root = await makeTempDir();

  await assert.rejects(
    execFileAsync(process.execPath, [CLI_PATH, "baseline", "diff", root], { cwd: process.cwd() }),
    (error) => {
      assert.equal(error.code, 3);
      assert.match(error.stderr, /Baseline file not found/);
      return true;
    }
  );
});

test("CLI accepts --option=value syntax", async () => {
  const root = await makeTempDir();

  const result = await execFileAsync(
    process.execPath,
    [CLI_PATH, "scan", root, "--format=json", "--max-findings=1"],
    { cwd: process.cwd() }
  );
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.schemaVersion, "1");
  assert.equal(parsed.report.maxFindings, 1);
});

test("CLI rejects unknown options and commands with usage errors", async () => {
  await assert.rejects(
    execFileAsync(process.execPath, [CLI_PATH, "scan", ".", "--nope"], { cwd: process.cwd() }),
    (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /Unknown option: --nope/);
      return true;
    }
  );

  await assert.rejects(
    execFileAsync(process.execPath, [CLI_PATH, "frobnicate"], { cwd: process.cwd() }),
    (error) => {
      assert.equal(error.code, 2);
      assert.match(error.stderr, /Unknown command: frobnicate/);
      return true;
    }
  );
});
