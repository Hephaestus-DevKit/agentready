import { mkdir, readFile, realpath, symlink, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { makeTempDir, repoPath } from "./helpers.js";
import { escapeMarkdown, markdownCode, stripControlChars } from "../src/utils.js";
import { formatCommandPath } from "../src/command-path.js";
import { formatMarkdown, formatSarif, formatText } from "../src/reporters.js";
import { summarizeBaselineDebt } from "../src/baseline.js";

const execFileAsync = promisify(execFile);
const CLI_PATH = repoPath("bin", "agentready.js");

function runCli(args, options = {}) {
  return execFileAsync(process.execPath, [CLI_PATH, ...args], options).then(
    (result) => ({ code: 0, ...result }),
    (error) => ({ code: error.code, stdout: error.stdout, stderr: error.stderr })
  );
}

async function makeProject(files) {
  const root = await makeTempDir("agentready-hardening-");
  for (const [name, content] of Object.entries(files)) {
    await mkdir(path.dirname(path.join(root, name)), { recursive: true });
    await writeFile(path.join(root, name), content, "utf8");
  }
  return root;
}

// -- SARIF --------------------------------------------------------------------

test("SARIF output is never truncated by report display limits", async () => {
  const root = await makeProject({ "run.sh": "sudo ls\n" });

  const full = await runCli(["scan", root, "--format", "sarif"]);
  const count = (output) => JSON.parse(output).runs[0].results.length;
  const expected = count(full.stdout);
  assert.ok(expected > 0);

  for (const extra of [["--summary-only"], ["--max-findings", "0"], ["--max-findings", "1"]]) {
    const limited = await runCli(["scan", root, "--format", "sarif", ...extra]);
    assert.equal(count(limited.stdout), expected, `${extra.join(" ")} must not drop SARIF results`);
  }
});

test("SARIF artifact URIs are percent-encoded per segment", () => {
  const sarif = JSON.parse(
    formatSarif({
      root: "/project",
      scannedAt: "2026-01-01T00:00:00.000Z",
      findings: [
        {
          id: "script.dangerous_command.sudo",
          severity: "medium",
          title: "Risky command detected",
          recommendation: "Review it.",
          file: "scripts/my script#1 %41.sh",
          line: 3
        }
      ]
    })
  );
  const uri = sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
  assert.equal(uri, "scripts/my%20script%231%20%2541.sh");
});

// -- CLI argument handling ----------------------------------------------------

test("scanning a file instead of a directory is a usage error, not a clean pass", async () => {
  const root = await makeProject({ "a.sh": "sudo ls\n" });
  const result = await runCli(["scan", path.join(root, "a.sh"), "--ci", "--quiet"]);
  assert.equal(result.code, 2);
  assert.match(result.stderr, /must be a directory/);
});

test("extra positional paths are rejected instead of silently ignored", async () => {
  const one = await makeProject({ "a.sh": "echo a\n" });
  const two = await makeProject({ "b.sh": "echo b\n" });
  const result = await runCli(["scan", one, two]);
  assert.equal(result.code, 2);
  assert.match(result.stderr, /at most one path/);
});

test("empty and non-decimal option values are rejected", async () => {
  const root = await makeProject({ "a.sh": "sudo ls\n" });
  for (const args of [["--max-findings="], ["--fail-on="], ["--format="], ["--max-findings", "1e1"], ["--max-findings", "0x10"], ["--max-findings", " "]]) {
    const result = await runCli(["scan", root, ...args]);
    assert.equal(result.code, 2, args.join(" "));
  }
  const ok = await runCli(["scan", root, "--max-findings", "0"]);
  assert.equal(ok.code, 0);
});

// -- report injection ---------------------------------------------------------

const HOSTILE = 'sudo ls "<img src=x onerror=alert(1)> [click](https://evil.example) ![t](https://evil.example/p.png) `x`"';

test("escapeMarkdown neutralizes HTML, links, code spans, and line breaks", () => {
  const escaped = escapeMarkdown('<b>[a](u)</b> `c`\n# H1\r\nnext|cell');
  assert.ok(!/(^|[^\\])[<>[\]`|]/.test(escaped), escaped);
  assert.ok(!/[\r\n]/.test(escaped));
  assert.equal(escapeMarkdown("a|b"), "a\\|b");
  assert.equal(escapeMarkdown("line1\nline2"), "line1 line2");
});

test("markdownCode uses a fence that the value cannot close", () => {
  assert.equal(markdownCode("a.sh:1"), "`a.sh:1`");
  assert.equal(markdownCode("a`b.yml:2"), "``a`b.yml:2``");
  assert.equal(markdownCode("`edge`"), "`` `edge` ``");
  assert.ok(!markdownCode("x\n# H1").includes("\n"));
});

test("markdown report does not render repository-controlled HTML or links", async () => {
  const root = await makeProject({ "run.sh": `${HOSTILE}\n` });
  const { stdout } = await runCli(["scan", root, "--format", "markdown"]);
  const evidence = stdout.split("\n").find((line) => line.startsWith("- Evidence:"));
  assert.ok(evidence);
  assert.ok(!/(^|[^\\])[<>[\]]/.test(evidence.slice("- Evidence:".length)), evidence);
});

test("markdown file names and titles cannot break out of their code span or heading", () => {
  const output = formatMarkdown({
    root: "/project",
    scannedAt: "2026-01-01T00:00:00.000Z",
    filesScanned: 1,
    summary: { high: 1, medium: 0, low: 0, info: 0 },
    config: {},
    findings: [
      {
        id: "script.dangerous_command.sudo",
        severity: "high",
        category: "shell",
        title: "<img src=x>\n# Injected heading",
        file: ".github/workflows/a`b.yml",
        line: 2,
        evidence: "x",
        recommendation: "Review it."
      }
    ]
  });
  assert.ok(!output.split("\n").some((line) => line.startsWith("# Injected")));
  assert.ok(output.includes("``.github/workflows/a`b.yml:2``"));
  assert.ok(!/(^|[^\\])</.test(output.replace(/``[^`]*`[^`]*``/g, "")), "no unescaped HTML tag outside code spans");
});

test("text report strips terminal control sequences from repository content", () => {
  const output = formatText({
    root: "/project",
    scannedAt: "2026-01-01T00:00:00.000Z",
    filesScanned: 1,
    summary: { high: 0, medium: 1, low: 0, info: 0 },
    config: {},
    findings: [
      {
        id: "script.dangerous_command.sudo",
        severity: "medium",
        category: "shell",
        title: "Risky\x1b[2J command",
        file: "evil\x1b]0;pwn\x07.sh",
        line: 1,
        evidence: 'sudo ls "\x1b[31m"',
        recommendation: "Review it."
      }
    ]
  });
  assert.ok(!/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/.test(output.replaceAll("\n", "")));
  assert.equal(stripControlChars("a\tb\nc\x1b\x07"), "a\tb\nc");
});

// -- shell-safe suggested commands --------------------------------------------

test("formatCommandPath quotes every shell metacharacter", { skip: process.platform === "win32" }, async () => {
  // Resolve symlinks (macOS tmpdir lives under /var -> /private/var) so the
  // cwd the process reports matches the paths built below.
  const root = await realpath(await makeTempDir("agentready-quote-"));
  const previousCwd = process.cwd();
  process.chdir(root);
  try {
    for (const name of ["a&b", "x;y", "(z)", "a|b", "a>b", "star*", "a!b", "a#b", "~home"]) {
      const target = path.join(root, name);
      assert.equal(formatCommandPath(target), `'./${name}'`, name);
    }
    assert.equal(formatCommandPath(path.join(root, "plain-dir_1.0")), "./plain-dir_1.0");
  } finally {
    process.chdir(previousCwd);
  }
});

// -- init safety --------------------------------------------------------------

test("init refuses to write through symbolic links", { skip: process.platform === "win32" }, async () => {
  const root = await makeTempDir("agentready-init-link-");
  const outside = await makeTempDir("agentready-init-outside-");
  const victim = path.join(outside, "victim.txt");
  await symlink(victim, path.join(root, "AGENTS.md"));
  await writeFile(path.join(outside, "keep.txt"), "original", "utf8");
  await symlink(path.join(outside, "keep.txt"), path.join(root, ".agentignore"));

  const result = await runCli(["init", root, "--force"]);
  assert.equal(result.code, 0);
  assert.match(result.stdout, /Skipped symbolic link AGENTS\.md/);
  assert.match(result.stdout, /Skipped symbolic link \.agentignore/);
  assert.equal(existsSync(victim), false, "dangling symlink target must not be created");
  assert.equal(await readFile(path.join(outside, "keep.txt"), "utf8"), "original");
});

test("init requires an existing directory, even for dry runs", async () => {
  const root = await makeTempDir("agentready-init-missing-");
  const missing = path.join(root, "nope", "sub");
  const result = await runCli(["init", missing, "--dry-run"]);
  assert.equal(result.code, 2);
  assert.match(result.stderr, /existing directory/);
  assert.equal(existsSync(path.join(root, "nope")), false);
});

// -- baseline robustness ------------------------------------------------------

test("a hand-edited baseline with non-string file fields does not crash debt", async () => {
  const root = await makeProject({ "a.sh": "echo a\n" });
  const baseline = path.join(root, "bad-baseline.json");
  await writeFile(
    baseline,
    JSON.stringify({ version: 1, generatedAt: "2026-01-01T00:00:00Z", findings: [{ fingerprint: "a", file: 5 }, { fingerprint: "b", file: 6, line: "x" }] }),
    "utf8"
  );
  const result = await runCli(["debt", root, "--baseline", baseline]);
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stdout, /Entries: 2/);
  assert.equal(typeof summarizeBaselineDebt, "function");
});
