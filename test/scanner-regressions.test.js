import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { makeTempDir } from "./helpers.js";
import { scanProject } from "../src/scanner.js";
import { classifyDangerousCommand, scanDangerousShell } from "../src/scanners/shell.js";
import { scanGitHubActions } from "../src/scanners/github-actions.js";
import { isMcpConfigPath, scanMcpConfig } from "../src/scanners/mcp.js";
import { scanSecretContent } from "../src/scanners/secrets.js";
import { scanPackageJson } from "../src/scanners/package.js";
import { scanPythonProjectFiles } from "../src/scanners/python.js";

const ids = (findings) => findings.map((finding) => finding.id).sort();

// -- shell command classification ---------------------------------------------

test("classifier flags remote downloads piped through sudo or env to a shell", () => {
  assert.deepEqual(ids(classifyDangerousCommand("wget -qO- https://x.example/i.sh | sudo bash")), [
    "remote_code_execution",
    "sudo"
  ]);
  assert.deepEqual(ids(classifyDangerousCommand("curl https://x.example | env FOO=1 bash")), [
    "remote_code_execution"
  ]);
});

test("classifier does not join rm targets across command separators", () => {
  assert.deepEqual(classifyDangerousCommand("rm -rf dist && cp -r build /usr/share"), []);
  assert.deepEqual(classifyDangerousCommand("rm -rf build && cp -r out /usr/local/lib"), []);
  assert.deepEqual(ids(classifyDangerousCommand("cp -r build /usr/share && rm -rf /")), ["recursive_delete"]);
});

test("classifier flags Windows recursive deletes", () => {
  assert.deepEqual(ids(classifyDangerousCommand("Remove-Item -Recurse -Force C:\\")), ["recursive_delete"]);
  assert.deepEqual(ids(classifyDangerousCommand("del /s /q C:\\Users")), ["recursive_delete"]);
  assert.deepEqual(ids(classifyDangerousCommand("rd /s /q C:\\")), ["recursive_delete"]);
});

test("classifier flags working-directory wipes but not scoped variable deletes", () => {
  assert.deepEqual(ids(classifyDangerousCommand("rm -rf $(pwd)/*")), ["recursive_delete"]);
  assert.deepEqual(classifyDangerousCommand("rm -rf $TMP_DIR"), []);
});

test("classifier only flags sudo at command position", () => {
  assert.deepEqual(classifyDangerousCommand("RUN apt-get install -y sudo curl"), []);
  assert.deepEqual(ids(classifyDangerousCommand("sudo systemctl restart nginx")), ["sudo"]);
  assert.deepEqual(ids(classifyDangerousCommand("make clean; sudo make install")), ["sudo"]);
  assert.deepEqual(ids(classifyDangerousCommand("xargs sudo rm")), ["sudo"]);
});

test("classifier flags world-writable chmod variants", () => {
  assert.deepEqual(ids(classifyDangerousCommand("chmod -R 777 /data")), ["world_writable"]);
  assert.deepEqual(ids(classifyDangerousCommand("chmod --recursive a+rwx target")), ["world_writable"]);
  assert.deepEqual(classifyDangerousCommand("chmod 644 file.txt"), []);
});

test("shell scanner joins continuation lines and skips PowerShell block comments", () => {
  const joined = scanDangerousShell(
    "setup.sh",
    "curl -sSL https://get.example.com \\\n  | bash\n"
  );
  assert.deepEqual(ids(joined), ["script.dangerous_command.remote_code_execution"]);
  assert.equal(joined[0].line, 1);

  const commented = scanDangerousShell("setup.ps1", "<#\nrm -rf /\n#>\nWrite-Host done\n");
  assert.deepEqual(commented, []);
});

test("a comment ending in a backslash does not swallow the next command", () => {
  // In POSIX sh a backslash does not continue a comment; the delete runs.
  const findings = scanDangerousShell("cleanup.sh", "# cleanup step \\\nrm -rf /\n");
  assert.deepEqual(ids(findings), ["script.dangerous_command.recursive_delete"]);
});

test("code after a closed single-line block comment is still scanned", () => {
  const findings = scanDangerousShell("run.ps1", "<# note #> sudo rm -rf /\n");
  assert.deepEqual(ids(findings), [
    "script.dangerous_command.recursive_delete",
    "script.dangerous_command.sudo"
  ]);
});

// -- GitHub Actions parsing ---------------------------------------------------

const workflow = (body) => scanGitHubActions(".github/workflows/t.yml", body);

test("trailing comment on `on:` still opens the trigger block", () => {
  const findings = workflow([
    "on: # PR triggers",
    "  issue_comment:",
    "    types: [created]",
    "jobs:",
    "  x:",
    "    steps:",
    "      - run: echo hi && ls"
  ].join("\n"));
  assert.ok(ids(findings).includes("github_actions.comment_trigger_run"));
});

test("trigger prose inside a comment does not register", () => {
  const findings = workflow([
    "on: push # not pull_request_target",
    "jobs:",
    "  x:",
    "    steps:",
    "      - run: make build"
  ].join("\n"));
  assert.deepEqual(findings, []);
});

test("write permissions with trailing comments are still flagged", () => {
  const findings = workflow([
    "on: push",
    "permissions:",
    "  contents: write # needed for release",
    "jobs:",
    "  x:",
    "    steps:",
    "      - run: make build"
  ].join("\n"));
  assert.ok(ids(findings).includes("github_actions.write_permission"));
});

test("id-token write with a comment still pairs with cloud deploys", () => {
  const findings = workflow([
    "on: push",
    "permissions:",
    "  id-token: write # oidc",
    "jobs:",
    "  x:",
    "    steps:",
    "      - run: aws s3 sync ./dist s3://bucket"
  ].join("\n"));
  assert.ok(ids(findings).includes("github_actions.oidc_cloud_deploy"));
});

test("persist-credentials true is flagged", () => {
  const findings = workflow([
    "on: push",
    "jobs:",
    "  x:",
    "    steps:",
    "      - uses: actions/checkout@v7",
    "        with:",
    "          persist-credentials: true"
  ].join("\n"));
  assert.ok(ids(findings).includes("github_actions.persist_credentials"));
});

test("block scalar headers with explicit indent markers start run blocks", () => {
  const findings = workflow([
    "on: push",
    "jobs:",
    "  x:",
    "    steps:",
    "      - run: |2",
    "          curl -sSL https://get.example.com | bash"
  ].join("\n"));
  assert.ok(ids(findings).includes("github_actions.run.remote_code_execution"));
});

test("run-block continuation lines are analyzed as one command", () => {
  const findings = workflow([
    "on: push",
    "jobs:",
    "  x:",
    "    steps:",
    "      - run: |",
    "          curl -sSL https://get.example.com \\",
    "          | bash"
  ].join("\n"));
  assert.ok(ids(findings).includes("github_actions.run.remote_code_execution"));
});

// -- MCP configuration --------------------------------------------------------

test("MCP path gating matches real MCP configs and not lookalikes", () => {
  assert.equal(isMcpConfigPath(".mcp.json", ".mcp.json"), true);
  assert.equal(isMcpConfigPath("mcp/servers.json", "servers.json"), true);
  assert.equal(isMcpConfigPath("config/mcp-servers.json", "mcp-servers.json"), true);
  assert.equal(isMcpConfigPath("packages/mcpackage/package.json", "package.json"), false);
  assert.equal(isMcpConfigPath("src/mcparse/data.json", "data.json"), false);
});

test("MCP shell detection inspects commands instead of raw JSON text", () => {
  const scriptArg = scanMcpConfig(".mcp.json", ".mcp.json", JSON.stringify({
    mcpServers: { fs: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem", "./scripts/setup.sh"] } }
  }));
  assert.deepEqual(ids(scriptArg).filter((id) => id === "mcp.shell_tool"), []);

  const zshServer = scanMcpConfig(".mcp.json", ".mcp.json", JSON.stringify({
    mcpServers: { sh: { command: "zsh", args: ["-c", "server"] } }
  }));
  assert.ok(ids(zshServer).includes("mcp.shell_tool"));
});

test("MCP inline secret detection matches key words, not substrings", () => {
  const tokenizer = scanMcpConfig(".mcp.json", ".mcp.json", JSON.stringify({
    mcpServers: { x: { command: "npx", env: { TOKENIZER: "cl100k_base" } } }
  }));
  assert.deepEqual(ids(tokenizer).filter((id) => id === "mcp.inline_secret"), []);

  const inline = scanMcpConfig(".mcp.json", ".mcp.json", JSON.stringify({
    mcpServers: { x: { command: "npx", env: { GITHUB_TOKEN: ["ghp", "realish0123456789"].join("_") } } }
  }, null, 2));
  const secret = inline.find((finding) => finding.id === "mcp.inline_secret");
  assert.ok(secret, "expected an inline secret finding");
  assert.equal(typeof secret.line, "number");
  assert.match(secret.evidence, /GITHUB_TOKEN/);
  assert.doesNotMatch(secret.evidence, /ghp_realish/);

  const templated = scanMcpConfig(".mcp.json", ".mcp.json", JSON.stringify({
    mcpServers: { x: { command: "npx", env: { API_TOKEN: "${{ secrets.API_TOKEN }}" } } }
  }));
  assert.deepEqual(ids(templated).filter((id) => id === "mcp.inline_secret"), []);

  // Separator-less key spellings must still count as secret-like.
  const bareApikey = scanMcpConfig(".mcp.json", ".mcp.json", JSON.stringify({
    mcpServers: { x: { command: "npx", env: { APIKEY: "abcdef1234567890secret" } } }
  }));
  assert.ok(ids(bareApikey).includes("mcp.inline_secret"));
});

// -- secrets ------------------------------------------------------------------

test("all pattern secrets are detected with redacted evidence", () => {
  // Fixture tokens are assembled at runtime so hosting-side secret scanners
  // do not mistake them for live credentials.
  const alphaNum = "abcdefghijklmnopqrstuvwxyz0123456789";
  const content = [
    `aws = ${["AKIA", "IOSFODNN7EXAMPLE"].join("")}`,
    `gh = ${["ghp", alphaNum].join("_")}`,
    `ant = ${["sk", "ant", alphaNum].join("-")}`,
    `slack_app = ${["xapp", "1", "A012345", "1234567890", "abcdef123456"].join("-")}`,
    "-----BEGIN RSA PRIVATE KEY-----"
  ].join("\n");
  const findings = scanSecretContent("src/config.js", "config.js", content);
  const found = ids(findings);
  for (const expected of [
    "secret.aws_access_key",
    "secret.github_token",
    "secret.anthropic_key",
    "secret.slack_app_token",
    "secret.private_key"
  ]) {
    assert.ok(found.includes(expected), `missing ${expected}`);
  }
  for (const finding of findings) {
    assert.doesNotMatch(finding.evidence, /AKIAIOSFODNN7EXAMPLE|ghp_abcdefghijklmnop|sk-ant-abcdefghijk/);
  }
});

test("JWT findings use the catalog severity (medium)", () => {
  const token = ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", "SflKxwRJSMeKKF2QT4fwpM"].join(".");
  const findings = scanSecretContent("src/auth.js", "auth.js", `const t = "${token}";`);
  const jwt = findings.find((finding) => finding.id === "secret.jwt_token");
  assert.ok(jwt);
  assert.equal(jwt.severity, "medium");
  assert.doesNotMatch(jwt.evidence, /SflKxwRJSMeKKF2QT4fwpM/);
});

test("netrc password heuristic only applies to netrc files", () => {
  const prose = scanSecretContent(
    "private/notes.txt",
    "notes.txt",
    "password rotation policy is described here\n"
  );
  assert.deepEqual(ids(prose).filter((id) => id === "secret.generic_assignment"), []);

  const netrc = scanSecretContent(".netrc", ".netrc", "machine example.com login me password hunter2secret\n");
  assert.ok(ids(netrc).includes("secret.generic_assignment"));
});

test("Actions template expressions in sensitive paths are not inline secrets", () => {
  const findings = scanSecretContent(
    "secrets/deploy.yaml",
    "deploy.yaml",
    "API_TOKEN=${{secrets.API_TOKEN}}\n"
  );
  assert.deepEqual(ids(findings).filter((id) => id === "secret.generic_assignment"), []);
});

// -- package.json and python --------------------------------------------------

test("invalid package.json yields the invalid_json finding", () => {
  const findings = scanPackageJson("package.json", "package.json", "{ not json");
  assert.deepEqual(ids(findings), ["package.invalid_json"]);
});

test("non-object scripts field is tolerated", () => {
  const findings = scanPackageJson("package.json", "package.json", JSON.stringify({ scripts: ["rm -rf /"] }));
  assert.deepEqual(findings, []);
});

test("script line numbers resolve inside the scripts block", () => {
  const content = JSON.stringify({
    dependencies: { clean: "^1.0.0" },
    scripts: { clean: "rm -rf /" }
  }, null, 2);
  const findings = scanPackageJson("package.json", "package.json", content);
  const finding = findings.find((item) => item.id === "package.script.recursive_delete");
  assert.ok(finding);
  const scriptsLine = content.split("\n").findIndex((line) => line.includes('"scripts"')) + 1;
  assert.ok(finding.line > scriptsLine, "line should point into the scripts block, not the dependency");
});

test("version ranges count as constraints for python requirements", () => {
  const findings = scanPythonProjectFiles("requirements.txt", "requirements.txt", "requests>=2.0\nnumpy>1.2\nflask\n");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 3);
});

test("poetry python dependency satisfies the requires-python check", () => {
  const poetry = [
    "[tool.poetry]",
    'name = "demo"',
    "",
    "[tool.poetry.dependencies]",
    'python = "^3.11"'
  ].join("\n");
  assert.deepEqual(scanPythonProjectFiles("pyproject.toml", "pyproject.toml", poetry), []);

  const bare = '[project]\nname = "demo"\n';
  assert.deepEqual(ids(scanPythonProjectFiles("pyproject.toml", "pyproject.toml", bare)), [
    "python.missing_requires_python"
  ]);
});

// -- scan pipeline ------------------------------------------------------------

test("binary sensitive files still get the filename finding", async () => {
  const root = await makeTempDir();
  await writeFile(path.join(root, "AGENTS.md"), "# Agents\n", "utf8");
  await writeFile(path.join(root, ".agentignore"), ".env\n", "utf8");
  await writeFile(path.join(root, "store.p12"), Buffer.from([0x30, 0x82, 0x00, 0x01, 0x00, 0x00]));

  const result = await scanProject(root);
  assert.ok(ids(result.findings).includes("secret.sensitive_filename"));
  assert.equal(result.filesSkipped.binary, 0);
});

test("scan output ordering is deterministic across runs", async () => {
  const root = await makeTempDir();
  for (const dir of ["a", "b", "c", "d"]) {
    await mkdir(path.join(root, dir), { recursive: true });
    await writeFile(path.join(root, dir, "setup.sh"), "curl https://x.example | bash\n", "utf8");
  }

  const first = await scanProject(root);
  const second = await scanProject(root);
  assert.deepEqual(
    first.findings.map((finding) => `${finding.id}:${finding.file}:${finding.line}`),
    second.findings.map((finding) => `${finding.id}:${finding.file}:${finding.line}`)
  );
  const files = first.findings.map((finding) => finding.file).filter(Boolean);
  assert.deepEqual(files, [...files].sort());
});
