import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { scanProject } from "../src/scanner.js";

test("scanProject detects agent boundary gaps and risky scripts", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
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

  const result = await scanProject(root);
  const ids = result.findings.map((finding) => finding.id);

  assert.equal(result.schemaVersion, "1");
  assert.equal(typeof result.durationMs, "number");
  assert.equal(result.summary.high, 1);
  assert.ok(ids.includes("agent.missing_agents_md"));
  assert.ok(ids.includes("agent.missing_agentignore"));
  assert.ok(ids.includes("package.script.recursive_delete"));
  assert.ok(ids.includes("package.lifecycle_script"));
});

test("scanProject reports package lifecycle scripts at catalog severity", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  await writeFile(
    path.join(root, "package.json"),
    JSON.stringify({
      scripts: {
        prepare: "node prepare.js"
      }
    }),
    "utf8"
  );

  const result = await scanProject(root);
  const finding = result.findings.find((item) => item.id === "package.lifecycle_script");

  assert.equal(finding?.severity, "medium");
});

test("scanProject detects alternate recursive delete flag order and quoted targets", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  await writeFile(path.join(root, "clean.sh"), "rm -fr \"$HOME\"\n", "utf8");

  const result = await scanProject(root);
  const finding = result.findings.find((item) => item.id === "script.dangerous_command.recursive_delete");

  assert.equal(finding?.file, "clean.sh");
  assert.equal(finding?.evidence, "rm -fr \"$HOME\"");
});

test("scanProject scans alternate shell script extensions", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  await writeFile(path.join(root, "install.bash"), "curl https://example.com/install.sh | bash\n", "utf8");

  const result = await scanProject(root);
  const finding = result.findings.find((item) => item.id === "script.dangerous_command.remote_code_execution");

  assert.equal(finding?.file, "install.bash");
});

test("scanProject scans UTF-16 text files with a byte order mark", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  const content = Buffer.concat([
    Buffer.from([0xff, 0xfe]),
    Buffer.from("rm -rf /\n", "utf16le")
  ]);
  await writeFile(path.join(root, "cleanup.ps1"), content);

  const result = await scanProject(root);
  const finding = result.findings.find((item) => item.id === "script.dangerous_command.recursive_delete");

  assert.equal(result.filesSkipped.binary, 0);
  assert.equal(finding?.file, "cleanup.ps1");
});

test("scanProject scans common extensionless project files for risky commands", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  await writeFile(path.join(root, "Dockerfile"), "RUN curl https://example.com/install.sh | bash\n", "utf8");
  await writeFile(path.join(root, "Makefile"), "clean:\n\trm -rf /\n", "utf8");

  const result = await scanProject(root);
  const remote = result.findings.find((item) => item.id === "script.dangerous_command.remote_code_execution");
  const recursiveDelete = result.findings.find((item) => item.id === "script.dangerous_command.recursive_delete");

  assert.equal(remote?.file, "Dockerfile");
  assert.equal(recursiveDelete?.file, "Makefile");
});

test("scanProject reports skipped file statistics", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  await writeFile(path.join(root, "image.bin"), "binary-ish", "utf8");
  await writeFile(path.join(root, "binary.txt"), Buffer.from([0x61, 0x00, 0x62]));
  await writeFile(path.join(root, "large.txt"), "x".repeat(513 * 1024), "utf8");

  const result = await scanProject(root, {
    config: {
      ignorePaths: ["ignored/**"],
      ignoreRules: [],
      severityOverrides: {},
      failOn: "medium"
    }
  });

  assert.equal(result.filesSkipped.unsupportedType, 1);
  assert.equal(result.filesSkipped.oversized, 1);
  assert.equal(result.filesSkipped.binary, 1);
});

test("scanProject respects configured max file size", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  await writeFile(path.join(root, "large.js"), "console.log('too large');\n", "utf8");

  const result = await scanProject(root, {
    config: {
      ignorePaths: [],
      ignoreRules: [],
      severityOverrides: {},
      failOn: "medium",
      maxFileBytes: 8
    }
  });

  assert.equal(result.filesSkipped.oversized, 1);
});

test("scanProject detects MCP inline secrets and broad filesystem access", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  await writeFile(
    path.join(root, "mcp.json"),
    JSON.stringify({
      mcpServers: {
        filesystem: {
          command: "node",
          args: ["server.js", "C:\\"],
          env: {
            API_TOKEN: "abc123456789"
          }
        }
      }
    }),
    "utf8"
  );

  const result = await scanProject(root);
  const ids = result.findings.map((finding) => finding.id);

  assert.ok(ids.includes("mcp.broad_filesystem"));
  assert.ok(ids.includes("mcp.inline_secret"));
});

test("scanProject detects MCP remote, private network, and metadata URLs", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  await writeFile(
    path.join(root, "mcp.json"),
    JSON.stringify({
      mcpServers: {
        remote: {
          url: "https://mcp.example.com/sse"
        },
        local: {
          url: "http://192.168.1.10:8787/sse"
        },
        metadata: {
          url: "http://169.254.169.254/latest/meta-data"
        }
      }
    }),
    "utf8"
  );

  const result = await scanProject(root);
  const ids = result.findings.map((finding) => finding.id);

  assert.ok(ids.includes("mcp.remote_url"));
  assert.ok(ids.includes("mcp.private_network_url"));
  assert.ok(ids.includes("mcp.metadata_endpoint"));
});

test("scanProject treats IPv6 localhost MCP URLs as private network endpoints", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  await writeFile(
    path.join(root, "mcp.json"),
    JSON.stringify({
      mcpServers: {
        local: {
          url: "http://[::1]:8787/sse"
        }
      }
    }),
    "utf8"
  );

  const result = await scanProject(root);
  const ids = result.findings.map((finding) => finding.id);

  assert.ok(ids.includes("mcp.private_network_url"));
  assert.equal(ids.includes("mcp.remote_url"), false);
});

test("scanProject allows MCP environment variable secret references", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  await writeFile(
    path.join(root, "mcp.json"),
    JSON.stringify({
      mcpServers: {
        api: {
          command: "node",
          args: ["server.js"],
          env: {
            API_TOKEN: "${env:API_TOKEN}",
            PASSWORD: "%MCP_PASSWORD%"
          }
        }
      }
    }),
    "utf8"
  );

  const result = await scanProject(root);
  const ids = result.findings.map((finding) => finding.id);

  assert.equal(ids.includes("mcp.inline_secret"), false);
});

test("scanProject detects MCP authorization forwarding and OAuth client settings", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  await writeFile(
    path.join(root, "mcp.json"),
    JSON.stringify({
      mcpServers: {
        remote: {
          url: "https://mcp.example.com/sse",
          headers: {
            Authorization: "Bearer ${env:MCP_TOKEN}"
          },
          oauth: {
            authorizationUrl: "https://idp.example.com/oauth/authorize",
            tokenUrl: "https://idp.example.com/oauth/token",
            clientId: "${env:MCP_CLIENT_ID}",
            scopes: ["repo:read"]
          }
        }
      }
    }),
    "utf8"
  );

  const result = await scanProject(root);
  const ids = result.findings.map((finding) => finding.id);

  assert.ok(ids.includes("mcp.authorization_passthrough"));
  assert.ok(ids.includes("mcp.oauth_client_config"));
  assert.equal(ids.includes("mcp.inline_secret"), false);
});

test("scanProject detects Python reproducibility risks", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  await writeFile(path.join(root, "requirements.txt"), "requests\npytest==8.0.0\n", "utf8");

  const result = await scanProject(root);
  const finding = result.findings.find((item) => item.id === "python.unpinned_requirement");

  assert.equal(finding?.file, "requirements.txt");
  assert.equal(finding?.line, 1);
  assert.equal(finding?.category, "python");
  assert.match(finding?.why, /Pinned Python/);
});

test("scanProject ignores commented requires-python declarations", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  await writeFile(path.join(root, "pyproject.toml"), "# requires-python = \">=3.11\"\n[project]\nname = \"demo\"\n", "utf8");

  const result = await scanProject(root);
  const finding = result.findings.find((item) => item.id === "python.missing_requires_python");

  assert.equal(finding?.file, "pyproject.toml");
});

test("scanProject detects generic secret assignments in sensitive files", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  await writeFile(path.join(root, ".env"), "SERVICE_TOKEN=real-secret-value\nPLACEHOLDER_TOKEN=example\n", "utf8");

  const result = await scanProject(root);
  const finding = result.findings.find((item) => item.id === "secret.generic_assignment");

  assert.equal(finding?.file, ".env");
  assert.equal(finding?.line, 1);
  assert.equal(finding?.evidence, "SERVICE_TOKEN=[redacted]");
});

test("scanProject treats .envrc as a sensitive file", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  await writeFile(path.join(root, ".envrc"), "export SERVICE_TOKEN=real-secret-value\n", "utf8");

  const result = await scanProject(root);
  const generic = result.findings.find((item) => item.id === "secret.generic_assignment");
  const filename = result.findings.find((item) => item.id === "secret.sensitive_filename");

  assert.equal(generic?.file, ".envrc");
  assert.equal(filename?.file, ".envrc");
});

test("scanProject detects npmrc auth tokens", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  await writeFile(path.join(root, ".npmrc"), "//registry.npmjs.org/:_authToken=npm-token-value\n", "utf8");

  const result = await scanProject(root);
  const generic = result.findings.find((item) => item.id === "secret.generic_assignment");
  const filename = result.findings.find((item) => item.id === "secret.sensitive_filename");

  assert.equal(generic?.file, ".npmrc");
  assert.equal(generic?.evidence, "_authToken=[redacted]");
  assert.equal(filename?.file, ".npmrc");
});

test("scanProject detects netrc password values", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  await writeFile(path.join(root, ".netrc"), "machine example.com login user password netrc-secret-value\n", "utf8");

  const result = await scanProject(root);
  const generic = result.findings.find((item) => item.id === "secret.generic_assignment");

  assert.equal(generic?.file, ".netrc");
  assert.equal(generic?.evidence, "password=[redacted]");
});

test("scanProject detects generic secret assignments in sensitive directories", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  const secretsDir = path.join(root, "secrets");
  await mkdir(secretsDir, { recursive: true });
  await writeFile(path.join(secretsDir, "prod.json"), "{\"SERVICE_TOKEN\":\"real-secret-value\"}\n", "utf8");

  const result = await scanProject(root);
  const ids = result.findings.map((finding) => finding.id);
  const generic = result.findings.find((finding) => finding.id === "secret.generic_assignment");
  const filename = result.findings.find((finding) => finding.id === "secret.sensitive_filename" && finding.file === "secrets/prod.json");

  assert.ok(ids.includes("secret.generic_assignment"));
  assert.equal(generic?.file, "secrets/prod.json");
  assert.equal(filename?.evidence, "secrets/prod.json");
});

test("scanProject scans extensionless files in sensitive directories", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  const backupsDir = path.join(root, "backups");
  await mkdir(backupsDir, { recursive: true });
  await writeFile(path.join(backupsDir, "prod"), "SERVICE_TOKEN=real-secret-value\n", "utf8");

  const result = await scanProject(root);
  const finding = result.findings.find((item) => item.id === "secret.generic_assignment");

  assert.equal(finding?.file, "backups/prod");
  assert.equal(finding?.evidence, "SERVICE_TOKEN=[redacted]");
});

test("scanProject does not flag placeholder sensitive template filenames", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  await writeFile(path.join(root, "AGENTS.md"), "# AGENTS.md\n", "utf8");
  await writeFile(path.join(root, ".agentignore"), ".env\n", "utf8");
  await writeFile(path.join(root, ".env.example"), "SERVICE_TOKEN=your-token-here\n", "utf8");

  const result = await scanProject(root);
  const ids = result.findings.map((finding) => finding.id);

  assert.equal(ids.includes("secret.sensitive_filename"), false);
  assert.equal(ids.includes("secret.generic_assignment"), false);
});

test("scanProject still detects real assignments in sensitive template files", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  await writeFile(path.join(root, "AGENTS.md"), "# AGENTS.md\n", "utf8");
  await writeFile(path.join(root, ".agentignore"), ".env\n", "utf8");
  await writeFile(path.join(root, ".env.example"), "SERVICE_TOKEN=real-secret-value\n", "utf8");

  const result = await scanProject(root);
  const finding = result.findings.find((item) => item.id === "secret.generic_assignment");

  assert.equal(finding?.file, ".env.example");
  assert.equal(finding?.evidence, "SERVICE_TOKEN=[redacted]");
});

test("scanProject does not treat source files named secrets as sensitive files", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  const sourceDir = path.join(root, "src", "scanners");
  await mkdir(sourceDir, { recursive: true });
  await writeFile(path.join(root, "AGENTS.md"), "# AGENTS.md\n", "utf8");
  await writeFile(path.join(root, ".agentignore"), ".env\n", "utf8");
  await writeFile(path.join(sourceDir, "secrets.js"), "export const name = 'secrets';\n", "utf8");

  const result = await scanProject(root);
  const ids = result.findings.map((finding) => finding.id);

  assert.equal(ids.includes("secret.sensitive_filename"), false);
});

test("scanProject detects GitHub Actions permissions, inherited secrets, and risky run commands", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  const workflowDir = path.join(root, ".github", "workflows");
  await mkdir(workflowDir, { recursive: true });
  await writeFile(
    path.join(workflowDir, "ci.yml"),
    [
      "name: ci",
      "on: pull_request_target",
      "permissions:",
      "  contents: write",
      "jobs:",
      "  call:",
      "    uses: owner/repo/.github/workflows/reusable.yml@main",
      "    secrets: inherit",
      "  test:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - run: curl https://example.com/install.sh | bash",
      "      - run: |",
      "          sudo deploy"
    ].join("\n"),
    "utf8"
  );

  const result = await scanProject(root);
  const ids = result.findings.map((finding) => finding.id);

  assert.ok(ids.includes("github_actions.pull_request_target"));
  assert.ok(ids.includes("github_actions.write_permission"));
  assert.ok(ids.includes("github_actions.secrets_inherit"));
  assert.ok(ids.includes("github_actions.run.remote_code_execution"));
  assert.ok(ids.includes("github_actions.run.sudo"));
});

test("scanProject detects floating actions and pull_request_target checkout combinations", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  const workflowDir = path.join(root, ".github", "workflows");
  await mkdir(workflowDir, { recursive: true });
  await writeFile(
    path.join(workflowDir, "unsafe.yml"),
    [
      "name: unsafe",
      "on: pull_request_target",
      "jobs:",
      "  test:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - uses: actions/checkout@v6",
      "      - uses: owner/reusable/.github/workflows/reuse.yml@main"
    ].join("\n"),
    "utf8"
  );

  const result = await scanProject(root);
  const ids = result.findings.map((finding) => finding.id);

  assert.ok(ids.includes("github_actions.unpinned_action"));
  assert.ok(ids.includes("github_actions.pull_request_target_checkout"));
});

test("scanProject does not report pinned or local GitHub Actions references as floating", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  const workflowDir = path.join(root, ".github", "workflows");
  await mkdir(workflowDir, { recursive: true });
  await writeFile(
    path.join(workflowDir, "pinned.yml"),
    [
      "name: pinned",
      "on: push",
      "jobs:",
      "  test:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567",
      "      - uses: actions/setup-node@v6",
      "      - uses: ./.github/actions/local"
    ].join("\n"),
    "utf8"
  );

  const result = await scanProject(root);
  const ids = result.findings.map((finding) => finding.id);

  assert.equal(ids.includes("github_actions.unpinned_action"), false);
  assert.equal(ids.includes("github_actions.pull_request_target_checkout"), false);
});

test("scanProject detects workflow_run, comment-triggered commands, cache, artifacts, and OIDC deploy risks", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  const workflowDir = path.join(root, ".github", "workflows");
  await mkdir(workflowDir, { recursive: true });
  await writeFile(
    path.join(workflowDir, "advanced.yml"),
    [
      "name: advanced",
      "on:",
      "  workflow_run:",
      "  issue_comment:",
      "  pull_request:",
      "permissions:",
      "  id-token: write",
      "jobs:",
      "  test:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - uses: actions/cache@v4",
      "        with:",
      "          path: ~/.npm",
      "          key: npm-${{ hashFiles('package-lock.json') }}",
      "          restore-keys: npm-",
      "      - uses: actions/download-artifact@v4",
      "      - run: |",
      "          bash artifact/run.sh",
      "          aws deploy push"
    ].join("\n"),
    "utf8"
  );

  const result = await scanProject(root);
  const ids = result.findings.map((finding) => finding.id);

  assert.ok(ids.includes("github_actions.workflow_run"));
  assert.ok(ids.includes("github_actions.comment_trigger_run"));
  assert.ok(ids.includes("github_actions.cache_restore_pr"));
  assert.ok(ids.includes("github_actions.artifact_execution"));
  assert.ok(ids.includes("github_actions.oidc_cloud_deploy"));
});

test("scanProject avoids advanced GitHub Actions combination findings without risky combinations", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  const workflowDir = path.join(root, ".github", "workflows");
  await mkdir(workflowDir, { recursive: true });
  await writeFile(
    path.join(workflowDir, "ordinary.yml"),
    [
      "name: ordinary",
      "on: push",
      "permissions:",
      "  contents: read",
      "jobs:",
      "  test:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - uses: actions/cache@v4",
      "        with:",
      "          path: ~/.npm",
      "          key: npm-${{ hashFiles('package-lock.json') }}",
      "      - uses: actions/download-artifact@v4",
      "      - run: echo ok"
    ].join("\n"),
    "utf8"
  );

  const result = await scanProject(root);
  const ids = result.findings.map((finding) => finding.id);

  assert.equal(ids.includes("github_actions.workflow_run"), false);
  assert.equal(ids.includes("github_actions.comment_trigger_run"), false);
  assert.equal(ids.includes("github_actions.cache_restore_pr"), false);
  assert.equal(ids.includes("github_actions.artifact_execution"), false);
  assert.equal(ids.includes("github_actions.oidc_cloud_deploy"), false);
});

test("scanProject ignores commented risky shell and workflow lines", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  await writeFile(path.join(root, "AGENTS.md"), "# AGENTS.md\n", "utf8");
  await writeFile(path.join(root, ".agentignore"), ".env\n", "utf8");
  await writeFile(path.join(root, "deploy.sh"), "# rm -rf /\necho ok\n", "utf8");
  await writeFile(path.join(root, "cleanup.cmd"), "REM rm -rf /\n:: curl https://example.com/install.sh | bash\n", "utf8");

  const workflowDir = path.join(root, ".github", "workflows");
  await mkdir(workflowDir, { recursive: true });
  await writeFile(
    path.join(workflowDir, "comments.yml"),
    [
      "name: comments",
      "# on: pull_request_target",
      "on: push",
      "# permissions: write-all",
      "permissions:",
      "  contents: read",
      "jobs:",
      "  test:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - run: |",
      "          # curl https://example.com/install.sh | bash",
      "          echo ok"
    ].join("\n"),
    "utf8"
  );

  const result = await scanProject(root);
  const ids = result.findings.map((finding) => finding.id);

  assert.equal(ids.includes("script.dangerous_command.recursive_delete"), false);
  assert.equal(ids.includes("script.dangerous_command.remote_code_execution"), false);
  assert.equal(ids.includes("github_actions.pull_request_target"), false);
  assert.equal(ids.includes("github_actions.write_all"), false);
  assert.equal(ids.includes("github_actions.run.remote_code_execution"), false);
});

test("scanProject detects pull_request_target array and list trigger forms", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  const workflowDir = path.join(root, ".github", "workflows");
  await mkdir(workflowDir, { recursive: true });
  await writeFile(
    path.join(workflowDir, "array.yml"),
    ["name: array", "on: [push, pull_request_target]", "jobs:", "  test:", "    runs-on: ubuntu-latest", "    steps:", "      - run: echo ok"].join("\n"),
    "utf8"
  );
  await writeFile(
    path.join(workflowDir, "list.yml"),
    ["name: list", "on:", "  - push", "  - pull_request_target", "jobs:", "  test:", "    runs-on: ubuntu-latest", "    steps:", "      - run: echo ok"].join("\n"),
    "utf8"
  );

  const result = await scanProject(root);
  const findings = result.findings.filter((finding) => finding.id === "github_actions.pull_request_target");

  assert.equal(findings.length, 2);
  assert.deepEqual(
    findings.map((finding) => finding.file).sort(),
    [".github/workflows/array.yml", ".github/workflows/list.yml"]
  );
});

test("scanProject reports pull_request_target block trigger once", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  const workflowDir = path.join(root, ".github", "workflows");
  await mkdir(workflowDir, { recursive: true });
  await writeFile(
    path.join(workflowDir, "block.yml"),
    ["name: block", "on:", "  pull_request_target:", "jobs:", "  test:", "    runs-on: ubuntu-latest", "    steps:", "      - run: echo ok"].join("\n"),
    "utf8"
  );

  const result = await scanProject(root);
  const findings = result.findings.filter((finding) => finding.id === "github_actions.pull_request_target");

  assert.equal(findings.length, 1);
  assert.equal(findings[0].file, ".github/workflows/block.yml");
});

test("scanProject detects Stripe live API keys", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  await writeFile(path.join(root, "AGENTS.md"), "# Agents", "utf8");
  await writeFile(path.join(root, ".agentignore"), ".env\n", "utf8");
  await writeFile(path.join(root, "config.js"), "const key = \"" + "sk_live_" + "abcdefghijklmnopqrstuvwx\";\n", "utf8");

  const result = await scanProject(root);
  const ids = result.findings.map((f) => f.id);
  assert.ok(ids.includes("secret.stripe_key"), "should detect Stripe live key");
});

test("scanProject detects Google API keys", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  await writeFile(path.join(root, "AGENTS.md"), "# Agents", "utf8");
  await writeFile(path.join(root, ".agentignore"), ".env\n", "utf8");
  await writeFile(path.join(root, "config.js"), "const key = \"" + "AIzaSy" + "A1234567890abcdefghijklmnopqrstuv\";\n", "utf8");

  const result = await scanProject(root);
  const ids = result.findings.map((f) => f.id);
  assert.ok(ids.includes("secret.google_api_key"), "should detect Google API key");
});

test("scanProject detects Slack bot tokens", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  await writeFile(path.join(root, "AGENTS.md"), "# Agents", "utf8");
  await writeFile(path.join(root, ".agentignore"), ".env\n", "utf8");
  await writeFile(
    path.join(root, "config.js"),
    "const token = \"" + "xoxb-" + "1234567890-" + "1234567890123-" + "abcdefghijklmnopqrstuvwx\";\n",
    "utf8"
  );

  const result = await scanProject(root);
  const ids = result.findings.map((f) => f.id);
  assert.ok(ids.includes("secret.slack_token"), "should detect Slack bot token");
});

test("scanProject detects hardcoded JWT tokens", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  await writeFile(path.join(root, "AGENTS.md"), "# Agents", "utf8");
  await writeFile(path.join(root, ".agentignore"), ".env\n", "utf8");
  // Minimal valid-looking JWT
  const jwt = "eyJ" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
  await writeFile(path.join(root, "auth.js"), `const token = "${jwt}";\n`, "utf8");

  const result = await scanProject(root);
  const ids = result.findings.map((f) => f.id);
  assert.ok(ids.includes("secret.jwt_token"), "should detect JWT token");
});

test("scanProject rejects non-existent scan target", async () => {
  await assert.rejects(
    () => scanProject("/non/existent/path/agentready-test-" + Date.now()),
    /Scan target does not exist/
  );
});
