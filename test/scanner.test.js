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
            API_TOKEN: "abc123"
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

test("scanProject detects generic secret assignments in sensitive files", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-"));
  await writeFile(path.join(root, ".env"), "SERVICE_TOKEN=real-secret-value\nPLACEHOLDER_TOKEN=example\n", "utf8");

  const result = await scanProject(root);
  const finding = result.findings.find((item) => item.id === "secret.generic_assignment");

  assert.equal(finding?.file, ".env");
  assert.equal(finding?.line, 1);
  assert.equal(finding?.evidence, "SERVICE_TOKEN=[redacted]");
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
