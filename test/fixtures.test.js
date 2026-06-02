import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { scanProject } from "../src/scanner.js";

test("fixture: clean initialized project has no findings", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-clean-"));
  await writeFile(path.join(root, "AGENTS.md"), "# AGENTS.md\n", "utf8");
  await writeFile(path.join(root, ".agentignore"), ".env\n", "utf8");
  await writeFile(
    path.join(root, "package.json"),
    JSON.stringify({
      scripts: {
        test: "node --test"
      }
    }),
    "utf8"
  );

  const result = await scanProject(root);

  assert.deepEqual(result.summary, { high: 0, medium: 0, low: 0, info: 0 });
  assert.equal(result.findings.length, 0);
});

test("fixture: legacy project surfaces adoption and baseline-worthy findings", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-legacy-"));
  await writeFile(path.join(root, ".env"), "SERVICE_TOKEN=real-secret-value\n", "utf8");
  await writeFile(path.join(root, "requirements.txt"), "requests\n", "utf8");
  await writeFile(
    path.join(root, "package.json"),
    JSON.stringify({
      scripts: {
        postinstall: "node setup.js"
      }
    }),
    "utf8"
  );

  const result = await scanProject(root);
  const ids = result.findings.map((finding) => finding.id);

  assert.ok(ids.includes("agent.missing_agents_md"));
  assert.ok(ids.includes("agent.missing_agentignore"));
  assert.ok(ids.includes("secret.generic_assignment"));
  assert.ok(ids.includes("python.unpinned_requirement"));
  assert.ok(ids.includes("package.lifecycle_script"));
});

test("fixture: CI and MCP project surfaces agent toolchain risks", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "agentready-tooling-"));
  await writeFile(path.join(root, "AGENTS.md"), "# AGENTS.md\n", "utf8");
  await writeFile(path.join(root, ".agentignore"), ".env\n", "utf8");
  await writeFile(
    path.join(root, "mcp.json"),
    JSON.stringify({
      mcpServers: {
        shell: {
          command: "bash",
          args: ["-lc", "echo ok"]
        },
        filesystem: {
          command: "node",
          args: ["server.js", "/"]
        }
      }
    }),
    "utf8"
  );

  const workflowDir = path.join(root, ".github", "workflows");
  await mkdir(workflowDir, { recursive: true });
  await writeFile(
    path.join(workflowDir, "agent.yml"),
    ["name: agent", "on: pull_request_target", "permissions: write-all", "jobs:", "  test:", "    runs-on: ubuntu-latest", "    steps:", "      - run: sudo deploy"].join("\n"),
    "utf8"
  );

  const result = await scanProject(root);
  const ids = result.findings.map((finding) => finding.id);

  assert.ok(ids.includes("mcp.shell_tool"));
  assert.ok(ids.includes("mcp.broad_filesystem"));
  assert.ok(ids.includes("github_actions.pull_request_target"));
  assert.ok(ids.includes("github_actions.write_all"));
  assert.ok(ids.includes("github_actions.run.sudo"));
});
