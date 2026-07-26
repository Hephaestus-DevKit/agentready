import { mkdir } from "node:fs/promises";
import { makeTempDir } from "./helpers.js";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { formatCommandPath } from "../src/command-path.js";

test("formatCommandPath quotes shell-sensitive paths literally", async () => {
  const previousCwd = process.cwd();
  const root = await makeTempDir("agentready-command-path-");
  const target = path.join(root, "project $HOME `date`");
  await mkdir(target);

  process.chdir(root);
  try {
    const formatted = formatCommandPath(target);

    if (process.platform === "win32") {
      // On Windows, double quotes are used (compatible with cmd.exe and PowerShell)
      assert.equal(formatted.startsWith('"'), true);
      assert.equal(formatted.endsWith('"'), true);
    } else {
      // On Unix, single quotes are used
      assert.equal(formatted.startsWith("'"), true);
      assert.equal(formatted.endsWith("'"), true);
    }

    assert.match(formatted, /\$HOME/);
    assert.match(formatted, /`date`/);
  } finally {
    process.chdir(previousCwd);
  }
});
