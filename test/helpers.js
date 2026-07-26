import { rmSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Absolute path to the repository root, independent of the process cwd, so
 * `node --test test/foo.test.js` works from any directory.
 */
export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export function repoPath(...segments) {
  return path.join(REPO_ROOT, ...segments);
}

// Every temp dir is registered here and removed when the test process exits
// (node:test runs each file in its own process), so the suite cannot leak
// directories into os.tmpdir() no matter how a test ends.
const tempDirs = new Set();

process.on("exit", () => {
  for (const dir of tempDirs) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // Best effort: never let cleanup mask a test result.
    }
  }
});

export async function makeTempDir(prefix = "agentready-") {
  const dir = await mkdtemp(path.join(os.tmpdir(), prefix));
  tempDirs.add(dir);
  return dir;
}

/** Run `fn(dir)` in a fresh temp dir that is removed immediately afterwards. */
export async function withTempDir(fn, prefix) {
  const dir = await makeTempDir(prefix);
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
    tempDirs.delete(dir);
  }
}

/**
 * Write a package.json carrying a lifecycle script into `root` — the standard
 * fixture for a medium-severity `package.lifecycle_script` finding.
 */
export async function writeLifecyclePackage(root) {
  await writeFile(
    path.join(root, "package.json"),
    JSON.stringify({
      scripts: {
        postinstall: "node setup.js"
      }
    }),
    "utf8"
  );
}

/** Create a fresh temp project that already contains the lifecycle fixture. */
export async function makeLifecycleProject() {
  const root = await makeTempDir();
  await writeLifecyclePackage(root);
  return root;
}
