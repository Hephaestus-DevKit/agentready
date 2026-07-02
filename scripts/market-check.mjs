import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PKG = JSON.parse(readFileSync(path.join(ROOT, "package.json"), "utf8"));
const SKIPPED_DIRS = new Set([
  ".cache",
  ".git",
  ".gradle",
  ".hg",
  ".mypy_cache",
  ".next",
  ".nuxt",
  ".pytest_cache",
  ".svn",
  ".tox",
  ".turbo",
  ".venv",
  "__pycache__",
  "build",
  "coverage",
  "dist",
  "node_modules",
  "out",
  "target",
  "vendor",
  "venv"
]);
const SENSITIVE_SEGMENTS = new Set(["secrets", "credentials", "private", "backups"]);
const SENSITIVE_FILES = new Set([".env", ".envrc", ".npmrc", ".pypirc", ".netrc"]);
const FORBIDDEN_PATTERNS = [
  new RegExp(["PROJECT", "PLAN"].join("_")),
  new RegExp(["UX", "IMPROVEMENT", "PLAN"].join("_")),
  new RegExp(["APPLICATION", "BRIEF"].join("_")),
  new RegExp(["申请", "材料"].join("")),
  new RegExp(["Claude", "6"].join(" "), "i"),
  new RegExp(["claude", "6"].join(""), "i"),
  new RegExp(["market", "harvest"].join(" "), "i"),
  new RegExp(["收", "割"].join("")),
  new RegExp(["actions/checkout@", "v4"].join("")),
  new RegExp(["actions/setup-node@", "v4"].join("")),
  new RegExp(["github/codeql-action/upload-sarif@", "v3"].join("")),
  new RegExp(["ossf/scorecard-action@", "v2.4.0"].join("")),
  new RegExp(["if:\\s*", "always\\(\\)"].join("")),
  new RegExp(["TO", "DO"].join("")),
  new RegExp(["FIX", "ME"].join("")),
  new RegExp(["NPM", "TOKEN"].join("_"))
];

const checks = [
  ["verify", () => run("npm", ["run", "verify"])],
  ["packed tarball smoke", runTarballSmoke],
  ["markdown links", checkMarkdownLinks],
  ["public keyword scan", checkForbiddenKeywords],
  ["git diff whitespace", () => run("git", ["diff", "--check"])]
];

for (const [name, check] of checks) {
  process.stdout.write(`market:check ${name}... `);
  check();
  process.stdout.write("ok\n");
}

function run(command, args, options = {}) {
  const result = spawn(command, args, {
    cwd: ROOT,
    stdio: "pipe",
    encoding: "utf8",
    ...options
  });

  if (result.status !== 0) {
    const output = [result.stdout, result.stderr].filter(Boolean).join("\n").trim();
    throw new Error(`${command} ${args.join(" ")} failed${output ? `\n${output}` : ""}`);
  }

  return result.stdout;
}

function spawn(command, args, options) {
  if (command === "npm") {
    return spawnNpm(args, options);
  }
  return spawnSync(command, args, options);
}

function spawnNpm(args, options) {
  const npmExecPath = process.env.npm_execpath;
  if (npmExecPath && existsSync(npmExecPath)) {
    return spawnSync(process.execPath, [npmExecPath, ...args], options);
  }
  return spawnSync(process.platform === "win32" ? "npm.cmd" : "npm", args, options);
}

function runTarballSmoke() {
  const tempRoot = mkdtempSync(path.join(tmpdir(), "agentready-market-"));
  try {
    const packOutput = run("npm", ["pack", "--silent", "--pack-destination", tempRoot]);
    const tgzName = packOutput.trim().split(/\r?\n/).filter(Boolean).at(-1);
    if (!tgzName) {
      throw new Error("npm pack did not return a tarball name");
    }

    const project = path.join(tempRoot, "consumer");
    mkdirSync(project, { recursive: true });
    writeFileSync(path.join(project, "package.json"), `${JSON.stringify({ private: true, type: "module" })}\n`, "utf8");
    run("npm", ["install", "--silent", "--no-audit", "--no-fund", path.join(tempRoot, tgzName)], { cwd: project });

    const cli = path.join(project, "node_modules", "@Hephaestus-DevKit", "agentready", "bin", "agentready.js");
    const version = run(process.execPath, [cli, "version"], { cwd: project }).trim();
    const scan = JSON.parse(run(process.execPath, [cli, "scan", project, "--format", "json", "--summary-only"], { cwd: project }));
    if (version !== PKG.version || scan.schemaVersion !== "1") {
      throw new Error(`unexpected tarball smoke result version=${version} (expected ${PKG.version}) schema=${scan.schemaVersion}`);
    }
  } finally {
    safeRemoveTempDir(tempRoot);
  }
}

function safeRemoveTempDir(tempRoot) {
  const resolvedTempRoot = path.resolve(tempRoot);
  const resolvedSystemTemp = path.resolve(tmpdir());
  const expectedPrefix = `${resolvedSystemTemp}${path.sep}`;

  if (!resolvedTempRoot.startsWith(expectedPrefix) || !path.basename(resolvedTempRoot).startsWith("agentready-market-")) {
    throw new Error(`Refusing to remove unexpected temp path: ${resolvedTempRoot}`);
  }

  rmSync(resolvedTempRoot, { recursive: true, force: true });
}

function checkMarkdownLinks() {
  const failures = [];
  for (const file of publicFiles().filter((item) => item.endsWith(".md"))) {
    const content = readFileSync(file, "utf8");
    const linkPattern = /\[[^\]]+\]\((?!https?:|mailto:|#)([^)]+)\)/g;
    for (const match of content.matchAll(linkPattern)) {
      const rawTarget = match[1].split("#")[0];
      if (!rawTarget || rawTarget.startsWith("`")) {
        continue;
      }
      const target = rawTarget.replace(/^<|>$/g, "");
      const resolved = path.resolve(path.dirname(file), target);
      if (!existsSync(resolved)) {
        failures.push(`${toRelative(file)} -> ${target}`);
      }
    }
  }

  if (failures.length > 0) {
    throw new Error(`Broken local markdown links:\n${failures.join("\n")}`);
  }
}

function checkForbiddenKeywords() {
  const failures = [];
  for (const file of publicFiles()) {
    if (!isTextLike(file)) {
      continue;
    }
    const content = readFileSync(file, "utf8");
    for (const pattern of FORBIDDEN_PATTERNS) {
      if (pattern.test(content)) {
        failures.push(`${toRelative(file)} matched ${pattern}`);
      }
    }
  }

  if (failures.length > 0) {
    throw new Error(`Forbidden public-surface keywords found:\n${failures.join("\n")}`);
  }
}

function publicFiles(current = ROOT, files = []) {
  for (const entry of readdirSync(current, { withFileTypes: true })) {
    const fullPath = path.join(current, entry.name);
    const relative = toRelative(fullPath);
    if (shouldSkip(relative, entry)) {
      continue;
    }
    if (entry.isDirectory()) {
      publicFiles(fullPath, files);
    } else if (entry.isFile()) {
      files.push(fullPath);
    }
  }
  return files;
}

function shouldSkip(relative, entry) {
  const normalized = relative.replaceAll("\\", "/");
  const segments = normalized.split("/");
  if (entry.isDirectory() && SKIPPED_DIRS.has(entry.name)) {
    return true;
  }
  if (segments.some((segment) => SENSITIVE_SEGMENTS.has(segment))) {
    return true;
  }
  const basename = path.basename(normalized);
  if (SENSITIVE_FILES.has(basename) || /^\.env\./.test(basename)) {
    return true;
  }
  return /\.(pem|key|p12|pfx)$/i.test(basename);
}

function isTextLike(file) {
  const basename = path.basename(file);
  const extension = path.extname(file).toLowerCase();
  return (
    [
      ".js", ".mjs", ".cjs", ".json", ".md", ".yml", ".yaml",
      ".toml", ".txt", ".sh", ".bash", ".zsh", ".ps1",
      ".py", ".rb", ".ts", ".tsx", ".tf", ".hcl"
    ].includes(extension) ||
    ["Dockerfile", "dockerfile", "Makefile", "makefile", "Taskfile", "Justfile", "action.yml"].includes(basename)
  );
}

function toRelative(file) {
  return path.relative(ROOT, file).replaceAll("\\", "/");
}
