import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Single source of truth for the tool version and published package name.
// Read once from package.json at module load so scanner results, reports
// (JSON/SARIF), the `version` command, and user-facing install/run commands
// all agree with the real package instead of hardcoded strings.
const packagePath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "package.json");
const pkg = JSON.parse(readFileSync(packagePath, "utf8"));

export const TOOL_VERSION = pkg.version;
export const PACKAGE_NAME = pkg.name;
