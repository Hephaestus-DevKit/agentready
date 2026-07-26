import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Single source of truth for the tool version. Read once from package.json at
// module load so scanner results, reports (JSON/SARIF), and the `version`
// command all report the same real version instead of a hardcoded string.
const packagePath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "package.json");

export const TOOL_VERSION = JSON.parse(readFileSync(packagePath, "utf8")).version;
