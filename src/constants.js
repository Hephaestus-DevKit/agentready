export const SEVERITIES = ["high", "medium", "low", "info"];

export const DEFAULT_IGNORED_DIRS = new Set([
  ".git",
  ".hg",
  ".svn",
  ".next",
  ".nuxt",
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

export const TEXT_EXTENSIONS = new Set([
  ".cjs",
  ".conf",
  ".env",
  ".ini",
  ".js",
  ".json",
  ".jsx",
  ".lock",
  ".md",
  ".mjs",
  ".ps1",
  ".py",
  ".rb",
  ".sh",
  ".toml",
  ".ts",
  ".tsx",
  ".txt",
  ".yaml",
  ".yml"
]);

export const MAX_FILE_BYTES = 512 * 1024;
