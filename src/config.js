import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { MAX_FILE_BYTES, SEVERITIES } from "./constants.js";
import { configError, usageError } from "./errors.js";
import { RULE_CATALOG } from "./rules.js";
import { escapeRegExp } from "./scanners/utils.js";

export const CONFIG_FILE_NAMES = ["agentready.config.json", ".agentready.json"];
// Re-export as SEVERITY_ORDER for backward compatibility; SEVERITIES from constants is canonical
export const SEVERITY_ORDER = SEVERITIES;
export const FAIL_ON_VALUES = [...SEVERITIES, "none"];

export const DEFAULT_CONFIG = {
  baselinePath: null,
  ignorePaths: [],
  ignoreRules: [],
  severityOverrides: {},
  maxFileBytes: MAX_FILE_BYTES,
  failOn: "medium"
};

const KNOWN_CONFIG_FIELDS = new Set(["$schema", "baselinePath", "failOn", "ignorePaths", "ignoreRules", "severityOverrides", "maxFileBytes"]);
const KNOWN_RULE_IDS = new Set(RULE_CATALOG.map((rule) => rule.id));

export async function loadConfig(root, explicitPath = null) {
  const configPath = explicitPath ? path.resolve(explicitPath) : findConfigPath(root);

  if (!configPath) {
    return {
      config: { ...DEFAULT_CONFIG, configPath: null },
      warnings: []
    };
  }

  if (!existsSync(configPath)) {
    throw configError(`Config file not found: ${configPath}\nRun agentready init . to create a starter configuration.`);
  }

  const raw = await readFile(configPath, "utf8");
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw configError(`Config file is not valid JSON: ${configPath}\n${error.message}`);
  }

  const { config, warnings } = normalizeConfig(parsed);
  return {
    config: {
      ...config,
      configPath
    },
    warnings
  };
}

export function applyCliOverrides(config, options = {}) {
  const next = {
    ...config,
    ignorePaths: [...config.ignorePaths],
    ignoreRules: [...config.ignoreRules],
    severityOverrides: { ...config.severityOverrides }
  };
  next.maxFileBytes = config.maxFileBytes ?? DEFAULT_CONFIG.maxFileBytes;

  for (const rule of options.ignoreRules || []) {
    const normalizedRule = String(rule).trim();
    assertKnownRule(normalizedRule, "ignore-rule");
    next.ignoreRules.push(normalizedRule);
  }

  for (const pattern of options.ignorePaths || []) {
    const normalizedPattern = String(pattern).trim();
    if (normalizedPattern) {
      next.ignorePaths.push(normalizedPattern);
    }
  }

  if (options.failOn) {
    if (!FAIL_ON_VALUES.includes(options.failOn)) {
      throw usageError(`Unsupported fail threshold "${options.failOn}". Use ${FAIL_ON_VALUES.join(", ")}.`);
    }
    next.failOn = options.failOn;
  }

  if (options.maxFileSize !== undefined) {
    next.maxFileBytes = parsePositiveInteger(options.maxFileSize, "--max-file-size");
  }

  return next;
}

export function applyFindingConfig(findings, config = DEFAULT_CONFIG) {
  return findings
    .filter((finding) => !config.ignoreRules.includes(finding.id))
    .filter((finding) => !finding.file || !matchesAnyPath(config.ignorePaths, finding.file))
    .map((finding) => {
      const override = config.severityOverrides[finding.id];
      return override ? { ...finding, severity: override } : finding;
    });
}

export function shouldFail(summary, failOn = DEFAULT_CONFIG.failOn) {
  if (failOn === "none") {
    return false;
  }

  const thresholdIndex = SEVERITY_ORDER.indexOf(failOn);
  return SEVERITY_ORDER.slice(0, thresholdIndex + 1).some((severity) => summary[severity] > 0);
}

export function matchesAnyPath(patterns, relativePath) {
  return patterns.some((pattern) => matchPath(pattern, relativePath));
}

function findConfigPath(root) {
  for (const name of CONFIG_FILE_NAMES) {
    const candidate = path.join(root, name);
    if (existsSync(candidate)) {
      return candidate;
    }
  }

  return null;
}

function normalizeConfig(input) {
  const warnings = [];

  if (!input || typeof input !== "object" || Array.isArray(input)) {
    warnings.push("Configuration root must be an object; defaults were used.");
    return {
      config: { ...DEFAULT_CONFIG },
      warnings
    };
  }

  for (const field of Object.keys(input)) {
    if (!KNOWN_CONFIG_FIELDS.has(field)) {
      warnings.push(`Unknown configuration field ignored: ${field}`);
    }
  }

  const config = {
    ...DEFAULT_CONFIG,
    baselinePath: normalizeOptionalString(input.baselinePath, "baselinePath", warnings),
    ignorePaths: normalizeStringArray(input.ignorePaths, "ignorePaths", warnings),
    ignoreRules: normalizeStringArray(input.ignoreRules, "ignoreRules", warnings),
    severityOverrides: normalizeSeverityOverrides(input.severityOverrides, warnings),
    maxFileBytes: normalizePositiveInteger(input.maxFileBytes, "maxFileBytes", warnings, DEFAULT_CONFIG.maxFileBytes),
    failOn: typeof input.failOn === "string" ? input.failOn : DEFAULT_CONFIG.failOn
  };

  if (!FAIL_ON_VALUES.includes(config.failOn)) {
    warnings.push(`Invalid failOn value "${config.failOn}" was ignored.`);
    config.failOn = DEFAULT_CONFIG.failOn;
  }

  for (const rule of config.ignoreRules) {
    if (!KNOWN_RULE_IDS.has(rule)) {
      warnings.push(`Unknown rule id in ignoreRules: ${rule}`);
    }
  }

  for (const rule of Object.keys(config.severityOverrides)) {
    if (!KNOWN_RULE_IDS.has(rule)) {
      warnings.push(`Unknown rule id in severityOverrides: ${rule}`);
    }
  }

  return { config, warnings };
}

function normalizePositiveInteger(value, field, warnings, fallback) {
  if (value === undefined) {
    return fallback;
  }

  if (!Number.isInteger(value) || value <= 0) {
    warnings.push(`${field} must be a positive integer and was ignored.`);
    return fallback;
  }

  return value;
}

function parsePositiveInteger(value, optionName) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw usageError(`${optionName} requires a positive integer.`);
  }
  return parsed;
}

function normalizeStringArray(value, field, warnings) {
  if (value === undefined) {
    return [];
  }

  if (!Array.isArray(value)) {
    warnings.push(`${field} must be an array of strings and was ignored.`);
    return [];
  }

  const normalized = [];
  for (const item of value) {
    if (typeof item !== "string") {
      warnings.push(`${field} contains a non-string value that was ignored.`);
      continue;
    }
    const trimmed = item.trim();
    if (!trimmed) {
      warnings.push(`${field} contains an empty string that was ignored.`);
      continue;
    }
    normalized.push(trimmed);
  }
  return normalized;
}

function normalizeOptionalString(value, field, warnings) {
  if (value === undefined || value === null || value === "") {
    return null;
  }

  if (typeof value !== "string") {
    warnings.push(`${field} must be a string and was ignored.`);
    return null;
  }

  return value;
}

function normalizeSeverityOverrides(value, warnings) {
  if (value === undefined) {
    return {};
  }

  if (!value || typeof value !== "object" || Array.isArray(value)) {
    warnings.push("severityOverrides must be an object and was ignored.");
    return {};
  }

  const overrides = {};
  for (const [rule, severity] of Object.entries(value)) {
    if (!SEVERITY_ORDER.includes(severity)) {
      warnings.push(`Invalid severity override for ${rule} was ignored.`);
      continue;
    }
    overrides[rule] = severity;
  }

  return overrides;
}

function matchPath(pattern, relativePath) {
  const normalizedPattern = normalizePath(pattern);
  const normalizedPath = normalizePath(relativePath);

  if (!normalizedPattern) {
    return false;
  }

  if (!normalizedPattern.includes("*") && !normalizedPattern.includes("?")) {
    return normalizedPath === normalizedPattern || normalizedPath.startsWith(`${normalizedPattern}/`);
  }

  return globToRegExp(normalizedPattern).test(normalizedPath);
}

function normalizePath(value) {
  return String(value).trim().replaceAll("\\", "/").replace(/^\.\/+/, "").replace(/\/+$/, "");
}

function globToRegExp(pattern) {
  let source = "";

  for (let index = 0; index < pattern.length; index += 1) {
    const char = pattern[index];
    const next = pattern[index + 1];

    if (char === "*" && next === "*") {
      if (pattern[index + 2] === "/") {
        source += "(?:.*/)?";
        index += 2;
        continue;
      }
      source += ".*";
      index += 1;
      continue;
    }

    if (char === "*") {
      source += "[^/]*";
      continue;
    }

    if (char === "?") {
      source += "[^/]";
      continue;
    }

    source += escapeRegExp(char);
  }

  return new RegExp(`^${source}$`);
}

// escapeRegExp is imported from scanners/utils.js



function assertKnownRule(rule, optionName) {
  if (typeof rule !== "string" || !rule.trim()) {
    throw usageError(`--${optionName} requires a rule id.`);
  }

  if (!KNOWN_RULE_IDS.has(rule)) {
    throw usageError(`Unknown rule id for --${optionName}: ${rule}. Run agentready list-rules.`);
  }
}
