import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { configError } from "./errors.js";
import { RULE_CATALOG } from "./rules.js";

export const CONFIG_FILE_NAMES = ["agentready.config.json", ".agentready.json"];
export const SEVERITY_ORDER = ["high", "medium", "low", "info"];
export const FAIL_ON_VALUES = [...SEVERITY_ORDER, "none"];

export const DEFAULT_CONFIG = {
  baselinePath: null,
  ignorePaths: [],
  ignoreRules: [],
  severityOverrides: {},
  failOn: "medium"
};

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

  for (const rule of options.ignoreRules || []) {
    assertKnownRule(rule, "ignore-rule");
    next.ignoreRules.push(rule);
  }

  for (const pattern of options.ignorePaths || []) {
    next.ignorePaths.push(pattern);
  }

  if (options.failOn) {
    if (!FAIL_ON_VALUES.includes(options.failOn)) {
      throw new Error(`Unsupported fail threshold "${options.failOn}". Use ${FAIL_ON_VALUES.join(", ")}.`);
    }
    next.failOn = options.failOn;
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
  const config = {
    ...DEFAULT_CONFIG,
    baselinePath: normalizeOptionalString(input.baselinePath, "baselinePath", warnings),
    ignorePaths: normalizeStringArray(input.ignorePaths, "ignorePaths", warnings),
    ignoreRules: normalizeStringArray(input.ignoreRules, "ignoreRules", warnings),
    severityOverrides: normalizeSeverityOverrides(input.severityOverrides, warnings),
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

function normalizeStringArray(value, field, warnings) {
  if (value === undefined) {
    return [];
  }

  if (!Array.isArray(value)) {
    warnings.push(`${field} must be an array of strings and was ignored.`);
    return [];
  }

  return value.filter((item) => {
    if (typeof item === "string" && item.trim()) {
      return true;
    }
    warnings.push(`${field} contains a non-string value that was ignored.`);
    return false;
  });
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

  if (!normalizedPattern.includes("*")) {
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
      source += ".*";
      index += 1;
      continue;
    }

    if (char === "*") {
      source += "[^/]*";
      continue;
    }

    source += escapeRegExp(char);
  }

  return new RegExp(`^${source}$`);
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function assertKnownRule(rule, optionName) {
  if (typeof rule !== "string" || !rule.trim()) {
    throw new Error(`--${optionName} requires a rule id.`);
  }

  if (!KNOWN_RULE_IDS.has(rule)) {
    throw new Error(`Unknown rule id for --${optionName}: ${rule}. Run agentready list-rules.`);
  }
}
