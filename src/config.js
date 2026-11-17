import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { MAX_FILE_BYTES, SEVERITIES } from "./constants.js";
import { configError, usageError } from "./errors.js";
import { RULE_CATALOG } from "./rules.js";
import { escapeRegExp } from "./utils.js";

export const CONFIG_FILE_NAMES = ["agentready.config.json", ".agentready.json"];
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

  let raw;
  try {
    raw = await readFile(configPath, "utf8");
  } catch (error) {
    throw configError(`Config file could not be read: ${configPath}\n${error.message}`);
  }

  let parsed;
  try {
    parsed = JSON.parse(raw.replace(/^\uFEFF/, ""));
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

  const thresholdIndex = SEVERITIES.indexOf(failOn);
  return SEVERITIES.slice(0, thresholdIndex + 1).some((severity) => summary[severity] > 0);
}

export function matchesAnyPath(patterns, relativePath, options = {}) {
  return patterns.some((pattern) => matchPath(pattern, relativePath, options));
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

  if (input.$schema !== undefined && typeof input.$schema !== "string") {
    warnings.push("$schema must be a string and was ignored.");
  }

  let failOn = DEFAULT_CONFIG.failOn;
  if (input.failOn !== undefined) {
    if (typeof input.failOn !== "string") {
      warnings.push(`Invalid failOn value "${String(input.failOn)}" was ignored.`);
    } else if (!FAIL_ON_VALUES.includes(input.failOn)) {
      warnings.push(`Invalid failOn value "${input.failOn}" was ignored.`);
    } else {
      failOn = input.failOn;
    }
  }

  const config = {
    ...DEFAULT_CONFIG,
    baselinePath: normalizeOptionalString(input.baselinePath, "baselinePath", warnings),
    ignorePaths: normalizeStringArray(input.ignorePaths, "ignorePaths", warnings),
    ignoreRules: normalizeStringArray(input.ignoreRules, "ignoreRules", warnings),
    severityOverrides: normalizeSeverityOverrides(input.severityOverrides, warnings),
    maxFileBytes: normalizePositiveInteger(input.maxFileBytes, "maxFileBytes", warnings, DEFAULT_CONFIG.maxFileBytes),
    failOn
  };

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

  const trimmed = value.trim();
  return trimmed || null;
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
    if (!SEVERITIES.includes(severity)) {
      warnings.push(`Invalid severity override for ${rule} was ignored.`);
      continue;
    }
    overrides[rule] = severity;
  }

  return overrides;
}

// matchPath runs for every walked file against every ignore pattern, so cache
// compiled glob regexes per normalized pattern instead of recompiling each call.
const globRegExpCache = new Map();

function matchPath(pattern, relativePath, options = {}) {
  const rawPattern = String(pattern).trim().replaceAll("\\", "/");
  const directoryOnly = /\/+$/.test(rawPattern);
  const normalizedPattern = normalizePath(rawPattern);
  const normalizedPath = normalizePath(relativePath);

  if (!normalizedPattern || !normalizedPath) {
    return false;
  }

  // A trailing slash (`secrets/`) means directory-only: match the directory
  // entry itself during walk() or anything underneath it, never a regular file
  // that happens to share the directory's name.
  if (directoryOnly && options.isDirectory === false && normalizedPath === normalizedPattern) {
    return false;
  }

  if (!normalizedPattern.includes("*") && !normalizedPattern.includes("?")) {
    return normalizedPath === normalizedPattern || normalizedPath.startsWith(`${normalizedPattern}/`);
  }

  // In walk(), a directory `fixtures` should be skipped immediately when
  // `fixtures/**` is configured, without reading and discarding every child.
  if (options.isDirectory === true && normalizedPattern.endsWith("/**")) {
    const dirPrefix = normalizedPattern.slice(0, -3);
    if (!dirPrefix.includes("*") && !dirPrefix.includes("?") && normalizedPath === dirPrefix) {
      return true;
    }
  }

  const cacheKey = `${directoryOnly ? "d:" : "f:"}${normalizedPattern}`;
  let matcher = globRegExpCache.get(cacheKey);
  if (!matcher) {
    matcher = compileGlobMatcher(normalizedPattern, directoryOnly);
    globRegExpCache.set(cacheKey, matcher);
  }
  return matcher(normalizedPath);
}

function normalizePath(value) {
  return String(value).trim().replaceAll("\\", "/").replace(/^(?:\.\/+|\/+)/, "").replace(/\/+$/, "");
}

function collapseGlobWildcards(rawPattern) {
  return rawPattern
    .replace(/\*{3,}/g, "**")
    .replace(/(?:\*\*\/){2,}/g, "**/")
    .replace(/(?:\/\*\*){2,}/g, "/**");
}

function compileGlobMatcher(rawPattern, directoryOnly = false) {
  const pattern = collapseGlobWildcards(rawPattern);
  const starCount = (pattern.match(/\*/g) || []).length;
  // Multi-wildcard patterns from untrusted `.agentready.json` files can make a
  // backtracking RegExp take exponential time; evaluate them with an O(P * N)
  // token automaton instead.
  if (starCount > 2) {
    const tokens = tokenizeGlob(pattern, directoryOnly);
    return (candidate) => matchGlobTokens(tokens, candidate);
  }
  const compiled = globToRegExp(pattern, directoryOnly);
  return (candidate) => compiled.test(candidate);
}

function tokenizeGlob(pattern, directoryOnly) {
  const tokens = [];
  for (let index = 0; index < pattern.length; index += 1) {
    const char = pattern[index];
    const next = pattern[index + 1];
    const prev = index > 0 ? pattern[index - 1] : "/";

    if (char === "*" && next === "*") {
      if (prev === "/" && pattern[index + 2] === "/") {
        tokens.push({ type: "globstarSlash" });
        index += 2;
        continue;
      }
      tokens.push({ type: "any" });
      index += 1;
      continue;
    }
    if (char === "*") {
      tokens.push({ type: "star" });
      continue;
    }
    if (char === "?") {
      tokens.push({ type: "qmark" });
      continue;
    }
    tokens.push({ type: "char", value: char });
  }
  if (directoryOnly) {
    tokens.push({ type: "dirTail" });
  }
  return tokens;
}

function matchGlobTokens(tokens, candidate) {
  const length = candidate.length;
  let reachable = new Uint8Array(length + 1);
  reachable[0] = 1;

  for (const token of tokens) {
    const next = new Uint8Array(length + 1);
    if (token.type === "char") {
      for (let j = 0; j < length; j += 1) {
        if (reachable[j] && candidate[j] === token.value) {
          next[j + 1] = 1;
        }
      }
    } else if (token.type === "qmark") {
      for (let j = 0; j < length; j += 1) {
        if (reachable[j] && candidate[j] !== "/") {
          next[j + 1] = 1;
        }
      }
    } else if (token.type === "star") {
      for (let j = 0; j <= length; j += 1) {
        if (reachable[j] || (j > 0 && next[j - 1] && candidate[j - 1] !== "/")) {
          next[j] = 1;
        }
      }
    } else if (token.type === "any") {
      const first = reachable.indexOf(1);
      if (first !== -1) {
        next.fill(1, first);
      }
    } else if (token.type === "globstarSlash") {
      const first = reachable.indexOf(1);
      for (let j = 0; j <= length; j += 1) {
        if (reachable[j]) {
          next[j] = 1;
        }
        if (first !== -1 && j > first && candidate[j - 1] === "/") {
          // `(?:.+/)?` requires at least one character before the slash (`j - 1 > first`).
          if (j - 1 > first) {
            next[j] = 1;
          }
        }
      }
    } else if (token.type === "dirTail") {
      if (reachable[length]) {
        next[length] = 1;
      } else {
        for (let j = 0; j < length; j += 1) {
          if (reachable[j] && candidate[j] === "/") {
            next[length] = 1;
            break;
          }
        }
      }
    }
    reachable = next;
  }

  return reachable[length] === 1;
}

function globToRegExp(pattern, directoryOnly = false) {
  let source = "";

  for (let index = 0; index < pattern.length; index += 1) {
    const char = pattern[index];
    const next = pattern[index + 1];
    const prev = index > 0 ? pattern[index - 1] : "/";

    if (char === "*" && next === "*") {
      if (prev === "/" && pattern[index + 2] === "/") {
        source += "(?:.+/)?";
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

  if (directoryOnly) {
    return new RegExp(`^(?:${source})(?:$|/.*)`);
  }

  return new RegExp(`^${source}$`);
}

function assertKnownRule(rule, optionName) {
  if (typeof rule !== "string" || !rule.trim()) {
    throw usageError(`--${optionName} requires a rule id.`);
  }

  if (!KNOWN_RULE_IDS.has(rule)) {
    throw usageError(`Unknown rule id for --${optionName}: ${rule}. Run agentready list-rules.`);
  }
}
