import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { diffBaseline, loadBaseline, loadBaselineFile, summarizeBaselineDebt, writeBaseline, writePrunedBaseline } from "./baseline.js";
import { FAIL_ON_VALUES, applyCliOverrides, loadConfig, shouldFail } from "./config.js";
import { usageError } from "./errors.js";
import { runDoctor } from "./doctor.js";
import { runInit } from "./init.js";
import { runQuickstart } from "./onboarding.js";
import { formatBaselineDebt, formatBaselineDiff, formatJson, formatMarkdown, formatSarif, formatText } from "./reporters.js";
import { formatRules, RULE_CATALOG } from "./rules.js";
import { scanProject } from "./scanner.js";
import { SEVERITIES } from "./constants.js";
import { sortFindings } from "./utils.js";

const HELP = `AgentReady - preflight security scanner for AI coding agents

Usage:
  agentready scan [path] [--format text|json|markdown|sarif] [--output file] [--ci]
                  [--config file] [--fail-on high|medium|low|info|none]
                  [--ignore-rule id] [--ignore-path pattern] [--baseline file]
                  [--max-file-size bytes]
                  [--max-findings count] [--summary-only] [--group-by severity|category]
                  [--quiet] [--verbose] [--no-color]
  agentready baseline [path] [--output .agentready-baseline.json]
                      [--config file] [--ignore-rule id] [--ignore-path pattern]
                      [--max-file-size bytes]
  agentready baseline diff [path] [--baseline .agentready-baseline.json]
                           [--format text|json|markdown] [--output file] [--config file]
                           [--ignore-rule id] [--ignore-path pattern] [--max-file-size bytes]
  agentready baseline prune [path] [--baseline .agentready-baseline.json] [--output file]
                            [--config file] [--ignore-rule id] [--ignore-path pattern]
                            [--max-file-size bytes]
  agentready debt [path] [--baseline .agentready-baseline.json]
                  [--format text|json|markdown] [--output file] [--config file]
  agentready init [path] [--force] [--dry-run] [--preset balanced|strict|legacy] [--with-ci]
  agentready quickstart [path]
  agentready doctor [path] [--config file] [--baseline file]
                    [--max-file-size bytes]
                    [--max-findings count] [--summary-only] [--group-by severity|category]
                    [--quiet] [--verbose] [--no-color]
  agentready config validate [path] [--config file]
  agentready list-rules [--format text|json|markdown] [--category name] [--severity level]
  agentready version
  agentready help

Examples:
  agentready scan
  agentready scan . --format markdown --output agentready-report.md
  agentready scan . --format json --ci
  agentready scan . --ci --fail-on high
  agentready scan . --format markdown --group-by category --max-findings 20
  agentready scan . --max-file-size 1048576
  agentready baseline . --output .agentready-baseline.json
  agentready baseline diff .
  agentready baseline prune .
  agentready debt .
  agentready init . --preset balanced --with-ci
  agentready quickstart .
  agentready list-rules --category github-actions
`;

export async function runCli(argv) {
  const [command = "help", ...rest] = argv;

  if (command === "help" || command === "--help" || command === "-h") {
    console.log(HELP);
    return;
  }

  if (command === "version" || command === "--version" || command === "-v") {
    console.log(await readVersion());
    return;
  }

  if (command === "scan") {
    await handleScan(rest);
    return;
  }

  if (command === "init") {
    await handleInit(rest);
    return;
  }

  if (command === "doctor") {
    await handleDoctor(rest);
    return;
  }

  if (command === "quickstart") {
    await handleQuickstart(rest);
    return;
  }

  if (command === "list-rules") {
    await handleListRules(rest);
    return;
  }

  if (command === "baseline") {
    await handleBaseline(rest);
    return;
  }

  if (command === "debt") {
    await handleDebt(rest);
    return;
  }

  if (command === "config") {
    await handleConfig(rest);
    return;
  }

  throw usageError(`Unknown command: ${command}\n\n${HELP}`);
}

async function handleScan(args) {
  const options = parseOptions(args);
  rejectUnsupportedOptions(options, [
    "format",
    "output",
    "ci",
    "config",
    "fail-on",
    "ignore-rule",
    "ignore-path",
    "baseline",
    "max-file-size",
    "max-findings",
    "summary-only",
    "group-by",
    "quiet",
    "verbose",
    "no-color"
  ]);
  const target = path.resolve(options.positionals[0] || process.cwd());
  const format = options.format || "text";

  if (!["text", "json", "markdown", "sarif"].includes(format)) {
    throw usageError(`Unsupported format "${format}". Use text, json, markdown, or sarif.`);
  }

  const reportOptions = normalizeReportOptions(options);

  if (options.failOn && !FAIL_ON_VALUES.includes(options.failOn)) {
    throw usageError(`Unsupported fail threshold "${options.failOn}". Use ${FAIL_ON_VALUES.join(", ")}.`);
  }

  const loaded = await loadConfig(target, options.config);
  const config = applyCliOverrides(loaded.config, options);
  const baselinePath = options.baseline || config.baselinePath;
  const baseline = await loadBaseline(target, baselinePath);

  const result = await scanProject(target, {
    config,
    baseline,
    configWarnings: loaded.warnings
  });
  const reportResult = applyReportOptions(result, reportOptions);
  const output =
    format === "json"
      ? formatJson(reportResult)
      : format === "markdown"
        ? formatMarkdown(reportResult, reportOptions)
        : format === "sarif"
          ? formatSarif(reportResult)
          : formatText(reportResult, { quiet: options.quiet, verbose: options.verbose, groupBy: reportOptions.groupBy });

  if (options.output) {
    const outputPath = path.resolve(options.output);
    await mkdir(path.dirname(outputPath), { recursive: true });
    await writeFile(outputPath, output, "utf8");
    if (!options.quiet) {
      console.log(`Wrote ${format} report to ${outputPath}`);
    }
  } else {
    console.log(output);
  }

  if (options.ci && shouldFail(result.summary, config.failOn)) {
    process.exitCode = 1;
  }
}

async function handleInit(args) {
  const options = parseOptions(args);
  rejectUnsupportedOptions(options, ["force", "dry-run", "preset", "with-ci"]);
  const target = path.resolve(options.positionals[0] || process.cwd());
  const result = await runInit(target, {
    dryRun: Boolean(options.dryRun),
    force: Boolean(options.force),
    preset: options.preset || "balanced",
    withCi: Boolean(options.withCi)
  });
  for (const line of result.messages) {
    console.log(line);
  }
}

async function handleBaseline(args) {
  const [subcommand, ...rest] = args;
  if (subcommand === "diff") {
    await handleBaselineDiff(rest);
    return;
  }

  if (subcommand === "prune") {
    await handleBaselinePrune(rest);
    return;
  }

  const options = parseOptions(args);
  rejectUnsupportedOptions(options, ["output", "config", "ignore-rule", "ignore-path", "max-file-size"]);
  const target = path.resolve(options.positionals[0] || process.cwd());
  const output = path.resolve(options.output || path.join(target, ".agentready-baseline.json"));
  const loaded = await loadConfig(target, options.config);
  const config = applyCliOverrides(
    {
      ...loaded.config,
      baselinePath: null
    },
    options
  );
  const result = await scanProject(target, {
    config,
    configWarnings: loaded.warnings
  });
  const baseline = await writeBaseline(output, result);

  console.log(`Wrote baseline with ${baseline.findings.length} findings to ${output}`);
}

async function handleBaselineDiff(args) {
  const options = parseOptions(args);
  rejectUnsupportedOptions(options, ["baseline", "config", "ignore-rule", "ignore-path", "max-file-size", "format", "output"]);
  const target = path.resolve(options.positionals[0] || process.cwd());
  const format = options.format || "text";

  if (!["text", "json", "markdown"].includes(format)) {
    throw usageError(`Unsupported format "${format}". Use text, json, or markdown.`);
  }

  const loaded = await loadConfig(target, options.config);
  const config = applyCliOverrides(
    {
      ...loaded.config,
      baselinePath: null
    },
    options
  );
  const baselinePath = resolveBaselinePathOption(target, options, loaded.config);
  const baseline = await loadBaselineFile(target, baselinePath);
  const result = await scanProject(target, {
    config,
    configWarnings: loaded.warnings
  });
  const diff = diffBaseline(result.findings, baseline);
  const output = formatBaselineDiff(diff, format);

  if (options.output) {
    const outputPath = path.resolve(options.output);
    await mkdir(path.dirname(outputPath), { recursive: true });
    await writeFile(outputPath, output, "utf8");
    console.log(`Wrote baseline diff to ${outputPath}`);
    return;
  }

  console.log(output);
}

async function handleBaselinePrune(args) {
  const options = parseOptions(args);
  rejectUnsupportedOptions(options, ["baseline", "output", "config", "ignore-rule", "ignore-path", "max-file-size"]);
  const target = path.resolve(options.positionals[0] || process.cwd());
  const loaded = await loadConfig(target, options.config);
  const config = applyCliOverrides(
    {
      ...loaded.config,
      baselinePath: null
    },
    options
  );
  const baselinePath = resolveBaselinePathOption(target, options, loaded.config);
  const baseline = await loadBaselineFile(target, baselinePath);
  const result = await scanProject(target, {
    config,
    configWarnings: loaded.warnings
  });
  const diff = diffBaseline(result.findings, baseline);
  const output = path.resolve(options.output || baseline.path);
  const pruned = await writePrunedBaseline(output, diff);

  console.log(`Pruned baseline: kept ${pruned.findings.length}, removed ${diff.summary.stale}, wrote ${output}`);
}

async function handleDebt(args) {
  const options = parseOptions(args);
  rejectUnsupportedOptions(options, ["baseline", "format", "output", "config"]);
  const target = path.resolve(options.positionals[0] || process.cwd());
  const format = options.format || "text";

  if (!["text", "json", "markdown"].includes(format)) {
    throw usageError(`Unsupported format "${format}". Use text, json, or markdown.`);
  }

  const loaded = await loadConfig(target, options.config);
  const baselinePath = resolveBaselinePathOption(target, options, loaded.config);
  const baseline = await loadBaselineFile(target, baselinePath);
  const output = formatBaselineDebt(summarizeBaselineDebt(baseline), format);

  if (options.output) {
    const outputPath = path.resolve(options.output);
    await mkdir(path.dirname(outputPath), { recursive: true });
    await writeFile(outputPath, output, "utf8");
    console.log(`Wrote baseline debt report to ${outputPath}`);
    return;
  }

  console.log(output);
}

async function handleDoctor(args) {
  const options = parseOptions(args);
  rejectUnsupportedOptions(options, [
    "config",
    "baseline",
    "ignore-rule",
    "ignore-path",
    "max-file-size",
    "max-findings",
    "summary-only",
    "group-by",
    "quiet",
    "verbose",
    "no-color"
  ]);
  const target = path.resolve(options.positionals[0] || process.cwd());
  const reportOptions = normalizeReportOptions(options);
  const loaded = await loadConfig(target, options.config);
  const config = applyCliOverrides(loaded.config, options);
  const baselinePath = options.baseline || config.baselinePath;
  const baseline = await loadBaseline(target, baselinePath);
  const result = await runDoctor(target, {
    config,
    baseline,
    configWarnings: loaded.warnings
  });
  console.log(formatText(applyReportOptions(result, reportOptions), { quiet: options.quiet, verbose: options.verbose, groupBy: reportOptions.groupBy }));
}

async function handleQuickstart(args) {
  const options = parseOptions(args);
  rejectUnsupportedOptions(options, []);
  const target = path.resolve(options.positionals[0] || process.cwd());
  const result = await runQuickstart(target);
  for (const line of result.messages) {
    console.log(line);
  }
}

async function handleConfig(args) {
  const [subcommand = "help", ...rest] = args;

  if (subcommand === "validate") {
    const options = parseOptions(rest);
    rejectUnsupportedOptions(options, ["config"]);
    const target = path.resolve(options.positionals[0] || process.cwd());
    const loaded = await loadConfig(target, options.config);

    if (loaded.warnings.length === 0) {
      console.log(`Configuration is valid: ${loaded.config.configPath || "(defaults)"}`);
      return;
    }

    console.log(`Configuration loaded with ${loaded.warnings.length} warning(s): ${loaded.config.configPath || "(defaults)"}`);
    for (const warning of loaded.warnings) {
      console.log(`- ${warning}`);
    }
    process.exitCode = 3;
    return;
  }

  throw usageError("Usage: agentready config validate [path] [--config file]");
}

async function handleListRules(args) {
  const options = parseOptions(args);
  rejectUnsupportedOptions(options, ["format", "category", "severity"]);
  const format = options.format || "text";

  if (!["text", "json", "markdown"].includes(format)) {
    throw usageError(`Unsupported format "${format}". Use text, json, or markdown.`);
  }

  if (options.severity && !SEVERITIES.includes(options.severity)) {
    throw usageError(`Unsupported severity "${options.severity}". Use ${SEVERITIES.join(", ")}.`);
  }

  const categories = [...new Set(RULE_CATALOG.map((rule) => rule.category))].sort();
  if (options.category && !categories.includes(options.category)) {
    throw usageError(`Unsupported category "${options.category}". Use ${categories.join(", ")}.`);
  }

  console.log(formatRules(format, { category: options.category, severity: options.severity }));
}

function rejectUnsupportedOptions(options, allowedNames) {
  const allowed = new Set(allowedNames);
  const present = [
    ["format", options.format !== undefined],
    ["output", options.output !== undefined],
    ["ci", Boolean(options.ci)],
    ["config", options.config !== undefined],
    ["fail-on", options.failOn !== undefined],
    ["ignore-rule", options.ignoreRules.length > 0],
    ["ignore-path", options.ignorePaths.length > 0],
    ["baseline", options.baseline !== undefined],
    ["max-file-size", options.maxFileSize !== undefined],
    ["max-findings", options.maxFindings !== undefined],
    ["summary-only", Boolean(options.summaryOnly)],
    ["group-by", options.groupBy !== undefined],
    ["category", options.category !== undefined],
    ["severity", options.severity !== undefined],
    ["preset", options.preset !== undefined],
    ["force", Boolean(options.force)],
    ["dry-run", Boolean(options.dryRun)],
    ["with-ci", Boolean(options.withCi)],
    ["quiet", Boolean(options.quiet)],
    ["verbose", Boolean(options.verbose)],
    ["no-color", Boolean(options.noColor)]
  ];

  for (const [name, isPresent] of present) {
    if (isPresent && !allowed.has(name)) {
      throw usageError(`Option --${name} is not supported for this command.`);
    }
  }
}

function parseOptions(args) {
  const options = {
    positionals: [],
    ignorePaths: [],
    ignoreRules: []
  };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];

    if (arg === "--format") {
      options.format = readOptionValue(args, index, "--format");
      index += 1;
      continue;
    }

    if (arg.startsWith("--format=")) {
      options.format = arg.slice("--format=".length);
      continue;
    }

    if (arg === "--output" || arg === "-o") {
      options.output = readOptionValue(args, index, arg);
      index += 1;
      continue;
    }

    if (arg.startsWith("--output=")) {
      options.output = arg.slice("--output=".length);
      continue;
    }

    if (arg === "--ci") {
      options.ci = true;
      continue;
    }

    if (arg === "--config") {
      options.config = readOptionValue(args, index, "--config");
      index += 1;
      continue;
    }

    if (arg.startsWith("--config=")) {
      options.config = arg.slice("--config=".length);
      continue;
    }

    if (arg === "--fail-on") {
      options.failOn = readOptionValue(args, index, "--fail-on");
      index += 1;
      continue;
    }

    if (arg.startsWith("--fail-on=")) {
      options.failOn = arg.slice("--fail-on=".length);
      continue;
    }

    if (arg === "--ignore-rule") {
      options.ignoreRules.push(readOptionValue(args, index, "--ignore-rule"));
      index += 1;
      continue;
    }

    if (arg.startsWith("--ignore-rule=")) {
      options.ignoreRules.push(arg.slice("--ignore-rule=".length));
      continue;
    }

    if (arg === "--ignore-path") {
      options.ignorePaths.push(readOptionValue(args, index, "--ignore-path"));
      index += 1;
      continue;
    }

    if (arg.startsWith("--ignore-path=")) {
      options.ignorePaths.push(arg.slice("--ignore-path=".length));
      continue;
    }

    if (arg === "--baseline") {
      options.baseline = readOptionValue(args, index, "--baseline");
      index += 1;
      continue;
    }

    if (arg.startsWith("--baseline=")) {
      options.baseline = arg.slice("--baseline=".length);
      continue;
    }

    if (arg === "--max-findings") {
      options.maxFindings = readOptionValue(args, index, "--max-findings");
      index += 1;
      continue;
    }

    if (arg.startsWith("--max-findings=")) {
      options.maxFindings = arg.slice("--max-findings=".length);
      continue;
    }

    if (arg === "--max-file-size") {
      options.maxFileSize = readOptionValue(args, index, "--max-file-size");
      index += 1;
      continue;
    }

    if (arg.startsWith("--max-file-size=")) {
      options.maxFileSize = arg.slice("--max-file-size=".length);
      continue;
    }

    if (arg === "--summary-only") {
      options.summaryOnly = true;
      continue;
    }

    if (arg === "--group-by") {
      options.groupBy = readOptionValue(args, index, "--group-by");
      index += 1;
      continue;
    }

    if (arg.startsWith("--group-by=")) {
      options.groupBy = arg.slice("--group-by=".length);
      continue;
    }

    if (arg === "--category") {
      options.category = readOptionValue(args, index, "--category");
      index += 1;
      continue;
    }

    if (arg.startsWith("--category=")) {
      options.category = arg.slice("--category=".length);
      continue;
    }

    if (arg === "--severity") {
      options.severity = readOptionValue(args, index, "--severity");
      index += 1;
      continue;
    }

    if (arg.startsWith("--severity=")) {
      options.severity = arg.slice("--severity=".length);
      continue;
    }

    if (arg === "--preset") {
      options.preset = readOptionValue(args, index, "--preset");
      index += 1;
      continue;
    }

    if (arg.startsWith("--preset=")) {
      options.preset = arg.slice("--preset=".length);
      continue;
    }

    if (arg === "--force") {
      options.force = true;
      continue;
    }

    if (arg === "--dry-run") {
      options.dryRun = true;
      continue;
    }

    if (arg === "--with-ci") {
      options.withCi = true;
      continue;
    }

    if (arg === "--quiet") {
      options.quiet = true;
      continue;
    }

    if (arg === "--verbose") {
      options.verbose = true;
      continue;
    }

    if (arg === "--no-color") {
      options.noColor = true;
      continue;
    }

    if (arg.startsWith("-")) {
      throw usageError(`Unknown option: ${arg}`);
    }

    options.positionals.push(arg);
  }

  return options;
}

function readOptionValue(args, index, optionName) {
  const value = args[index + 1];

  if (value === undefined || value.startsWith("--")) {
    throw usageError(`${optionName} requires a value.`);
  }

  return value;
}

function normalizeReportOptions(options) {
  const normalized = {
    maxFindings: null,
    summaryOnly: Boolean(options.summaryOnly),
    groupBy: options.groupBy || "severity"
  };

  if (options.maxFindings !== undefined) {
    const parsed = Number(options.maxFindings);
    if (!Number.isInteger(parsed) || parsed < 0) {
      throw usageError(`--max-findings requires a non-negative integer.`);
    }
    normalized.maxFindings = parsed;
  }

  if (!["severity", "category"].includes(normalized.groupBy)) {
    throw usageError(`Unsupported group-by value "${normalized.groupBy}". Use severity or category.`);
  }

  return normalized;
}

function applyReportOptions(result, options) {
  const totalFindings = result.findings.length;
  const shouldLimit = options.summaryOnly || options.maxFindings !== null || options.groupBy !== "severity";

  if (!shouldLimit) {
    return result;
  }

  const findings = options.summaryOnly
    ? []
    : sortFindings(result.findings).slice(0, options.maxFindings ?? totalFindings);

  return {
    ...result,
    findings,
    report: {
      totalFindings,
      displayedFindings: findings.length,
      omittedFindings: totalFindings - findings.length,
      summaryOnly: options.summaryOnly,
      maxFindings: options.maxFindings,
      groupBy: options.groupBy
    }
  };
}



function resolveBaselinePathOption(target, options, config) {
  return options.baseline || config.baselinePath || path.join(target, ".agentready-baseline.json");
}

let cachedVersion = null;

async function readVersion() {
  if (cachedVersion) {
    return cachedVersion;
  }
  const packagePath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "package.json");
  const parsed = JSON.parse(await readFile(packagePath, "utf8"));
  cachedVersion = parsed.version;
  return cachedVersion;
}
