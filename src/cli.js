import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadBaseline, writeBaseline } from "./baseline.js";
import { applyCliOverrides, loadConfig, shouldFail } from "./config.js";
import { usageError } from "./errors.js";
import { runDoctor } from "./doctor.js";
import { runInit } from "./init.js";
import { formatJson, formatMarkdown, formatSarif, formatText } from "./reporters.js";
import { formatRules } from "./rules.js";
import { scanProject } from "./scanner.js";

const HELP = `AgentReady - preflight security scanner for AI coding agents

Usage:
  agentready scan [path] [--format text|json|markdown|sarif] [--output file] [--ci]
                  [--config file] [--fail-on high|medium|low|info|none]
                  [--ignore-rule id] [--ignore-path pattern] [--baseline file]
                  [--quiet] [--verbose] [--no-color]
  agentready baseline [path] [--output .agentready-baseline.json]
  agentready init [path] [--force] [--dry-run] [--preset balanced|strict|legacy] [--with-ci]
  agentready doctor [path]
  agentready config validate [path] [--config file]
  agentready list-rules [--format text|json|markdown] [--category name] [--severity level]
  agentready version
  agentready help

Examples:
  agentready scan
  agentready scan . --format markdown --output agentready-report.md
  agentready scan . --format json --ci
  agentready scan . --ci --fail-on high
  agentready baseline . --output .agentready-baseline.json
  agentready init . --preset balanced --with-ci
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

  if (command === "list-rules") {
    await handleListRules(rest);
    return;
  }

  if (command === "baseline") {
    await handleBaseline(rest);
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
  const target = path.resolve(options.positionals[0] || process.cwd());
  const format = options.format || "text";
  const loaded = await loadConfig(target, options.config);
  const config = applyCliOverrides(loaded.config, options);
  const baselinePath = options.baseline || config.baselinePath;
  const baseline = await loadBaseline(target, baselinePath);

  if (!["text", "json", "markdown", "sarif"].includes(format)) {
    throw usageError(`Unsupported format "${format}". Use text, json, markdown, or sarif.`);
  }

  const result = await scanProject(target, {
    config,
    baseline,
    configWarnings: loaded.warnings
  });
  const output =
    format === "json"
      ? formatJson(result)
      : format === "markdown"
        ? formatMarkdown(result)
        : format === "sarif"
          ? formatSarif(result)
          : formatText(result, { quiet: options.quiet, verbose: options.verbose });

  if (options.output) {
    await writeFile(path.resolve(options.output), output, "utf8");
    if (!options.quiet) {
      console.log(`Wrote ${format} report to ${path.resolve(options.output)}`);
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
  const options = parseOptions(args);
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

async function handleDoctor(args) {
  const options = parseOptions(args);
  const target = path.resolve(options.positionals[0] || process.cwd());
  const loaded = await loadConfig(target, options.config);
  const config = applyCliOverrides(loaded.config, options);
  const result = await runDoctor(target, {
    config,
    configWarnings: loaded.warnings
  });
  console.log(formatText(result, { quiet: options.quiet, verbose: options.verbose }));
}

async function handleConfig(args) {
  const [subcommand = "help", ...rest] = args;

  if (subcommand === "validate") {
    const options = parseOptions(rest);
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
    return;
  }

  throw usageError("Usage: agentready config validate [path] [--config file]");
}

async function handleListRules(args) {
  const options = parseOptions(args);
  const format = options.format || "text";

  if (!["text", "json", "markdown"].includes(format)) {
    throw usageError(`Unsupported format "${format}". Use text, json, or markdown.`);
  }

  console.log(formatRules(format, { category: options.category, severity: options.severity }));
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

  if (!value || value.startsWith("--")) {
    throw usageError(`${optionName} requires a value.`);
  }

  return value;
}

async function readVersion() {
  const packagePath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "package.json");
  const parsed = JSON.parse(await readFile(packagePath, "utf8"));
  return parsed.version;
}
