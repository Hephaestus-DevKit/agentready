import { escapeMarkdown } from "./utils.js";

export const RULE_CATALOG = [
  rule("agent.missing_agents_md", "info", "AGENTS.md is missing", "Create AGENTS.md to document safe AI agent operating boundaries."),
  rule("agent.missing_agentignore", "low", ".agentignore is missing", "Create .agentignore to mark sensitive paths agents should avoid."),
  rule("secret.sensitive_filename", "medium", "Sensitive-looking file is agent-readable", "Keep sensitive files out of git and agent-readable paths."),
  rule("secret.private_key", "high", "Private key material is present", "Remove private keys and rotate exposed credentials."),
  rule("secret.github_token", "high", "GitHub token-like value is present", "Move tokens to scoped secret storage and rotate exposed values."),
  rule("secret.anthropic_key", "high", "Anthropic-style API key is present", "Move API keys to environment secrets and rotate exposed values."),
  rule("secret.openai_key", "high", "OpenAI-style API key is present", "Move API keys to environment secrets and rotate exposed values."),
  rule("secret.aws_access_key", "high", "AWS access key-like value is present", "Rotate exposed keys and use scoped secret storage."),
  rule("secret.generic_assignment", "high", "Secret-like assignment is present", "Move secret values out of repository files and rotate exposed values."),
  rule("script.dangerous_command.recursive_delete", "high", "Risky recursive delete command", "Guard recursive deletes and require manual approval."),
  rule("script.dangerous_command.remote_code_execution", "high", "Remote download piped to shell", "Pin scripts and verify checksums before execution."),
  rule("script.dangerous_command.world_writable", "medium", "World-writable permission command", "Avoid chmod -R 777 and scope permissions tightly."),
  rule("script.dangerous_command.sudo", "medium", "Elevated privilege command", "Require manual approval for privileged commands."),
  rule("package.invalid_json", "low", "package.json could not be parsed", "Fix package.json so scripts and dependencies can be inspected."),
  rule("package.script.recursive_delete", "high", "Risky npm script recursive delete", "Guard recursive deletes and require manual approval."),
  rule("package.script.remote_code_execution", "high", "Risky npm script remote shell execution", "Avoid piping remote downloads directly into shells."),
  rule("package.script.world_writable", "medium", "Risky npm script world-writable permissions", "Avoid chmod -R 777 in npm scripts."),
  rule("package.script.sudo", "medium", "Risky npm script elevated privilege use", "Require manual approval for privileged scripts."),
  rule("package.lifecycle_script", "medium", "Package lifecycle script detected", "Review lifecycle scripts before automated installs."),
  rule("github_actions.pull_request_target", "high", "GitHub Actions uses pull_request_target", "Avoid pull_request_target for untrusted code or restrict it heavily."),
  rule("github_actions.write_all", "medium", "GitHub Actions grants write-all permissions", "Use least-privilege workflow permissions."),
  rule("github_actions.write_permission", "medium", "GitHub Actions grants a write permission", "Use job-level least-privilege write permissions."),
  rule("github_actions.secrets_inherit", "medium", "GitHub Actions inherits all caller secrets", "Pass only required secrets to reusable workflows."),
  rule("github_actions.persist_credentials", "low", "actions/checkout persists credentials", "Disable persisted credentials when jobs do not need push access."),
  rule("github_actions.unpinned_action", "medium", "GitHub Actions uses a floating external action or reusable workflow reference", "Use a full commit SHA or reviewed release tag instead of a branch or missing ref."),
  rule("github_actions.pull_request_target_checkout", "high", "pull_request_target workflow checks out repository code", "Avoid checking out untrusted pull request code in pull_request_target workflows."),
  rule("github_actions.workflow_run", "medium", "GitHub Actions uses workflow_run", "Review workflow_run chains carefully before granting secrets or write permissions."),
  rule("github_actions.comment_trigger_run", "medium", "Comment-triggered workflow runs shell commands", "Gate comment-triggered commands behind explicit maintainer authorization."),
  rule("github_actions.cache_restore_pr", "medium", "PR-triggered workflow uses broad cache restore keys", "Avoid broad restore-keys in untrusted PR-triggered workflows."),
  rule("github_actions.artifact_execution", "high", "Workflow downloads artifacts and executes commands", "Do not execute downloaded artifacts unless their producer and contents are trusted."),
  rule("github_actions.oidc_cloud_deploy", "medium", "Workflow grants OIDC tokens and runs cloud deployment commands", "Constrain OIDC trust policies to specific refs, environments, and audiences."),
  rule("github_actions.run.recursive_delete", "high", "Risky GitHub Actions recursive delete command", "Guard recursive deletes and require manual approval."),
  rule("github_actions.run.remote_code_execution", "high", "Risky GitHub Actions remote shell execution", "Avoid piping remote downloads directly into shells."),
  rule("github_actions.run.world_writable", "medium", "Risky GitHub Actions world-writable permissions", "Avoid chmod -R 777 in workflow run commands."),
  rule("github_actions.run.sudo", "medium", "Risky GitHub Actions elevated privilege use", "Require review before privileged workflow commands."),
  rule("mcp.shell_tool", "medium", "MCP configuration can launch a shell", "Restrict shell-capable MCP servers."),
  rule("mcp.broad_filesystem", "medium", "MCP configuration may expose broad filesystem access", "Limit filesystem MCP access to project-specific directories."),
  rule("mcp.inline_secret", "high", "MCP configuration appears to contain inline secret values", "Move secret values out of MCP config files."),
  rule("mcp.authorization_passthrough", "medium", "MCP configuration forwards authorization headers", "Avoid passing user or workspace tokens through unreviewed MCP server configuration."),
  rule("mcp.oauth_client_config", "medium", "MCP configuration includes OAuth client settings", "Review OAuth scopes, redirect URIs, and token handling before exposing the MCP server to agents."),
  rule("mcp.remote_url", "medium", "MCP configuration references a remote server URL", "Review remote MCP servers before exposing agent tools or repository context."),
  rule("mcp.private_network_url", "medium", "MCP configuration references a private network URL", "Limit MCP access to private network services unless the service is intended for agent use."),
  rule("mcp.metadata_endpoint", "high", "MCP configuration references a cloud metadata endpoint", "Remove metadata endpoint access from MCP configuration and review credential exposure."),
  rule("secret.stripe_key", "high", "Stripe live API key is present", "Rotate the key and move it to scoped secret storage."),
  rule("secret.google_api_key", "high", "Google API key is present", "Restrict the key scope and move it to secret storage."),
  rule("secret.slack_token", "high", "Slack token is present", "Rotate the token and use scoped secret storage."),
  rule("secret.slack_app_token", "high", "Slack app-level token is present", "Rotate the token and use scoped secret storage."),
  rule("secret.jwt_token", "medium", "Hardcoded JWT token detected", "Tokens should be generated dynamically, not stored in source files."),
  rule("python.unpinned_requirement", "low", "Unpinned Python dependency", "Pin dependency versions for reproducible agent and CI runs."),
  rule("python.missing_requires_python", "info", "pyproject.toml does not declare requires-python", "Declare supported Python versions."),
  rule("doctor.node", "info", "Node.js runtime", "Use Node.js 20 or newer."),
  rule("doctor.git", "info", "Git repository check", "Run AgentReady inside a project repository."),
  rule("doctor.write", "info", "Workspace write access", "Ensure report output and init can write to the workspace.")
];

export const RULE_BY_ID = new Map(RULE_CATALOG.map((item) => [item.id, item]));

export function enrichFindings(findings) {
  return findings.map((finding) => {
    const metadata = RULE_BY_ID.get(finding.id);
    const category = finding.category || metadata?.category || categoryForRule(finding.id);
    const why = finding.why || metadata?.why || whyForCategory(category);
    // Spread finding first so computed values override undefined fields from finding
    return {
      ...finding,
      category,
      why
    };
  });
}

export function formatRules(format = "text", filters = {}) {
  const rules = RULE_CATALOG.filter((item) => {
    if (filters.category && item.category !== filters.category) {
      return false;
    }
    if (filters.severity && item.defaultSeverity !== filters.severity) {
      return false;
    }
    return true;
  });

  if (format === "json") {
    return `${JSON.stringify(rules, null, 2)}\n`;
  }

  if (format === "markdown") {
    const lines = [
      "# AgentReady Rule Catalog",
      "",
      "| Rule | Default Severity | Category | Description |",
      "| --- | --- | --- | --- |"
    ];

    for (const item of rules) {
      lines.push(`| \`${item.id}\` | ${item.defaultSeverity} | ${item.category} | ${escapeMarkdown(item.description)} |`);
    }

    return `${lines.join("\n")}\n`;
  }

  return rules.map((item) => `${item.id} [${item.defaultSeverity}] [${item.category}] ${item.description}`).join("\n");
}

function rule(id, defaultSeverity, description, recommendation) {
  const category = categoryForRule(id);
  return {
    id,
    defaultSeverity,
    category,
    description,
    recommendation,
    why: whyForCategory(category)
  };
}

function categoryForRule(id) {
  if (id.startsWith("secret.")) {
    return "secrets";
  }
  if (id.startsWith("github_actions.")) {
    return "github-actions";
  }
  if (id.startsWith("mcp.")) {
    return "mcp";
  }
  if (id.startsWith("package.")) {
    return "package";
  }
  if (id.startsWith("python.")) {
    return "python";
  }
  if (id.startsWith("script.")) {
    return "shell";
  }
  if (id.startsWith("agent.")) {
    return "agent-boundaries";
  }
  if (id.startsWith("doctor.")) {
    return "environment";
  }
  return "general";
}

function whyForCategory(category) {
  const descriptions = {
    "agent-boundaries": "AI coding agents need explicit project boundaries so they avoid sensitive files and risky operations.",
    "environment": "A predictable local environment makes agent and CI behavior easier to reproduce.",
    "github-actions": "AI-generated changes often touch CI; overbroad workflow permissions can expose secrets or write access.",
    "mcp": "MCP servers can expose tools and local resources to agents, so broad access should be reviewed before use.",
    "package": "Package scripts can execute during installs or agent-run commands, which makes them part of the agent trust boundary.",
    "python": "Pinned Python metadata helps agents and CI reproduce the same environment.",
    "secrets": "Secrets in agent-readable files may be copied into prompts, logs, reports, or generated patches.",
    "shell": "Shell commands can delete files, fetch remote code, or escalate privileges when run by agents or CI."
  };

  return descriptions[category] || "This finding affects the safety or reproducibility of AI-assisted development.";
}

// escapeMarkdown is imported from utils.js
