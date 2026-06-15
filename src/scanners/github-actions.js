import { classifyDangerousCommand } from "./shell.js";
import { escapeRegExp, redact } from "./utils.js";

export function scanGitHubActions(relativePath, content) {
  if (!relativePath.startsWith(".github/workflows/") || !/\.(?:yml|yaml)$/i.test(relativePath)) {
    return [];
  }

  const findings = [];
  const lines = content.split(/\r?\n/);
  let inRunBlock = false;
  let runBlockIndent = 0;
  let inOnBlock = false;
  let onBlockIndent = 0;
  const pullRequestTargetLines = [];
  const checkoutUses = [];
  const triggers = new Map();
  const cacheUses = [];
  const restoreKeys = [];
  const artifactDownloads = [];
  const runCommands = [];
  const idTokenWrites = [];

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const trimmed = line.trim();
    const indent = getIndent(line);

    if (inRunBlock) {
      if (!trimmed) {
        continue;
      }

      if (indent <= runBlockIndent) {
        inRunBlock = false;
      } else {
        if (!trimmed.startsWith("#")) {
          runCommands.push({
            line: index + 1,
            command: trimmed
          });
          findings.push(...scanGitHubActionRunCommand(relativePath, trimmed, index + 1));
        }
        continue;
      }
    }

    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }

    if (inOnBlock && trimmed && indent <= onBlockIndent) {
      inOnBlock = false;
    }

    let reportedPullRequestTarget = false;
    const onMatch = line.match(/^(\s*)on\s*:\s*(.*)$/);
    if (onMatch) {
      const value = onMatch[2].trim();
      if (!value) {
        inOnBlock = true;
        onBlockIndent = indent;
      }
      if (containsPullRequestTarget(value)) {
        findings.push(pullRequestTargetFinding(relativePath, index + 1, trimmed));
        pullRequestTargetLines.push(index + 1);
        reportedPullRequestTarget = true;
      }
      recordTriggers(triggers, value, index + 1);
    } else if (inOnBlock && containsPullRequestTarget(trimmed)) {
      findings.push(pullRequestTargetFinding(relativePath, index + 1, trimmed));
      pullRequestTargetLines.push(index + 1);
      reportedPullRequestTarget = true;
    }

    if (inOnBlock) {
      recordTriggers(triggers, trimmed, index + 1);
    }

    if (!reportedPullRequestTarget && !onMatch && /^\s*pull_request_target\s*:/.test(line)) {
      findings.push(pullRequestTargetFinding(relativePath, index + 1, trimmed));
      pullRequestTargetLines.push(index + 1);
    }

    if (/permissions\s*:\s*write-all/.test(line)) {
      findings.push({
        id: "github_actions.write_all",
        severity: "medium",
        title: "GitHub Actions grants write-all permissions",
        file: relativePath,
        line: index + 1,
        evidence: line.trim(),
        recommendation: "Use least-privilege permissions such as contents: read unless write access is required."
      });
    }

    if (/^\s*id-token\s*:\s*write\s*$/.test(line)) {
      idTokenWrites.push({
        line: index + 1,
        evidence: trimmed
      });
    }

    const writePermission = line.match(/^\s*(actions|checks|contents|deployments|issues|packages|pull-requests|statuses)\s*:\s*write\s*$/);
    if (writePermission) {
      findings.push({
        id: "github_actions.write_permission",
        severity: "medium",
        title: `GitHub Actions grants ${writePermission[1]} write permission`,
        file: relativePath,
        line: index + 1,
        evidence: trimmed,
        recommendation: "Use least-privilege permissions and grant write access only to jobs that require it."
      });
    }

    if (/^\s*secrets\s*:\s*inherit\s*$/.test(line)) {
      findings.push({
        id: "github_actions.secrets_inherit",
        severity: "medium",
        title: "GitHub Actions inherits all caller secrets",
        file: relativePath,
        line: index + 1,
        evidence: trimmed,
        recommendation: "Pass only the specific secrets required by the reusable workflow."
      });
    }

    if (/persist-credentials\s*:\s*true/.test(line)) {
      findings.push({
        id: "github_actions.persist_credentials",
        severity: "low",
        title: "actions/checkout persists credentials",
        file: relativePath,
        line: index + 1,
        evidence: line.trim(),
        recommendation: "Set persist-credentials: false when jobs do not need to push to the repository."
      });
    }

    const uses = parseUsesReference(line);
    if (uses) {
      if (isExternalUsesReference(uses) && !isPinnedUsesReference(uses)) {
        findings.push({
          id: "github_actions.unpinned_action",
          severity: "medium",
          title: "GitHub Actions uses a floating external action or reusable workflow reference",
          file: relativePath,
          line: index + 1,
          evidence: `uses: ${uses}`,
          recommendation: "Use a full commit SHA or reviewed release tag instead of a branch or missing ref."
        });
      }

      if (isCheckoutReference(uses)) {
        checkoutUses.push({
          line: index + 1,
          evidence: `uses: ${uses}`
        });
      }

      if (isCacheReference(uses)) {
        cacheUses.push({
          line: index + 1,
          evidence: `uses: ${uses}`
        });
      }

      if (isArtifactDownloadReference(uses)) {
        artifactDownloads.push({
          line: index + 1,
          evidence: `uses: ${uses}`
        });
      }
    }

    if (/^\s*restore-keys\s*:/.test(line)) {
      restoreKeys.push({
        line: index + 1,
        evidence: trimmed
      });
    }

    const runMatch = line.match(/^\s*-?\s*run\s*:\s*(.*)$/);
    if (runMatch) {
      const command = runMatch[1].trim();
      if (/^[>|][+-]?$/.test(command)) {
        inRunBlock = true;
        runBlockIndent = indent;
      } else {
        runCommands.push({
          line: index + 1,
          command
        });
        findings.push(...scanGitHubActionRunCommand(relativePath, command, index + 1));
      }
    }
  }

  if (pullRequestTargetLines.length > 0 && checkoutUses.length > 0) {
    for (const checkout of checkoutUses) {
      findings.push({
        id: "github_actions.pull_request_target_checkout",
        severity: "high",
        title: "pull_request_target workflow checks out repository code",
        file: relativePath,
        line: checkout.line,
        evidence: checkout.evidence,
        recommendation: "Avoid checking out pull request code in pull_request_target workflows, or restrict checkout to trusted refs with no secrets."
      });
    }
  }

  findings.push(...scanWorkflowLevelRisks(relativePath, {
    triggers,
    cacheUses,
    restoreKeys,
    artifactDownloads,
    runCommands,
    idTokenWrites
  }));

  return findings;
}

function pullRequestTargetFinding(relativePath, line, evidence) {
  return {
    id: "github_actions.pull_request_target",
    severity: "high",
    title: "GitHub Actions uses pull_request_target",
    file: relativePath,
    line,
    evidence,
    recommendation: "Avoid pull_request_target for untrusted code, or heavily restrict checkout, scripts, and secrets."
  };
}

function containsPullRequestTarget(value) {
  return /(^|[^A-Za-z0-9_-])pull_request_target([^A-Za-z0-9_-]|$)/.test(value);
}

function scanWorkflowLevelRisks(relativePath, context) {
  const findings = [];

  const workflowRun = context.triggers.get("workflow_run");
  if (workflowRun) {
    findings.push({
      id: "github_actions.workflow_run",
      severity: "medium",
      title: "GitHub Actions uses workflow_run",
      file: relativePath,
      line: workflowRun.line,
      evidence: workflowRun.evidence,
      recommendation: "Review workflow_run chains carefully; do not grant secrets or write access to artifacts from untrusted workflows."
    });
  }

  const commentTrigger = context.triggers.get("issue_comment") || context.triggers.get("pull_request_review_comment");
  if (commentTrigger && context.runCommands.length > 0) {
    findings.push({
      id: "github_actions.comment_trigger_run",
      severity: "medium",
      title: "Comment-triggered workflow runs shell commands",
      file: relativePath,
      line: context.runCommands[0].line,
      evidence: context.runCommands[0].command,
      recommendation: "Gate comment-triggered commands behind explicit maintainer authorization and avoid running untrusted input."
    });
  }

  if (hasPullRequestTrigger(context.triggers) && context.cacheUses.length > 0 && context.restoreKeys.length > 0) {
    findings.push({
      id: "github_actions.cache_restore_pr",
      severity: "medium",
      title: "PR-triggered workflow uses broad cache restore keys",
      file: relativePath,
      line: context.restoreKeys[0].line,
      evidence: context.restoreKeys[0].evidence,
      recommendation: "Avoid broad restore-keys in PR-triggered workflows, or isolate caches by trusted refs and lockfiles."
    });
  }

  const artifactExecution = context.artifactDownloads.length > 0
    ? context.runCommands.find((item) => /\b(chmod\s+\+x|bash|sh|node|python|pwsh|powershell)\b/i.test(item.command))
    : null;
  if (artifactExecution) {
    findings.push({
      id: "github_actions.artifact_execution",
      severity: "high",
      title: "Workflow downloads artifacts and executes commands",
      file: relativePath,
      line: artifactExecution.line,
      evidence: artifactExecution.command,
      recommendation: "Do not execute downloaded artifacts unless their producer workflow and contents are trusted."
    });
  }

  const cloudDeploy = context.idTokenWrites.length > 0
    ? context.runCommands.find((item) => /\b(aws|gcloud|az|kubectl|helm|pulumi|terraform)\b/i.test(item.command))
    : null;
  if (cloudDeploy) {
    findings.push({
      id: "github_actions.oidc_cloud_deploy",
      severity: "medium",
      title: "Workflow grants OIDC tokens and runs cloud deployment commands",
      file: relativePath,
      line: cloudDeploy.line,
      evidence: cloudDeploy.command,
      recommendation: "Constrain cloud OIDC trust policies to specific refs, environments, repositories, and audiences."
    });
  }

  return findings;
}

function scanGitHubActionRunCommand(relativePath, command, line) {
  return classifyDangerousCommand(command).map((commandFinding) => ({
    id: `github_actions.run.${commandFinding.id}`,
    severity: commandFinding.severity,
    title: "Risky GitHub Actions run command detected",
    file: relativePath,
    line,
    evidence: redact(String(command).trim()),
    recommendation: commandFinding.recommendation
  }));
}

function recordTriggers(triggers, value, line) {
  for (const trigger of ["pull_request", "pull_request_target", "workflow_run", "issue_comment", "pull_request_review_comment"]) {
    if (containsWord(value, trigger) && !triggers.has(trigger)) {
      triggers.set(trigger, { line, evidence: value });
    }
  }
}

function hasPullRequestTrigger(triggers) {
  return triggers.has("pull_request") || triggers.has("pull_request_target");
}

const wordRegExpCache = new Map();

function containsWord(value, word) {
  let re = wordRegExpCache.get(word);
  if (!re) {
    re = new RegExp(`(^|[^A-Za-z0-9_-])${escapeRegExp(word)}([^A-Za-z0-9_-]|$)`);
    wordRegExpCache.set(word, re);
  }
  return re.test(value);
}

function getIndent(line) {
  return line.match(/^\s*/)?.[0].length || 0;
}

function parseUsesReference(line) {
  const match = line.match(/^\s*-?\s*uses\s*:\s*(.+?)\s*$/);
  if (!match) {
    return null;
  }

  return match[1]
    .replace(/\s+#.*$/, "")
    .trim()
    .replace(/^['"]|['"]$/g, "");
}

function isExternalUsesReference(value) {
  return !value.startsWith("./") && !value.startsWith("../") && !value.startsWith("docker://");
}

function isPinnedUsesReference(value) {
  const atIndex = value.lastIndexOf("@");
  if (atIndex === -1) {
    return false;
  }
  const ref = value.slice(atIndex + 1);
  return /^[a-f0-9]{40}$/i.test(ref) || /^v?\d+(?:\.\d+){0,2}(?:[-+][A-Za-z0-9.-]+)?$/.test(ref);
}

function isCheckoutReference(value) {
  return /^actions\/checkout(?:@|$)/i.test(value);
}

function isCacheReference(value) {
  return /^actions\/cache(?:@|$)/i.test(value);
}

function isArtifactDownloadReference(value) {
  return /^actions\/download-artifact(?:@|$)/i.test(value);
}
