import { classifyDangerousCommand } from "./shell.js";
import { escapeRegExp } from "../utils.js";
import { redact, splitLines } from "./utils.js";

function isGitHubActionsFile(relativePath) {
  const normalized = String(relativePath).replaceAll("\\", "/");
  if (!/\.(?:yml|yaml)$/i.test(normalized)) {
    return false;
  }
  return (
    normalized.startsWith(".github/workflows/") ||
    /^\.github\/actions\/.+\/action\.(?:yml|yaml)$/i.test(normalized) ||
    /^action\.(?:yml|yaml)$/i.test(normalized)
  );
}

export function scanGitHubActions(relativePath, content) {
  if (!isGitHubActionsFile(relativePath)) {
    return [];
  }

  const findings = [];
  const lines = splitLines(content);
  let inRunBlock = false;
  let runBlockIndent = 0;
  let runBlockStyle = "literal";
  let foldedRunLines = [];
  let foldedRunStartLine = 0;
  let inOnBlock = false;
  let inOnFlowArray = false;
  let onBlockIndent = 0;
  const pullRequestTargetLines = [];
  const checkoutUses = [];
  const triggers = new Map();
  const cacheUses = [];
  const restoreKeys = [];
  const artifactDownloads = [];
  const runCommands = [];
  const idTokenWrites = [];

  const emitRunCommand = (command, commandLine) => {
    if (!command) {
      return;
    }
    runCommands.push({
      line: commandLine,
      command
    });
    findings.push(...scanGitHubActionRunCommand(relativePath, command, commandLine));
    findings.push(...scanRunInjection(relativePath, command, commandLine));
  };

  const flushFoldedRun = () => {
    if (foldedRunLines.length > 0) {
      emitRunCommand(foldedRunLines.join(" "), foldedRunStartLine);
      foldedRunLines = [];
      foldedRunStartLine = 0;
    }
  };

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const trimmed = line.trim();
    const indent = getIndent(line);

    if (inRunBlock) {
      if (!trimmed) {
        if (runBlockStyle === "folded") {
          flushFoldedRun();
        }
        continue;
      }

      if (indent <= runBlockIndent) {
        if (runBlockStyle === "folded") {
          flushFoldedRun();
        }
        inRunBlock = false;
      } else {
        if (runBlockStyle === "folded") {
          if (!trimmed.startsWith("#")) {
            if (foldedRunLines.length === 0) {
              foldedRunStartLine = index + 1;
            }
            foldedRunLines.push(trimmed);
          }
        } else if (!trimmed.startsWith("#")) {
          // Join backslash continuations in O(N) so a piped download split
          // across lines still reads as one command without quadratic re-scans.
          const commandLine = index + 1;
          let command = trimmed;
          if (/\\\s*$/.test(command) && index + 1 < lines.length) {
            const parts = [command.replace(/\\\s*$/, "").trim()];
            let rawCurrent = command;
            while (/\\\s*$/.test(rawCurrent) && index + 1 < lines.length) {
              const next = lines[index + 1];
              if (next.trim() && getIndent(next) <= runBlockIndent) {
                break;
              }
              index += 1;
              rawCurrent = next.trim();
              parts.push(rawCurrent.replace(/\\\s*$/, "").trim());
            }
            command = parts.filter(Boolean).join(" ");
          }
          emitRunCommand(command, commandLine);
        }
        continue;
      }
    }

    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }

    if (inOnBlock && !inOnFlowArray && trimmed && indent <= onBlockIndent) {
      inOnBlock = false;
    }

    let reportedPullRequestTarget = false;
    const onMatch = line.match(/^(\s*)(?:on|["']on["'])\s*:\s*(.*)$/);
    if (onMatch) {
      // Strip a trailing comment first: `on:  # PR triggers` still opens a
      // trigger block, and prose in the comment must not register as a trigger.
      const value = stripYamlComment(onMatch[2]).trim();
      if (!value) {
        inOnBlock = true;
        inOnFlowArray = false;
        onBlockIndent = indent;
      } else if (value.includes("[") && !value.includes("]")) {
        inOnBlock = true;
        inOnFlowArray = true;
        onBlockIndent = indent;
      }
      if (containsPullRequestTarget(value)) {
        findings.push(pullRequestTargetFinding(relativePath, index + 1, trimmed));
        pullRequestTargetLines.push(index + 1);
        reportedPullRequestTarget = true;
      }
      recordTriggers(triggers, value, index + 1);
    } else if (inOnBlock) {
      const cleanedTrigger = stripYamlComment(trimmed);
      if (containsPullRequestTarget(cleanedTrigger)) {
        findings.push(pullRequestTargetFinding(relativePath, index + 1, trimmed));
        pullRequestTargetLines.push(index + 1);
        reportedPullRequestTarget = true;
      }
      recordTriggers(triggers, cleanedTrigger, index + 1);
      if (inOnFlowArray && cleanedTrigger.includes("]")) {
        inOnBlock = false;
        inOnFlowArray = false;
      }
    }

    if (!reportedPullRequestTarget && !onMatch && /^\s*pull_request_target\s*:/.test(line)) {
      findings.push(pullRequestTargetFinding(relativePath, index + 1, trimmed));
      pullRequestTargetLines.push(index + 1);
    }

    if (/^\s*(?:-\s*)?permissions\s*:\s*["']?write-all["']?(?:\s+#.*)?\s*$/.test(line)) {
      findings.push({
        id: "github_actions.write_all",
        severity: "medium",
        title: "GitHub Actions grants write-all permissions",
        file: relativePath,
        line: index + 1,
        evidence: redact(line.trim()),
        recommendation: "Use least-privilege permissions such as contents: read unless write access is required."
      });
    }

    if (/^\s*id-token\s*:\s*["']?write["']?\s*,?(?:\s+#.*)?\s*$/.test(line)) {
      idTokenWrites.push({
        line: index + 1,
        evidence: redact(trimmed)
      });
    }

    for (const permission of findWritePermissions(line)) {
      findings.push({
        id: "github_actions.write_permission",
        severity: "medium",
        title: `GitHub Actions grants ${permission.name} write permission`,
        file: relativePath,
        line: index + 1,
        // Block-style evidence stays the trimmed line so existing baseline
        // fingerprints remain valid.
        evidence: redact(permission.evidence ?? trimmed),
        recommendation: "Use least-privilege permissions and grant write access only to jobs that require it."
      });
    }

    if (/^\s*secrets\s*:\s*inherit(?:\s+#.*)?\s*$/.test(line)) {
      findings.push({
        id: "github_actions.secrets_inherit",
        severity: "medium",
        title: "GitHub Actions inherits all caller secrets",
        file: relativePath,
        line: index + 1,
        evidence: redact(trimmed),
        recommendation: "Pass only the specific secrets required by the reusable workflow."
      });
    }

    if (/^\s*persist-credentials\s*:\s*["']?true["']?(?:\s+#.*)?\s*$/.test(line)) {
      findings.push({
        id: "github_actions.persist_credentials",
        severity: "low",
        title: "actions/checkout persists credentials",
        file: relativePath,
        line: index + 1,
        evidence: redact(line.trim()),
        recommendation: "Set persist-credentials: false when jobs do not need to push to the repository."
      });
    }

    const uses = parseUsesReference(line);
    if (uses) {
      const redactedUses = redact(uses);
      if (isExternalUsesReference(uses) && !isPinnedUsesReference(uses)) {
        findings.push({
          id: "github_actions.unpinned_action",
          severity: "medium",
          title: "GitHub Actions uses a floating external action or reusable workflow reference",
          file: relativePath,
          line: index + 1,
          evidence: `uses: ${redactedUses}`,
          recommendation: "Use a full commit SHA or reviewed release tag instead of a branch or missing ref."
        });
      }

      if (isCheckoutReference(uses)) {
        checkoutUses.push({
          line: index + 1,
          evidence: `uses: ${redactedUses}`
        });
      }

      if (isCacheReference(uses)) {
        cacheUses.push({
          line: index + 1,
          evidence: `uses: ${redactedUses}`
        });
      }

      if (isArtifactDownloadReference(uses)) {
        artifactDownloads.push({
          line: index + 1,
          evidence: `uses: ${redactedUses}`
        });
      }
    }

    if (/^\s*restore-keys\s*:/.test(line)) {
      restoreKeys.push({
        line: index + 1,
        evidence: redact(trimmed)
      });
    }

    const runMatch = line.match(/^(\s*(?:-\s*)?)run\s*:\s*(.*)$/);
    if (runMatch) {
      // Use the column of `run:` itself (not `-`) so sibling step keys such as
      // `env:` or `shell:` at the same mapping level exit the run block cleanly.
      const runKeyIndent = runMatch[1].length;
      const command = runMatch[2].trim();
      const blockHeader = command.match(/^([>|])[0-9+-]{0,2}(?:\s+#.*)?$/);
      if (blockHeader) {
        inRunBlock = true;
        runBlockIndent = runKeyIndent;
        runBlockStyle = blockHeader[1] === ">" ? "folded" : "literal";
      } else if (!command || command.startsWith("#")) {
        inRunBlock = true;
        runBlockIndent = runKeyIndent;
        runBlockStyle = "folded";
      } else {
        emitRunCommand(command, index + 1);
      }
    }
  }

  flushFoldedRun();

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

const WRITE_PERMISSION_SCOPES = "actions|attestations|checks|contents|deployments|discussions|issues|packages|pages|pull-requests|repository-projects|statuses";
const BLOCK_WRITE_PERMISSION = new RegExp(String.raw`^\s*(${WRITE_PERMISSION_SCOPES})\s*:\s*["']?write["']?(\s*,)?(?:\s+#.*)?\s*$`);
const FLOW_PERMISSIONS = /^\s*permissions\s*:\s*\{([^}]*)\}/;
const FLOW_WRITE_PERMISSION = new RegExp(String.raw`(?:^|,)\s*["']?(${WRITE_PERMISSION_SCOPES})["']?\s*:\s*["']?write["']?\s*(?=,|$)`, "g");

/**
 * Write permissions declared on one line, in either block style
 * (`contents: write`) or flow style (`permissions: { contents: write }`).
 * Flow-style entries carry their own evidence so several on one line stay
 * distinct findings; block-style entries leave it unset and use the line.
 */
function findWritePermissions(line) {
  const block = line.match(BLOCK_WRITE_PERMISSION);
  if (block) {
    return [{ name: block[1], ...(block[2] ? { evidence: `${block[1]}: write` } : {}) }];
  }

  const flow = line.match(FLOW_PERMISSIONS);
  if (!flow) {
    return [];
  }
  return [...flow[1].matchAll(FLOW_WRITE_PERMISSION)].map((match) => ({
    name: match[1],
    evidence: `${match[1]}: write`
  }));
}

// Context values an outside contributor controls (issue/PR titles, bodies,
// branch names, commit messages, ...), per GitHub's script-injection guidance.
// Matched anywhere inside a `${{ ... }}` expression so wrappers such as
// `format(...)`, `toJSON(...)`, `||`, or bracket access cannot mask injection.
const UNTRUSTED_PROP = (names) => String.raw`(?:\.(?:${names})\b|\[\s*['"](?:${names})['"]\s*\])`;
const UNTRUSTED_CONTEXT = new RegExp(
  String.raw`\$\{\{(?:(?!\}\})[\s\S])*\b(?:github\.head_ref\b|github\.event` +
    String.raw`(?:\.(?:` +
    [
      String.raw`issue${UNTRUSTED_PROP("title|body")}`,
      String.raw`pull_request(?:\.head(?:\.(?:ref|label)\b|\.repo\.(?:default_branch|name)\b)|${UNTRUSTED_PROP("title|body")})`,
      String.raw`(?:comment|review|review_comment|discussion_comment|release)${UNTRUSTED_PROP("body")}`,
      String.raw`discussion${UNTRUSTED_PROP("title|body")}`,
      String.raw`pages\.[^}\s]*${UNTRUSTED_PROP("page_name")}`,
      String.raw`commits\.[^}\s]*(?:${UNTRUSTED_PROP("message")}|\.author${UNTRUSTED_PROP("email|name")})`,
      String.raw`head_commit(?:${UNTRUSTED_PROP("message")}|\.(?:author|committer)${UNTRUSTED_PROP("email|name")})`,
      String.raw`workflow_run(?:\.head_branch\b|\.head_commit(?:${UNTRUSTED_PROP("message")}|\.author${UNTRUSTED_PROP("email|name")})|\.pull_requests\.[^}\s]*\.head\.(?:ref|repo\.name)\b)`
    ].join("|") +
    String.raw`)))` +
    String.raw`(?:(?!\}\})[\s\S])*\}\}`
);

function scanRunInjection(relativePath, command, line) {
  if (!UNTRUSTED_CONTEXT.test(command)) {
    return [];
  }
  return [
    {
      id: "github_actions.script_injection",
      severity: "high",
      title: "Untrusted GitHub context is interpolated into a run command",
      file: relativePath,
      line,
      evidence: redact(String(command).trim()),
      recommendation: "Pass untrusted values through env: and reference them as shell variables instead of interpolating ${{ }} into the script."
    }
  ];
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
      evidence: redact(context.runCommands[0].command),
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
      evidence: redact(artifactExecution.command),
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
      evidence: redact(cloudDeploy.command),
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

function stripYamlComment(value) {
  // YAML comments start at `#` preceded by whitespace (or at value start).
  return value.replace(/(^|\s)#.*$/, "$1");
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
  return !value.startsWith("./") && !value.startsWith("../");
}

function isPinnedUsesReference(value) {
  if (value.startsWith("docker://")) {
    return /@sha256:[a-f0-9]{64}$/i.test(value);
  }
  const atIndex = value.lastIndexOf("@");
  if (atIndex === -1) {
    return false;
  }
  const ref = value.slice(atIndex + 1);
  if (/^[a-f0-9]{40}$/i.test(ref)) {
    return true;
  }
  // Reject 7+ digit bare numbers (`@1234567`), which are truncated commit SHAs
  // that happen to contain only decimal digits, not major release tags.
  if (/^\d{5,}$/.test(ref)) {
    return false;
  }
  return /^v?\d+(?:\.\d+){0,2}(?:[-+][A-Za-z0-9.-]+)?$/.test(ref);
}

function isCheckoutReference(value) {
  return /^actions\/checkout(?:@|$)/i.test(value);
}

function isCacheReference(value) {
  return /^actions\/cache(?:\/restore)?(?:@|$)/i.test(value);
}

function isArtifactDownloadReference(value) {
  return /^actions\/download-artifact(?:@|$)/i.test(value);
}
