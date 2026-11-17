import path from "node:path";
import { redact, splitLines } from "./utils.js";

const SHELL_LIKE_FILE_NAMES = new Set([
  ".bash_profile",
  ".bashrc",
  ".profile",
  ".zprofile",
  ".zshrc",
  "Brewfile",
  "Dockerfile",
  "dockerfile",
  "Justfile",
  "Makefile",
  "makefile",
  "Procfile",
  "Rakefile",
  "Taskfile",
  "Vagrantfile"
]);

export function scanDangerousShell(relativePath, content) {
  const basename = path.basename(relativePath);
  if (!/\.(?:sh|ps1|bash|zsh|cmd|bat)$/i.test(relativePath) && !SHELL_LIKE_FILE_NAMES.has(basename)) {
    return [];
  }

  return scanDangerousCommandLines(relativePath, content, "script.dangerous_command");
}

function scanDangerousCommandLines(relativePath, content, idPrefix) {
  const findings = [];
  const lines = splitLines(content);
  const isPowerShell = /\.ps1$/i.test(relativePath);
  const isBatch = /\.(?:cmd|bat)$/i.test(relativePath);
  const continuationPattern = isBatch ? /\s\^\s*$/ : isPowerShell ? /(?:\\|\s`)\s*$/ : /\\\s*$/;
  const stripContinuation = (line) =>
    line.replace(isBatch ? /\^\s*$/ : isPowerShell ? /(?:\\|`)\s*$/ : /\\\s*$/, "").trim();
  let inBlockComment = false;

  for (let index = 0; index < lines.length; index += 1) {
    let text = lines[index];

    if (isPowerShell) {
      if (inBlockComment) {
        const end = text.indexOf("#>");
        if (end === -1) {
          continue;
        }
        text = text.slice(end + 2);
        inBlockComment = false;
      }

      // Strip leading PowerShell block comments; an unterminated one swallows
      // the following lines, a closed one leaves any trailing code in play.
      // Gated to .ps1 so `<#` redirections in POSIX sh cannot hide later lines.
      text = text.trimStart();
      while (text.startsWith("<#")) {
        const end = text.indexOf("#>");
        if (end === -1) {
          inBlockComment = true;
          break;
        }
        text = text.slice(end + 2).trimStart();
      }
      if (inBlockComment) {
        continue;
      }
    } else {
      text = text.trimStart();
    }

    // Comment classification must happen before continuation joining: in
    // POSIX sh a backslash does not continue a comment, so `# step \` must
    // not swallow the next (real) command line.
    const isComment = isBatch
      ? text.startsWith("::") || /^rem\b/i.test(text)
      : text.startsWith("#");
    if (!text.trim() || isComment) {
      continue;
    }

    const lineNumber = index + 1;

    // Join continuation lines (\ in sh, ` in PowerShell, ^ in cmd) in O(N)
    // using an accumulator array so long multi-line commands never re-scan
    // from index 0 on each continuation.
    if (continuationPattern.test(text) && index + 1 < lines.length) {
      const parts = [stripContinuation(text)];
      let rawCurrent = text;
      while (continuationPattern.test(rawCurrent) && index + 1 < lines.length) {
        index += 1;
        rawCurrent = lines[index];
        parts.push(stripContinuation(rawCurrent));
      }
      text = parts.filter(Boolean).join(" ");
    }

    const trimmed = text.trim();
    const commandFindings = classifyDangerousCommand(trimmed);
    for (const commandFinding of commandFindings) {
      findings.push({
        id: `${idPrefix}.${commandFinding.id}`,
        severity: commandFinding.severity,
        title: "Risky command detected",
        file: relativePath,
        line: lineNumber,
        evidence: redact(trimmed),
        recommendation: commandFinding.recommendation
      });
    }
  }

  return findings;
}

const RM_COMMAND = /\brm\s+/i;
const RM_RECURSIVE_FLAG = /(?:^|\s)(?:-(?=[A-Za-z]*r)[A-Za-z]+|--recursive)(?=\s|$)/i;
const RM_FORCE_FLAG = /(?:^|\s)(?:-(?=[A-Za-z]*f)[A-Za-z]+|--force)(?=\s|$)/i;
// A scoped temp subdirectory (/tmp/<name>, /var/tmp/<name>) is routine CI
// cleanup, not a broad delete, so the bare-slash target excludes it;
// deleting /tmp itself still matches. $(pwd)/$PWD roots wipe the entire
// working directory, so they count as broad; other variable roots stay
// unflagged to keep routine `rm -rf $TMP_DIR` cleanup quiet.
const BROAD_DELETE_ROOTS = String.raw`\/(?!(?:var\/)?tmp\/[^\s"'])|\*|~|\$(?:HOME|\{HOME\}|PWD|\{PWD\}|\(pwd\))|%USERPROFILE%|[A-Za-z]:[\\/]`;
const RM_BROAD_TARGET = new RegExp(String.raw`(?:^|\s)["']?(?:${BROAD_DELETE_ROOTS})`, "i");

// Quoted text is inert for the echo/printf guard below. Single quotes never
// expand, and a double-quoted string only runs code when it contains `$(` or a
// backtick, so those are left in place and still count as separators.
const INERT_QUOTED_TEXT = /'[^']*'|"(?:[^"\\`$]|\\.|\$(?!\())*"/g;
const COMMAND_SEPARATORS = /&&|\|\||;|\r?\n|(?<![<>0-9&])&(?![>&])|(?<!\|)\|(?!\|)/;

// Remote download piped into an interpreter that executes stdin. A bare
// `| python3` (or `python3 -`) runs the payload, while `| python -m json.tool`
// only pretty-prints it, so interpreters other than shells must end the
// pipeline without a script argument.
const DOWNLOAD_STAGE = /\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b/i;
const PIPE_ELEVATION_PREFIX = String.raw`(?:sudo\s+(?:-\S+\s+)*)?(?:(?:\/[\w.-]+)*\/env\s+(?:[^=\s]+=\S*\s+)*|env\s+(?:[^=\s]+=\S*\s+)*)?`;
const PIPE_SHELL_RECEIVER = new RegExp(
  String.raw`^\s*${PIPE_ELEVATION_PREFIX}(?:(?:\/[\w.-]+)*\/(?:sh|bash|zsh|dash|ksh|pwsh|powershell)|sh|bash|zsh|dash|ksh|pwsh|powershell|iex|Invoke-Expression)\b`,
  "i"
);
const PIPE_INTERPRETER_RECEIVER = new RegExp(
  String.raw`^\s*${PIPE_ELEVATION_PREFIX}(?:(?:\/[\w.-]+)*\/)?(?:python[0-9.]*|perl|ruby|node)(?:\s+-)?[\s)"'\`]*$`,
  "i"
);
// Executing the output of a download via command/process substitution:
// `bash -c "$(curl ...)"`, `eval "$(curl ...)"`, `source <(curl ...)`.
const REMOTE_SUBSTITUTION =
  /\b(?:(?:\/[\w.-]+)*\/(?:ba|z|da|k)?sh|(?:ba|z|da|k)?sh|eval|source)(?:\s+-[A-Za-z]+)*\s+["']?(?:\$\(|`|<\()\s*(?:sudo\s+)?(?:curl|wget)\b/i;
// PowerShell evaluates a download directly: `iex (irm ...)`,
// `iex ((New-Object Net.WebClient).DownloadString(...))`.
const REMOTE_POWERSHELL_EVAL = /\b(?:iex|Invoke-Expression)\b[\s(]*(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|New-Object\s+(?:System\.)?Net\.WebClient\s*\)?\s*\.\s*Download(?:String|Data))/i;

function hasRemotePipeExecution(command) {
  if (!command.includes("|")) {
    return false;
  }

  for (const pipeline of command.split(/&&|\|\||;|\r?\n|(?<![<>0-9&])&(?![>&])/)) {
    if (!pipeline.includes("|")) {
      continue;
    }
    const stages = pipeline.split(/(?<!\|)\|(?!\|)/);
    for (let index = 0; index < stages.length - 1; index += 1) {
      if (!DOWNLOAD_STAGE.test(stages[index])) {
        continue;
      }
      const nextStage = stages[index + 1];
      if (PIPE_SHELL_RECEIVER.test(nextStage) || PIPE_INTERPRETER_RECEIVER.test(nextStage)) {
        return true;
      }
    }
  }

  return false;
}

export function classifyDangerousCommand(command) {
  const findings = [];
  const found = new Set();
  const push = (finding) => {
    if (!found.has(finding.id)) {
      found.add(finding.id);
      findings.push(finding);
    }
  };

  // A line that only prints text is not executing anything: install scripts
  // commonly echo instructions like `echo "run: sudo systemctl ..."` or
  // `echo 'install with: curl ... | sh'`. Only skip when no shell separator
  // could chain a real command after the echo; separators inside inert
  // quoted text do not count.
  const withoutInertQuotes = command.replace(INERT_QUOTED_TEXT, '""');
  if (
    /^\s*(echo|printf)\b/i.test(command) &&
    !COMMAND_SEPARATORS.test(withoutInertQuotes) &&
    !/\$\(|`/.test(withoutInertQuotes)
  ) {
    return findings;
  }

  // Remote download piped to shell must see the whole pipeline: the pipe that
  // feeds the shell is itself a segment separator. Allow sudo/env and full
  // interpreter paths (`/bin/sh`) between the pipe and the shell.
  if (
    hasRemotePipeExecution(command) ||
    REMOTE_SUBSTITUTION.test(command) ||
    REMOTE_POWERSHELL_EVAL.test(command) ||
    /\b(?:(?:\/[\w.-]+)*\/)?(?:bash|sh|zsh|dash|ksh)\s+<\s*\(\s*(?:curl|wget)\b/i.test(command)
  ) {
    push({
      id: "remote_code_execution",
      severity: "high",
      recommendation: "Avoid piping remote downloads directly into shells; pin scripts and verify checksums first."
    });
  }

  // Everything else is checked per command segment so a match cannot span
  // `&&`, `;`, `&`, `\n`, or `|` — `rm -rf dist && cp -r build /usr/share`
  // must not read as one `rm ... /usr/share`.
  for (const segment of command.split(COMMAND_SEPARATORS)) {
    classifyCommandSegment(segment, push);
  }

  return findings;
}

function classifyCommandSegment(segment, push) {
  // Echoed instructions inside one segment are plain text, not execution.
  if (/^\s*(echo|printf)\b/i.test(segment)) {
    return;
  }

  // Recursive delete: rm -rf, rm -fr, rm -r -f, rm --recursive --force with a
  // broad target, plus the PowerShell and cmd.exe equivalents.
  if (
    (RM_COMMAND.test(segment) && RM_RECURSIVE_FLAG.test(segment) && RM_FORCE_FLAG.test(segment) && RM_BROAD_TARGET.test(segment)) ||
    (/\bRemove-Item\b/i.test(segment) && /-Recurse\b/i.test(segment) && /-Force\b/i.test(segment) &&
      /(?:[A-Za-z]:[\\/]|\*|~|\$env:\w+|\$HOME)/i.test(segment)) ||
    (/\b(?:del|rd|rmdir)\b/i.test(segment) && /\s\/s\b/i.test(segment) &&
      /(?:[A-Za-z]:[\\/]|\*|%\w+%)/.test(segment))
  ) {
    push({
      id: "recursive_delete",
      severity: "high",
      recommendation: "Guard recursive deletes with explicit path checks and require manual approval before agents run them."
    });
  }

  // World-writable permissions: chmod -R 777, chmod 777 -R, chmod --recursive 777, chmod -R a+rwx
  if (/\bchmod\s+(?:-R\s+(?:777|0777|a\+rwx)|(?:777|0777|a\+rwx)\s+-R|--recursive\s+(?:777|0777|a\+rwx))/i.test(segment)) {
    push({
      id: "world_writable",
      severity: "medium",
      recommendation: "Avoid world-writable permissions and scope chmod to the minimum required mode and path."
    });
  }

  // Sudo at command position only: `apt-get install -y sudo` ships the
  // package, it does not elevate.
  if (hasSudoAtCommandPosition(segment)) {
    push({
      id: "sudo",
      severity: "medium",
      recommendation: "Require manual approval before agents run commands with elevated privileges."
    });
  }
}

function hasSudoAtCommandPosition(segment) {
  const stripped = segment
    .trim()
    .replace(/^(?:RUN|CMD)\s+/, "")
    .replace(/^[-@+]+\s*/, "")
    .replace(/^(?:if|then|elif|else|until|while|do)\s+/, "")
    .replace(/^(?:\w+=\S*\s+)+/, "")
    .replace(/^(?:exec|env|command|nice|nohup|time|xargs)\s+(?:-\S+\s+)*/i, "")
    .replace(/^[$(`\s]+/, "");
  return /^sudo\b/i.test(stripped);
}
