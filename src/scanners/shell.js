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
  let inBlockComment = false;

  for (let index = 0; index < lines.length; index += 1) {
    let text = lines[index];

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

    // Comment classification must happen before continuation joining: in
    // POSIX sh a backslash does not continue a comment, so `# step \` must
    // not swallow the next (real) command line.
    if (!text.trim() || text.startsWith("#") || text.startsWith("::") || /^rem\b/i.test(text)) {
      continue;
    }

    const lineNumber = index + 1;

    // Join continuation lines (\ in sh, ` in PowerShell, ^ in cmd) so a piped
    // download split across lines still reads as one command. Backtick and
    // caret only continue after whitespace, so a closing backtick of command
    // substitution does not trigger a join.
    while (index + 1 < lines.length && /(?:\\|\s[`^])\s*$/.test(text)) {
      text = text.replace(/(?:\\|[`^])\s*$/, " ") + lines[index + 1].trim();
      index += 1;
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

const RECURSIVE_FORCE_FLAGS = /\brm\s+(?:-[A-Za-z]*r[A-Za-z]*\s+-[A-Za-z]*f[A-Za-z]*|-[A-Za-z]*f[A-Za-z]*\s+-[A-Za-z]*r[A-Za-z]*|-(?=[A-Za-z]*r)(?=[A-Za-z]*f)[A-Za-z]+|--recursive\s+--force|--force\s+--recursive)/i;
// A scoped temp subdirectory (/tmp/<name>, /var/tmp/<name>) is routine CI
// cleanup, not a broad delete, so the bare-slash target excludes it;
// deleting /tmp itself still matches. $(pwd)/$PWD roots wipe the entire
// working directory, so they count as broad; other variable roots stay
// unflagged to keep routine `rm -rf $TMP_DIR` cleanup quiet.
const BROAD_DELETE_ROOTS = String.raw`\/(?!(?:var\/)?tmp\/[^\s"'])|\*|~|\$(?:HOME|\{HOME\}|PWD|\{PWD\}|\(pwd\))|%USERPROFILE%`;
const RM_LATER_TARGET = new RegExp(String.raw`\brm\s+.+\s+["']?(?:${BROAD_DELETE_ROOTS}|[A-Za-z]:[\\/])`, "i");
const RM_DIRECT_TARGET = new RegExp(String.raw`\brm\s+(?:-[A-Za-z]*r[A-Za-z]*\s+-[A-Za-z]*f[A-Za-z]*|-[A-Za-z]*f[A-Za-z]*\s+-[A-Za-z]*r[A-Za-z]*|-(?=[A-Za-z]*r)(?=[A-Za-z]*f)[A-Za-z]+)\s+["']?(?:${BROAD_DELETE_ROOTS})`, "i");

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
  // commonly echo instructions like `echo "run: sudo systemctl ..."`. Only
  // skip when no shell separator could chain a real command after the echo.
  if (/^\s*(echo|printf)\b/i.test(command) && !/(\&\&|\|\||;|\||\$\(|`)/.test(command)) {
    return findings;
  }

  // Remote download piped to shell must see the whole line: the pipe that
  // feeds the shell is itself a segment separator. Allow sudo/env between
  // the pipe and the shell (`curl ... | sudo bash`).
  if (
    /\b(curl|wget|iwr|Invoke-WebRequest)\b.+\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+(?:\S+=\S*\s+)*)?(sh|bash|zsh|pwsh|powershell|iex|Invoke-Expression)\b/i.test(command) ||
    /\b(bash|sh|zsh)\s+<\s*\(\s*(curl|wget)\b/i.test(command)
  ) {
    push({
      id: "remote_code_execution",
      severity: "high",
      recommendation: "Avoid piping remote downloads directly into shells; pin scripts and verify checksums first."
    });
  }

  // Everything else is checked per command segment so a match cannot span
  // `&&`, `;`, or `|` — `rm -rf dist && cp -r build /usr/share` must not
  // read as one `rm ... /usr/share`.
  for (const segment of command.split(/&&|\|\||;|\|/)) {
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
    (RECURSIVE_FORCE_FLAGS.test(segment) && RM_LATER_TARGET.test(segment)) ||
    RM_DIRECT_TARGET.test(segment) ||
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
