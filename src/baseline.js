import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { SEVERITIES } from "./constants.js";
import { configError } from "./errors.js";
import { summarizeSeverities } from "./utils.js";

export async function loadBaseline(root, baselinePath = null) {
  if (!baselinePath) {
    return null;
  }

  const baseline = await loadBaselineFile(root, baselinePath);
  const fingerprints = new Set(baseline.findings.map((finding) => finding.fingerprint).filter(Boolean));

  return {
    path: baseline.path,
    entries: fingerprints.size,
    findings: baseline.findings,
    fingerprints,
    stableFingerprints: new Set(baseline.findings.map((finding) => finding.stableFingerprint).filter(Boolean))
  };
}

export async function loadBaselineFile(root, baselinePath) {
  const resolved = path.resolve(root, baselinePath);
  if (!existsSync(resolved)) {
    throw configError(`Baseline file not found: ${resolved}\nRun agentready baseline . --output ${baselinePath} to create it.`);
  }

  const raw = await readFile(resolved, "utf8");
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw configError(`Baseline file is not valid JSON: ${resolved}\n${error.message}`);
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw configError(`Baseline file root must be an object: ${resolved}`);
  }

  if (!Array.isArray(parsed.findings)) {
    throw configError(`Baseline file must contain a findings array: ${resolved}`);
  }

  return {
    path: resolved,
    version: parsed.version || 1,
    generatedAt: parsed.generatedAt || null,
    findings: normalizeBaselineFindings(parsed.findings)
  };
}

// A finding is baselined when its exact fingerprint is recorded, or, for
// baselines written by newer versions, when its line-independent fingerprint
// is (so edits above the finding do not resurrect it).
function isBaselined(baseline, finding) {
  return (
    baseline.fingerprints.has(finding.fingerprint) ||
    (finding.stableFingerprint !== undefined && baseline.stableFingerprints?.has(finding.stableFingerprint) === true)
  );
}

export function applyBaseline(findings, baseline) {
  if (!baseline) {
    return {
      findings,
      summary: {
        path: null,
        entries: 0,
        suppressed: 0
      }
    };
  }

  const kept = [];
  let suppressed = 0;

  for (const finding of findings) {
    if (isBaselined(baseline, finding)) {
      suppressed += 1;
      continue;
    }
    kept.push(finding);
  }

  return {
    findings: kept,
    summary: {
      path: baseline.path,
      entries: baseline.entries,
      suppressed
    }
  };
}

export async function writeBaseline(filePath, scanResult) {
  const previous = await readPreviousEntries(filePath);
  const generatedAt = new Date().toISOString();
  const baseline = buildBaseline(
    scanResult.findings.map((finding) =>
      toBaselineEntry(finding, generatedAt, previous.byFingerprint.get(finding.fingerprint) || previous.byStable.get(finding.stableFingerprint))
    ),
    { generatedAt }
  );

  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, `${JSON.stringify(baseline, null, 2)}\n`, "utf8");
  return baseline;
}

// Regenerating a baseline must not reset when each finding was first seen,
// or `debt` would lose its age information. A missing or unreadable previous
// file simply means there is nothing to preserve.
async function readPreviousEntries(filePath) {
  const byFingerprint = new Map();
  const byStable = new Map();
  try {
    const parsed = JSON.parse(await readFile(filePath, "utf8"));
    for (const entry of normalizeBaselineFindings(Array.isArray(parsed?.findings) ? parsed.findings : [])) {
      byFingerprint.set(entry.fingerprint, entry);
      if (entry.stableFingerprint) {
        byStable.set(entry.stableFingerprint, entry);
      }
    }
  } catch {
    // No previous baseline to merge.
  }
  return { byFingerprint, byStable };
}

export async function writePrunedBaseline(filePath, diff) {
  const now = new Date().toISOString();
  const baseline = buildBaseline(
    diff.matched.map((item) => toBaselineEntry(item.current, now, item.baseline)),
    {
      generatedAt: now,
      prunedAt: now,
      previousEntries: diff.summary.baseline,
      removedEntries: diff.summary.stale,
      entriesPreserved: diff.summary.matched
    }
  );

  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, `${JSON.stringify(baseline, null, 2)}\n`, "utf8");
  return baseline;
}

export function diffBaseline(scanFindings, baseline) {
  const currentByFingerprint = new Map();
  const currentByStable = new Map();
  for (const finding of scanFindings) {
    if (finding.fingerprint && !currentByFingerprint.has(finding.fingerprint)) {
      currentByFingerprint.set(finding.fingerprint, finding);
      if (finding.stableFingerprint && !currentByStable.has(finding.stableFingerprint)) {
        currentByStable.set(finding.stableFingerprint, finding);
      }
    }
  }

  const baselineByFingerprint = new Map();
  for (const finding of baseline.findings || []) {
    if (finding.fingerprint && !baselineByFingerprint.has(finding.fingerprint)) {
      baselineByFingerprint.set(finding.fingerprint, finding);
    }
  }

  const matched = [];
  const stale = [];
  const claimed = new Set();

  // Exact fingerprints win; only then fall back to the line-independent one so
  // a moved finding cannot steal another entry's exact match.
  const pending = [];
  for (const [fingerprint, baselineFinding] of baselineByFingerprint) {
    const current = currentByFingerprint.get(fingerprint);
    if (current) {
      claimed.add(current.fingerprint);
      matched.push({ fingerprint, baseline: baselineFinding, current });
    } else {
      pending.push([fingerprint, baselineFinding]);
    }
  }
  for (const [fingerprint, baselineFinding] of pending) {
    const current = baselineFinding.stableFingerprint ? currentByStable.get(baselineFinding.stableFingerprint) : undefined;
    if (current && !claimed.has(current.fingerprint)) {
      claimed.add(current.fingerprint);
      matched.push({ fingerprint, baseline: baselineFinding, current });
    } else {
      stale.push(baselineFinding);
    }
  }

  const added = [...currentByFingerprint.values()].filter((finding) => !claimed.has(finding.fingerprint));

  return {
    baselinePath: baseline.path,
    summary: {
      baseline: baselineByFingerprint.size,
      current: currentByFingerprint.size,
      matched: matched.length,
      new: added.length,
      stale: stale.length,
      severity: {
        baseline: summarizeSeverities([...baselineByFingerprint.values()]),
        current: summarizeSeverities([...currentByFingerprint.values()]),
        matched: summarizeSeverities(matched.map((item) => item.current)),
        new: summarizeSeverities(added),
        stale: summarizeSeverities(stale)
      }
    },
    matched,
    newFindings: added,
    staleFindings: stale
  };
}

export function summarizeBaselineDebt(baseline, now = new Date()) {
  const findings = baseline.findings || [];
  const bySeverity = summarizeSeverities(findings);
  const byRule = countBy(findings, (finding) => finding.id || "unknown");
  const byFile = countBy(findings, (finding) => finding.file || "(project)");
  const ages = findings.map((finding) => ageDays(finding.firstSeenAt, now)).filter((age) => age !== null);

  return {
    baselinePath: baseline.path,
    generatedAt: baseline.generatedAt || null,
    entries: findings.length,
    severity: bySeverity,
    oldestAgeDays: ages.length ? ages.reduce((max, age) => Math.max(max, age), 0) : null,
    averageAgeDays: ages.length ? Math.round(ages.reduce((total, age) => total + age, 0) / ages.length) : null,
    byRule: topCounts(byRule, 10),
    byFile: topCounts(byFile, 10),
    findings: findings.map((finding) => ({
      ...finding,
      ageDays: ageDays(finding.firstSeenAt, now)
    }))
  };
}

function buildBaseline(findings, extra = {}) {
  const generatedAt = extra.generatedAt || new Date().toISOString();
  const entriesAreBaselineEntries = findings.every((finding) => finding.firstSeenAt || finding.lastSeenAt);

  return {
    version: 1,
    generatedAt,
    ...extra,
    findings: entriesAreBaselineEntries ? findings : findings.map((finding) => toBaselineEntry(finding, generatedAt))
  };
}

function toBaselineEntry(finding, seenAt, previous = {}) {
  return {
    fingerprint: finding.fingerprint,
    ...(finding.stableFingerprint ? { stableFingerprint: finding.stableFingerprint } : {}),
    id: finding.id,
    severity: finding.severity,
    title: finding.title,
    file: finding.file,
    line: finding.line || null,
    firstSeenAt: previous.firstSeenAt || finding.firstSeenAt || seenAt,
    lastSeenAt: seenAt
  };
}

function normalizeBaselineFindings(findings) {
  return findings
    .filter((finding) => finding && typeof finding === "object" && typeof finding.fingerprint === "string")
    .map((finding) => ({
      fingerprint: finding.fingerprint,
      ...(typeof finding.stableFingerprint === "string" ? { stableFingerprint: finding.stableFingerprint } : {}),
      id: typeof finding.id === "string" ? finding.id : "unknown",
      severity: SEVERITIES.includes(finding.severity) ? finding.severity : "info",
      title: typeof finding.title === "string" ? finding.title : "Baseline finding",
      file: typeof finding.file === "string" ? finding.file : null,
      line: Number.isInteger(finding.line) && finding.line > 0 ? finding.line : null,
      firstSeenAt: typeof finding.firstSeenAt === "string" ? finding.firstSeenAt : null,
      lastSeenAt: typeof finding.lastSeenAt === "string" ? finding.lastSeenAt : null
    }));
}

function countBy(findings, keyFn) {
  const counts = new Map();
  for (const finding of findings) {
    const key = keyFn(finding);
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return counts;
}

function topCounts(counts, limit) {
  return [...counts.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((left, right) => right.count - left.count || left.key.localeCompare(right.key))
    .slice(0, limit);
}

function ageDays(value, now) {
  if (!value) {
    return null;
  }

  const timestamp = Date.parse(value);
  if (Number.isNaN(timestamp)) {
    return null;
  }

  return Math.max(0, Math.floor((now.getTime() - timestamp) / 86400000));
}
