import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { SEVERITIES } from "./constants.js";
import { AgentReadyError, configError } from "./errors.js";
import { summarizeSeverities } from "./utils.js";

export async function loadBaseline(root, baselinePath = null) {
  if (!baselinePath) {
    return null;
  }

  const baseline = await loadBaselineFile(root, baselinePath);
  const dedupedFindings = dedupeBaselineEntries(baseline.findings);
  const fingerprints = new Set(dedupedFindings.map((finding) => finding.fingerprint));

  return {
    path: baseline.path,
    entries: dedupedFindings.length,
    findings: dedupedFindings,
    fingerprints,
    stableFingerprints: new Set(dedupedFindings.map((finding) => finding.stableFingerprint).filter(Boolean))
  };
}

export async function loadBaselineFile(root, baselinePath) {
  const resolved = path.resolve(root, baselinePath);
  if (!existsSync(resolved)) {
    throw configError(`Baseline file not found: ${resolved}\nRun agentready baseline . --output ${baselinePath} to create it.`);
  }

  let raw;
  try {
    raw = await readFile(resolved, "utf8");
  } catch (error) {
    throw configError(`Baseline file could not be read: ${resolved}\n${error.message}`);
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw configError(`Baseline file is not valid JSON: ${resolved}\n${error.message}`);
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw configError(`Baseline file root must be an object: ${resolved}`);
  }

  if (parsed.version !== undefined && parsed.version !== 1) {
    throw configError(`Unsupported baseline version "${parsed.version}" in ${resolved}; expected version 1.`);
  }

  if (!Array.isArray(parsed.findings)) {
    throw configError(`Baseline file must contain a findings array: ${resolved}`);
  }

  return {
    path: resolved,
    version: 1,
    generatedAt: parsed.generatedAt || null,
    findings: normalizeBaselineFindings(parsed.findings)
  };
}

/**
 * Compute an optimal 1-to-1 matching between baseline entries and current scan
 * findings. Each baseline entry has at most two candidate edges, ordered by
 * preference:
 *   1. Exact `fingerprint` match (same file, line, rule, and evidence)
 *   2. Line-independent `stableFingerprint` match (survives edits above it)
 *
 * Using Kuhn's augmenting-path matching over those <=2 edges guarantees:
 * - One baseline entry can never suppress two findings (`suppressed <= entries`).
 * - Exact line matches win ties when a new duplicate finding is inserted above
 *   an existing baselined line.
 * - Consecutive identical findings that shift lines together augment cleanly so
 *   an exact-line collision never strands a sibling entry.
 * - `applyBaseline`, `diffBaseline`, and `writeBaseline` agree on every edge.
 */
function matchBaselineEntries(scanFindings, baselineEntries) {
  const uniqueBaseline = dedupeBaselineEntries(baselineEntries);
  const currentList = [];
  const seenCurrentFp = new Set();
  const currentIdxByFp = new Map();
  const currentIndicesByStable = new Map();

  for (const finding of scanFindings) {
    if (!finding?.fingerprint) {
      currentList.push(finding);
      continue;
    }
    if (seenCurrentFp.has(finding.fingerprint)) {
      continue;
    }
    seenCurrentFp.add(finding.fingerprint);
    const cIdx = currentList.length;
    currentList.push(finding);
    currentIdxByFp.set(finding.fingerprint, cIdx);
    if (finding.stableFingerprint) {
      const list = currentIndicesByStable.get(finding.stableFingerprint) || [];
      list.push(cIdx);
      currentIndicesByStable.set(finding.stableFingerprint, list);
    }
  }

  // Fallback support when a caller passes a hand-constructed `{ fingerprints, stableFingerprints }`
  // object without a `findings` array.
  if (uniqueBaseline.length === 0 && baselineEntries === null) {
    return { uniqueBaseline: [], currentList, matched: [], unmatchedCurrent: currentList, staleBaseline: [] };
  }

  const adj = uniqueBaseline.map((bf) => {
    const candidates = [];
    const exact = bf.fingerprint ? currentIdxByFp.get(bf.fingerprint) : undefined;
    if (exact !== undefined) {
      candidates.push(exact);
    }
    if (bf.stableFingerprint) {
      for (const stableIdx of currentIndicesByStable.get(bf.stableFingerprint) || []) {
        if (stableIdx !== exact) {
          candidates.push(stableIdx);
        }
      }
    }
    return candidates;
  });

  const matchForCurrent = new Array(currentList.length).fill(-1);
  const matchForBaseline = new Array(uniqueBaseline.length).fill(-1);

  function tryAugment(bIdx, visited) {
    for (const cIdx of adj[bIdx]) {
      if (visited.has(cIdx)) {
        continue;
      }
      visited.add(cIdx);
      const prevB = matchForCurrent[cIdx];
      if (prevB === -1 || tryAugment(prevB, visited)) {
        matchForCurrent[cIdx] = bIdx;
        matchForBaseline[bIdx] = cIdx;
        return true;
      }
    }
    return false;
  }

  for (let bIdx = 0; bIdx < uniqueBaseline.length; bIdx += 1) {
    tryAugment(bIdx, new Set());
  }

  const matched = [];
  const staleBaseline = [];
  for (let bIdx = 0; bIdx < uniqueBaseline.length; bIdx += 1) {
    const cIdx = matchForBaseline[bIdx];
    if (cIdx !== -1) {
      matched.push({
        fingerprint: uniqueBaseline[bIdx].fingerprint,
        baseline: uniqueBaseline[bIdx],
        current: currentList[cIdx]
      });
    } else {
      staleBaseline.push(uniqueBaseline[bIdx]);
    }
  }

  const unmatchedCurrent = currentList.filter((_, cIdx) => matchForCurrent[cIdx] === -1);

  return {
    uniqueBaseline,
    currentList,
    matched,
    unmatchedCurrent,
    staleBaseline
  };
}

function dedupeBaselineEntries(entries = []) {
  const seen = new Set();
  const unique = [];
  for (const entry of entries) {
    if (!entry?.fingerprint || seen.has(entry.fingerprint)) {
      continue;
    }
    seen.add(entry.fingerprint);
    unique.push(entry);
  }
  return unique;
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

  // Support synthesized baseline objects in tests that only provide Sets
  // without a `findings` array.
  const baselineEntries = Array.isArray(baseline.findings)
    ? baseline.findings
    : [...(baseline.fingerprints || [])].map((fingerprint) => ({ fingerprint }));

  const { uniqueBaseline, matched, unmatchedCurrent } = matchBaselineEntries(findings, baselineEntries);

  return {
    findings: unmatchedCurrent,
    summary: {
      path: baseline.path,
      entries: baseline.entries ?? uniqueBaseline.length,
      suppressed: matched.length
    }
  };
}

export async function writeBaseline(filePath, scanResult) {
  const previousEntries = await readPreviousEntries(filePath);
  const { matched } = matchBaselineEntries(scanResult.findings, previousEntries);
  const previousByCurrentFp = new Map(matched.map((pair) => [pair.current.fingerprint, pair.baseline]));
  const generatedAt = new Date().toISOString();
  const baseline = buildBaseline(
    scanResult.findings.map((finding) =>
      toBaselineEntry(finding, generatedAt, previousByCurrentFp.get(finding.fingerprint))
    ),
    { generatedAt }
  );

  await writeBaselineJson(filePath, baseline);
  return baseline;
}

// Regenerating a baseline must not reset when each finding was first seen,
// or `debt` would lose its age information. A missing or unreadable previous
// file simply means there is nothing to preserve.
async function readPreviousEntries(filePath) {
  try {
    const parsed = JSON.parse(await readFile(filePath, "utf8"));
    return normalizeBaselineFindings(Array.isArray(parsed?.findings) ? parsed.findings : []);
  } catch {
    return [];
  }
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

  await writeBaselineJson(filePath, baseline);
  return baseline;
}

async function writeBaselineJson(filePath, baseline) {
  try {
    await mkdir(path.dirname(filePath), { recursive: true });
    await writeFile(filePath, `${JSON.stringify(baseline, null, 2)}\n`, "utf8");
  } catch (error) {
    throw new AgentReadyError(`Failed to write baseline file ${filePath}: ${error.message}`, 4);
  }
}

export function diffBaseline(scanFindings, baseline) {
  const { uniqueBaseline, currentList, matched, unmatchedCurrent, staleBaseline } = matchBaselineEntries(
    scanFindings,
    baseline.findings || []
  );

  return {
    baselinePath: baseline.path,
    summary: {
      baseline: uniqueBaseline.length,
      current: currentList.length,
      matched: matched.length,
      new: unmatchedCurrent.length,
      stale: staleBaseline.length,
      severity: {
        baseline: summarizeSeverities(uniqueBaseline),
        current: summarizeSeverities(currentList),
        matched: summarizeSeverities(matched.map((item) => item.current)),
        new: summarizeSeverities(unmatchedCurrent),
        stale: summarizeSeverities(staleBaseline)
      }
    },
    matched,
    newFindings: unmatchedCurrent,
    staleFindings: staleBaseline
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
    file: finding.file ?? null,
    line: finding.line || null,
    firstSeenAt: previous.firstSeenAt || finding.firstSeenAt || seenAt,
    lastSeenAt: seenAt
  };
}

function normalizeBaselineFindings(findings) {
  return findings
    .filter((finding) => finding && typeof finding === "object" && typeof finding.fingerprint === "string" && finding.fingerprint.trim().length > 0)
    .map((finding) => ({
      fingerprint: finding.fingerprint.trim(),
      ...(typeof finding.stableFingerprint === "string" && finding.stableFingerprint.trim().length > 0
        ? { stableFingerprint: finding.stableFingerprint.trim() }
        : {}),
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
