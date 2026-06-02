import { existsSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { configError } from "./errors.js";

export async function loadBaseline(root, baselinePath = null) {
  if (!baselinePath) {
    return null;
  }

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

  const fingerprints = new Set((parsed.findings || []).map((finding) => finding.fingerprint).filter(Boolean));

  return {
    path: resolved,
    entries: fingerprints.size,
    fingerprints
  };
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
    if (baseline.fingerprints.has(finding.fingerprint)) {
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
  const baseline = {
    version: 1,
    generatedAt: new Date().toISOString(),
    findings: scanResult.findings.map((finding) => ({
      fingerprint: finding.fingerprint,
      id: finding.id,
      severity: finding.severity,
      title: finding.title,
      file: finding.file,
      line: finding.line || null
    }))
  };

  await writeFile(filePath, `${JSON.stringify(baseline, null, 2)}\n`, "utf8");
  return baseline;
}
