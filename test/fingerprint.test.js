import { test } from "node:test";
import assert from "node:assert/strict";
import { fingerprintFinding, addFingerprints } from "../src/fingerprint.js";

test("fingerprintFinding produces a 24-char hex string", () => {
  const finding = {
    id: "secret.private_key",
    file: "keys/server.pem",
    line: 1,
    evidence: "-----BEGIN PRIVATE KEY-----",
    title: "Private key material is present"
  };
  const fp = fingerprintFinding(finding);
  assert.match(fp, /^[a-f0-9]{24}$/);
});

test("fingerprintFinding is deterministic", () => {
  const finding = {
    id: "test.rule",
    file: "src/app.js",
    line: 42,
    evidence: "some evidence",
    title: "Test finding"
  };
  const fp1 = fingerprintFinding(finding);
  const fp2 = fingerprintFinding(finding);
  assert.equal(fp1, fp2);
});

test("fingerprintFinding differs when any stable field changes", () => {
  const base = {
    id: "test.rule",
    file: "src/app.js",
    line: 42,
    evidence: "some evidence",
    title: "Test finding"
  };
  const fpBase = fingerprintFinding(base);

  const variations = [
    { ...base, id: "test.other" },
    { ...base, file: "src/other.js" },
    { ...base, line: 43 },
    { ...base, evidence: "other evidence" },
    { ...base, title: "Other title" }
  ];

  for (const variant of variations) {
    assert.notEqual(fingerprintFinding(variant), fpBase, `Fingerprint should differ for ${JSON.stringify(variant)}`);
  }
});

test("fingerprintFinding handles null and missing fields gracefully", () => {
  const finding = { id: "test.rule" };
  const fp = fingerprintFinding(finding);
  assert.match(fp, /^[a-f0-9]{24}$/);
});

test("fingerprintFinding preserves line number 0", () => {
  const withZero = { id: "test", file: "a.js", line: 0, evidence: "e", title: "t" };
  const withNull = { id: "test", file: "a.js", line: null, evidence: "e", title: "t" };
  assert.notEqual(fingerprintFinding(withZero), fingerprintFinding(withNull));
});

test("addFingerprints adds fingerprint to each finding", () => {
  const findings = [
    { id: "a", file: "x.js", line: 1, evidence: "e1", title: "t1" },
    { id: "b", file: "y.js", line: 2, evidence: "e2", title: "t2" }
  ];
  const result = addFingerprints(findings);
  assert.equal(result.length, 2);
  for (const finding of result) {
    assert.ok(finding.fingerprint);
    assert.match(finding.fingerprint, /^[a-f0-9]{24}$/);
  }
});

test("addFingerprints does not mutate original findings", () => {
  const original = { id: "a", file: "x.js", line: 1, evidence: "e", title: "t" };
  const result = addFingerprints([original]);
  assert.ok(!("fingerprint" in original));
  assert.ok("fingerprint" in result[0]);
});
