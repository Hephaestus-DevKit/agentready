import { test } from "node:test";
import assert from "node:assert/strict";
import {
  SECRET_TOKEN_RULES,
  createLineFinder,
  looksLikePlaceholderValue,
  redact
} from "../src/scanners/utils.js";

// Realistic-shaped fake tokens, one per detection rule. None are real
// credentials; they exist to prove detect/redact stay in lockstep. The
// strings are assembled at runtime so repository-hosting secret scanners
// (e.g. GitHub push protection) do not mistake the fixtures for live keys.
const ALPHA = "abcdefghijklmnopqrstuvwxyz";
const SAMPLE_TOKENS = {
  "secret.private_key": ["-----BEGIN RSA PRIVATE KEY-----", "MIIfake", "-----END RSA PRIVATE KEY-----"].join("\n"),
  "secret.github_token": ["ghp", `${ALPHA}0123456789`].join("_"),
  "secret.anthropic_key": ["sk", "ant", `${ALPHA}0123456789`].join("-"),
  "secret.stripe_key": ["sk", "live", ALPHA].join("_"),
  "secret.openai_key": ["sk", `proj4${ALPHA}0123456789`].join("-"),
  "secret.aws_access_key": ["AKIA", "IOSFODNN7EXAMPLE"].join(""),
  "secret.google_api_key": ["AIzaSy", "A1234567890abcdefghijklmnopqrstuv"].join(""),
  "secret.slack_token": ["xoxb", "1234567890", "1234567890123", ALPHA.slice(0, 24)].join("-"),
  "secret.slack_app_token": ["xapp", "1", "A012345", "1234567890", "abcdef123456"].join("-"),
  "secret.jwt_token": ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", "SflKxwRJSMeKKF2QT4fwpM"].join(".")
};

test("every secret detection rule has a working sample and redaction", () => {
  assert.equal(SECRET_TOKEN_RULES.length, Object.keys(SAMPLE_TOKENS).length);

  for (const rule of SECRET_TOKEN_RULES) {
    const sample = SAMPLE_TOKENS[rule.id];
    assert.ok(sample, `missing sample token for ${rule.id}`);
    assert.match(sample, rule.detect, `${rule.id} sample should trigger detection`);

    const line = `const value = "${sample}";`;
    const redacted = redact(line);
    assert.ok(redacted.includes("[redacted]"), `${rule.id} evidence should be redacted`);
    if (rule.id === "secret.private_key") {
      // The PEM envelope survives by design; only the key body is secret.
      assert.ok(!redacted.includes("MIIfake"), "private key body must not survive redaction");
    } else {
      assert.ok(!redacted.includes(sample.slice(-12)), `${rule.id} token tail must not survive redaction`);
    }
  }
});

test("redact masks JWT tokens", () => {
  const line = `Authorization: Bearer ${SAMPLE_TOKENS["secret.jwt_token"]}`;
  const redacted = redact(line);
  assert.match(redacted, /eyJ\.\.\.\[redacted\]/);
  assert.ok(!redacted.includes("SflKxwRJSMeKKF2QT4fwpM"));
});

test("redact keeps the GitHub token prefix for identification", () => {
  const redacted = redact(`token: ${SAMPLE_TOKENS["secret.github_token"]}`);
  assert.match(redacted, /ghp_abcd\.\.\.\[redacted\]/);
});

test("redact leaves ordinary text untouched", () => {
  const line = "const url = \"https://example.com/api\";";
  assert.equal(redact(line), line);
});

test("GitHub Actions template expressions are placeholders", () => {
  assert.equal(looksLikePlaceholderValue("${{ secrets.API_TOKEN }}"), true);
  assert.equal(looksLikePlaceholderValue("${{secrets.API_TOKEN}}"), true);
  assert.equal(looksLikePlaceholderValue("actual-secret-value-123"), false);
});

test("createLineFinder supports searching from a given line", () => {
  const finder = createLineFinder("alpha\nbeta\nalpha\ngamma");
  assert.equal(finder("alpha"), 1);
  assert.equal(finder("alpha", 2), 3);
  assert.equal(finder("missing"), null);
  assert.equal(finder("beta", 3), null);
});
