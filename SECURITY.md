# Security Policy

AgentReady is a local scanner. It should not transmit repository contents,
findings, secrets, paths, or configuration to external services.

## Reporting Vulnerabilities

If you find a security issue, open a private security advisory when the project
is hosted on GitHub. If advisories are not available yet, contact the maintainer
privately before publishing details.

Please include:

- A clear description of the issue
- A minimal reproduction when possible
- Expected impact
- Affected versions or commit range

## Handling Secret Findings

If AgentReady reports a secret-like value, treat it as potentially exposed until
verified. Remove it from the repository, rotate the credential, and review logs
or artifacts where it may have appeared.

AgentReady redacts known secret formats in output, but scanner output should
still be treated as sensitive in CI and issue trackers.
