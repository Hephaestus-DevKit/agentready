## Summary

-

## User Impact

-

## Risk

- [ ] Low: docs, tests, or narrow implementation change
- [ ] Medium: scanner behavior, CLI output, config handling, or CI behavior
- [ ] High: release, security-sensitive detection, baseline compatibility, or public API behavior

## Verification

- [ ] `npm run verify`
- [ ] Relevant CLI output reviewed
- [ ] Documentation updated when user-facing behavior changed

## Maintenance Notes

- Rule ids remain stable, or the breaking change is documented.
- New findings include a clear recommendation and tests for positive and negative cases.
- Reports avoid exposing secrets beyond redacted evidence.
