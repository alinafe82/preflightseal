# Contributing

PreflightSeal is security-sensitive infrastructure. Contributions should favor
small, reviewable changes with executable evidence.

## Local Checks

```sh
npm test
npm run check
```

## Rules

- Do not execute repository-controlled code during acquire, inspect, analyze, or
  plan.
- Do not add package lifecycle scripts.
- Do not broaden destination permissions without tests.
- Do not add an `ALLOW` path for missing evidence.
- Add regression tests for every security-sensitive bug fix.
- Keep examples honest: if a capability is not implemented, document it as a
  non-goal or future extension rather than a feature.

## Release Checklist

- `npm test`
- `npm run check`
- clean `git status --short`
- package metadata review
- repository-wide secret and contamination audit
- inspect published package contents with `npm pack --dry-run`
