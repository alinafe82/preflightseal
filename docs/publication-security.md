# Publication Security

PreflightSeal is licensed under MIT so others may use, modify, distribute, and
sell copies of the code if they keep the copyright and license notice. The
official project identity is the `alinafe82/preflightseal` GitHub repository and
the `preflightseal` npm package when published by the maintainer.

## Maintainer Controls

- Keep maintainer accounts protected with passkeys or hardware-backed two-factor
  authentication.
- Keep admin access narrow. Prefer pull requests and status checks over direct
  pushes to `main`.
- Keep `.github/CODEOWNERS` authoritative for control surfaces such as workflows,
  package metadata, source, schemas, and release policy.
- Use signed commits for direct maintainer commits once local signing is
  configured.

## Repository Controls

After the repository is public, protect `main` with a ruleset or branch
protection rule:

- require pull requests before merging
- require the CI checks from `.github/workflows/ci.yml`
- require CodeQL after its first successful public run
- block force pushes and branch deletion
- require conversation resolution before merge
- restrict who can push directly to `main`
- enable required CODEOWNERS review when there is more than one maintainer

For a solo maintainer, do not require a second reviewer until another trusted
maintainer exists; otherwise routine releases can become blocked.

## GitHub Security Features

Enable these repository security features after publication:

- Dependabot alerts and security updates
- secret scanning and push protection
- CodeQL code scanning
- private vulnerability reporting

The checked-in Dependabot and CodeQL workflow files are intentionally ready
before publication, but some GitHub security features are unavailable for a
private repository on GitHub Free.

## npm Package Controls

The official `preflightseal` npm package is published from the maintainer
account and maintained through the release process in
[`docs/release-process.md`](release-process.md).

- Require two-factor authentication for publishing and settings changes.
- Prefer npm trusted publishing from GitHub Actions over long-lived npm tokens.
- Configure the trusted publisher for `.github/workflows/release.yml`.
- Keep `publishConfig.provenance` enabled in `package.json`.
- Use the `npm-publish` GitHub environment for release approvals.

Do not add a long-lived `NPM_TOKEN` unless trusted publishing is unavailable.

## Brand Use

The MIT license grants rights to the code, not permission to impersonate the
official project. Third parties may accurately say their work is based on
PreflightSeal, but they should not imply maintainer endorsement or publish a
confusingly official package, repository, or service.
