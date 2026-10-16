# Release notes

Release notes live in the repository
[CHANGELOG](https://github.com/Guard-Core/guard-core-jvm/blob/master/CHANGELOG.md).

Conventions (family-wide, matching the reference repo):

- Every release entry states the spec version targeted and, for engine
  releases, the mirrored guard-core version.
- Engine and facade versions move in lockstep with guard-core (4.4.1); the
  adapters start a fresh family version at 1.0.0; the agent mirrors
  guard-agent (3.2.3).
- Breaking behavior changes (spec version bumps) and mixed-version Redis
  interop constraints (section 08) are documented in the CHANGELOG and in
  [Migration](migration.md) before release.

The release choreography itself (tag gates, Central Portal publish, per-tag
audits) is [docs/release.md](release.md), with the dry-run proof in
[docs/release-rehearsal.md](release-rehearsal.md).
