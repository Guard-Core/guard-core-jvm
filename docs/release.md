# Release runbook (guard-core-jvm)

The exact choreography for the operator on release day. NOTHING releases
without fresh explicit operator go (W8b standing rule): every step below is a
deliberate human action. This document covers the engine repo; the adapters
(spring-boot-guard, ktor-guard) and the agent (guard-agent-jvm) have their own
runbooks with the same structure and a version-flip checklist.

## Versioning law

| Artifact | Repo | Version | Rule |
|---|---|---|---|
| `guard-core-engine` | guard-core-jvm (this repo) | 4.3.2 | lockstep with guard-core 4.3.2 |
| `guard-core` (facade) | guard-core-jvm (this repo) | 4.3.2 | lockstep with guard-core 4.3.2 |
| `spring-boot-guard` | spring-boot-guard | 1.0.0 | fresh family version |
| `ktor-guard` | ktor-guard | 1.0.0 | fresh family version |
| `guard-agent-jvm` | guard-agent-jvm | 3.2.2 | mirrors guard-agent 3.2.2 |

- The engine version is set in-file (`build.gradle.kts`, `allprojects`).
  Tags must match it exactly: the engine tags `v4.3.2`.
- Tags are bare `vX.Y.z` only: no suffixes (`v4.3.2-jvm` is wrong), no build
  metadata. The `tag-consistency` job refuses anything else. This audit exists
  because of the guard-core-rs invisible-rule incident on `refs/tags/v4.3.2`.
- CHANGELOG entries use `## [SEMVER] - YYYY-MM-DD` and mirror the narrative
  naming of the guard-core Python repo.
- groupId `com.guard-core` (the Maven Central Portal namespace; it reverses
  to guard-core.com). Kotlin/JVM packages stay `com.guardcore.*`: hyphens are
  illegal in JVM packages and the groupId/package mismatch is standard for
  hyphenated domains.

## Publishing auth reality (verified 2026-10-11)

- The Central Portal Publisher API authenticates with a **Portal user token**
  (`Authorization: Bearer base64(username:password)`), generated in the Portal
  under Account -> Generate User Token. **OIDC trusted publishing does not
  exist for Maven Central** as of October 2026 (npm/PyPI/Packagist have it;
  Maven does not): the publish jobs therefore request no `id-token` scope and
  are the least-privilege set. If Sonatype ships trusted publishing later,
  this section and the workflows get a follow-up.
- **GPG signing is mandatory.** Every deployed file needs an `.asc` signature.
  The key never leaves the runner: the workflow passes the armored private
  key + passphrase through Gradle's `useInMemoryPgpKeys`.
- **Checksums** `.md5`/`.sha1` are mandatory (`.sha256`/`.sha512` optional);
  Gradle's `maven-publish` generates them.
- **Sources and javadoc jars are mandatory** for every artifact (the build
  files produce them; the javadoc jar carries the README until Dokka lands).
- **Publishing limits** took effect 2026-10-01: three monthly metrics per
  organization (file count, release size, release count), evaluated as hard
  thresholds with a grace flow. The source of truth for thresholds and usage
  is the Portal's Usage Center. A JVM family train (4 deployments, well under
  100 files) is far below the community thresholds; check the Usage Center
  before each train anyway.
- Publishing type is fixed to `USER_MANAGED` in the workflows: deployments are
  uploaded and VALIDATED by CI, and a human releases them from the Portal UI.
  This is the deliberate human gate before artifacts go immutable-live.
  (`AUTOMATIC` would skip that gate; do not switch without an operator ruling.)

## One-time prerequisites (operator)

1. Portal namespace `com.guard-core` shows **Verified** at
   central.sonatype.com. (History: the `com.guardcore` claim was abandoned as
   unverifiable on 2026-10-11 - guardcore.com is a parked domain the operator
   does not own; `com.guard-core` reverses to guard-core.com, TXT record
   placed, re-registered 2026-10-11. repo1.maven.org has no prior art for
   either group.)
2. Generate a Portal user token (Account -> Generate User Token).
3. Prepare the signing key, if none exists yet:
   - `gpg --full-generate-key` (RSA 4096, no expiry is fine, email
     `rennf93@guard-core.com`).
   - Distribute the public key: `gpg --keyserver keyserver.ubuntu.com
     --send-key <KEYID>` (Portal validation checks public availability).
   - Export for CI: `gpg --armor --export-secret-keys <KEYID>`.
4. Set four GitHub secrets on **each** family repo (Settings -> Secrets and
   variables -> Actions):

   | Secret | Value |
   |---|---|
   | `CENTRAL_PORTAL_USERNAME` | user token username |
   | `CENTRAL_PORTAL_PASSWORD` | user token password |
   | `GPG_PRIVATE_KEY` | armored private key (whole `-----BEGIN ... KEY BLOCK-----` block) |
   | `GPG_PASSPHRASE` | the key's passphrase |

5. Check the Portal Usage Center (Publishing -> Usage Center) shows the org
   comfortably below all three thresholds.

## Release choreography (family order)

Engine first, then the Portal release clicks, then (and only then) the
adapters and the agent.

### 1. Engine (this repo)

1. Confirm `build.gradle.kts` carries the release version (4.3.2 - no flip
   needed while in lockstep; the version lives in the file, never on the
   command line) and the CHANGELOG has a `## [4.3.2] - YYYY-MM-DD` section.
2. Tag on the release commit: `git tag v4.3.2 && git push origin v4.3.2`.
   The tag push runs the gate suite (build + full-corpus certification +
   tag-consistency audit). Wait for it to go green.
3. Create the GitHub release for `v4.3.2` (Create release from the tag). The
   `release: created` event starts the publish job:
   - secrets gate -> existence check per artifact (skip if already live) ->
     `guard-core-engine` staging bundle -> Portal upload -> VALIDATED ->
     `guard-core` staging bundle -> Portal upload -> VALIDATED
   (engine-before-facade is enforced by job structure; a partial failure
   re-drives with workflow_dispatch and only the missing artifact publishes).
4. In the Portal UI (central.sonatype.com, Publishing -> Deployments):
   inspect both VALIDATED deployments, then click **Release** on the engine
   deployment first, the facade second.
5. Wait for replication and verify liveness (this is the signal the consumer
   releases wait on):
   - `curl -f https://repo1.maven.org/maven2/com/guard-core/guard-core-engine/4.3.2/guard-core-engine-4.3.2.pom`
   - `curl -f https://repo1.maven.org/maven2/com/guard-core/guard-core/4.3.2/guard-core-4.3.2.pom`

### 2. Adapters and agent (spring-boot-guard, ktor-guard, guard-agent-jvm)

Only after step 1.5 succeeds (their workflows re-check it anyway):

1. Version-flip PR per repo (see the checklist below): flip the project
   version, update the CHANGELOG, merge with CI green.
2. Tag: `git tag v1.0.0 && git push origin v1.0.0` (agent: `v3.2.2`). Gates
   run: engine-artifact pre-flight, tests at tag, tag-consistency.
3. Create the GitHub release. The publish job runs with
   `GUARD_CORE_USE_COMPOSITE=false`, so the build resolves
   `com.guard-core:guard-core:4.3.2` from Maven Central (mavenLocal, then
   Central) - proving the published graph, not the composite checkout.
4. Release the VALIDATED deployment in the Portal UI.
5. Verify liveness:
   - `curl -f https://repo1.maven.org/maven2/com/guard-core/spring-boot-guard/1.0.0/spring-boot-guard-1.0.0.pom`
   - `curl -f https://repo1.maven.org/maven2/com/guard-core/ktor-guard/1.0.0/ktor-guard-1.0.0.pom`
   - `curl -f https://repo1.maven.org/maven2/com/guard-core/guard-agent-jvm/3.2.2/guard-agent-jvm-3.2.2.pom`

### Version-flip checklist (adapters + agent, per release PR)

- [ ] `build.gradle.kts`: `version = "1.0.0-SNAPSHOT"` -> `version = "1.0.0"`
      (agent: `3.2.2-SNAPSHOT` -> `3.2.2`).
- [ ] `gradle/libs.versions.toml`: the `guardCore` version ref still reads
      `4.3.2` (the lockstep engine pin - bump it only when the engine train
      moves).
- [ ] `CHANGELOG.md`: rename the `Unreleased` section to
      `## [1.0.0] - YYYY-MM-DD` and state the engine pin.
- [ ] The workflow's `tag-consistency` job is the safety net: it fails with a
      clear message if the tag is pushed without the flip (SNAPSHOT version)
      or if the tag does not equal the in-file version.
- [ ] After the train: the consumers' `GUARD_CORE_JVM_REF` pins (ci.yml +
      settings comments) move to the released engine tag SHA in the next
      regular development PR.

## Post-release audits (per train, per tag - the php v4.3.1 lesson)

1. **Release page audit**: every tag in the train has a GitHub release page
   with the expected artifact notes and no draft leftovers.
2. **Registry existence check**: every artifact coordinates above answers
   HTTP 200 on repo1 (the same check the workflows use for rerun safety).
3. **Portal Deployments audit**: no deployment left in VALIDATED/PENDING.
4. **Usage Center**: the train registered without warnings.

## Rerun safety and failure recovery

- A publish job that dies mid-train re-drives via workflow_dispatch: the
  existence check skips anything already live on repo1, and only the missing
  deployment uploads again.
- A deployment stuck in VALIDATED that you do NOT want: click **Drop** in the
  Portal UI, then re-drive the workflow.
- Validation FAILED: the job logs print the Portal's error messages; fix the
  POM/jar/signature issue, drop the failed deployment in the Portal, re-drive.
- Workflow re-runs NEVER double-publish: repo1 serving 200 is authoritative.

## Rollback notes

- Published Maven Central artifacts are **immutable and undeleteable**. There
  is no rollback after the Portal Release click - only a fixed follow-up
  version.
- The rollback surface that exists:
  1. Before the click: Drop the VALIDATED deployment (nothing was published).
  2. After the click: cut a fix version through the same choreography, and
     (for security-grade breakage) yank consumers off the artifact via a
     patch release of the adapters plus a documented advisory.
- Delete the git tag and GitHub release only for a train that never released
  (no VALIDATED deployment was released); a published artifact's tag must
  stay forever.

## Rehearsal

The W8b dry-run proof (publishToMavenLocal, POM validation, workflow lint)
and its findings live in [docs/release-rehearsal.md](release-rehearsal.md).
The rehearsal never touched a remote registry: the first real upload happens
only on operator go, on release day, through the choreography above.
