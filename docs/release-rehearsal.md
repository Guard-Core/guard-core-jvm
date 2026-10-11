# W8b release rehearsal (2026-10-11)

Dry-run proof for the family release engineering. NOTHING was published to
any remote registry, no tags were created, no publish workflow runs were
triggered: every publish here went to `mavenLocal` and every registry touch
was a read-only `GET`. The first real upload happens only on operator go,
through [docs/release.md](release.md).

Branch heads rehearsed: guard-core-jvm `93f878f`, spring-boot-guard
`8a87184`, ktor-guard `64dd550`, guard-agent-jvm `9bd686e` (feat/w8b-release).

## 1. Verified live

### 1.1 Workflow lint

`actionlint` clean on all four `release.yml` (plus the existing per-repo
workflows unaffected by this wave):

```text
guard-core-jvm release.yml: CLEAN
spring-boot-guard release.yml: CLEAN
ktor-guard release.yml: CLEAN
guard-agent-jvm release.yml: CLEAN
```

### 1.2 Clean publishToMavenLocal, all four artifacts

From clean clones, `~/.m2/repository/com/guard-core` wiped first, JDK 17
(temurin 17.0.6), Gradle wrapper 9.8.1:

```text
./gradlew clean :guard-core-engine:publishToMavenLocal :guard-core:publishToMavenLocal
BUILD SUCCESSFUL in 24s (18 tasks)

guard-core-engine/4.3.2/: jar, sources-jar, javadoc-jar, module, pom
guard-core/4.3.2/:        jar, sources-jar, javadoc-jar, module, pom
```

Consumers, each with `GUARD_CORE_USE_COMPOSITE=false ./gradlew clean
publishToMavenLocal` (the release-workflow mode):

```text
GUARD_CORE_USE_COMPOSITE is disabled: resolving com.guard-core:guard-core from
the repositories (mavenLocal, then Maven Central).
BUILD SUCCESSFUL (spring-boot-guard 1.0.0-SNAPSHOT, ktor-guard 1.0.0-SNAPSHOT,
guard-agent-jvm 3.2.2-SNAPSHOT)
```

The builds compile in that mode, which is only possible because
`com.guard-core:guard-core:4.3.2` actually resolved from mavenLocal (Central
does not serve it: HTTP 404, section 1.6) - the rehearsal stands in for the
registry exactly as release day will.

### 1.3 POM coordinate proof (the Portal validator surface)

Parsed from mavenLocal (python xml.etree), all five publications:

```text
guard-core-engine 4.3.2: groupId com.guard-core; licenses MIT + Apache-2.0;
  developers rennf93; scm github.com/Guard-Core/guard-core-jvm;
  deps: kotlin-stdlib 2.4.21 (runtime)
guard-core 4.3.2: groupId com.guard-core; licenses MIT + Apache-2.0;
  deps: com.guard-core:guard-core-engine:4.3.2 (compile), lettuce-core
  6.7.1.RELEASE, maxmind-db 4.2.0, slf4j-api 2.0.17 (compile),
  kotlinx-coroutines/serialization (runtime)
spring-boot-guard 1.0.0-SNAPSHOT: MIT; deps: com.guard-core:guard-core:4.3.2
  (compile), kotlin-reflect (compile)
ktor-guard 1.0.0-SNAPSHOT: MIT; deps: com.guard-core:guard-core:4.3.2
  (compile), ktor-server-core-jvm 3.6.0 (runtime)
guard-agent-jvm 3.2.2-SNAPSHOT: MIT; deps: kotlin-stdlib, coroutines,
  lettuce (runtime) - NO guard-core dependency (engine-free POM, by design:
  compile-only facade contract)
```

Every Portal-required POM element is present in all five: name, description,
url, licenses, developers, scm. Sources jars are non-trivial (engine facade
sources jar: 61 entries); javadoc jars are non-empty (README carrier until
Dokka lands - the Portal validator rejects empty javadoc jars).

### 1.4 Composite toggle semantics (the release-mode proof)

`./gradlew dependencyInsight --dependency guard-core --configuration
compileClasspath` in spring-boot-guard:

```text
composite OFF (release mode):
  com.guard-core:guard-core:4.3.2          <- external module (mavenLocal ->
                                              Maven Central on release day)
composite ON (dev/CI default):
  com.guard-core:guard-core:4.3.2
  \--- project ':guard-core-jvm:guard-core'   <- included build substitution
```

Same selector, two resolution worlds, switched only by the env var. The
settings log line prints the active mode in every invocation.

### 1.5 Staging bundle + signing (what the Portal actually receives)

`./gradlew :guard-core-engine:publishMavenPublicationToCentralStagingRepository`
then zipped from the workspace root - the exact bundle the upload step posts:

```text
com/guard-core/guard-core-engine/4.3.2/
  guard-core-engine-4.3.2.jar / .pom / -sources.jar / -javadoc.jar / .module
  + .md5 / .sha1 for every file (Portal-mandatory) + .sha256 / .sha512
  + maven-metadata.xml with checksums
34 files, 627,914 bytes uncompressed
```

GPG path proven with a throwaway key (temp GNUPGHOME, deleted after): with
`GPG_PRIVATE_KEY` + `GPG_PASSPHRASE` set, the signing block activates and the
staging dir gains `.asc` for all five files (jar, pom, sources, javadoc,
module) - the Portal's every-file signature requirement. The rehearsal
bundles were unsigned (no secret material involved); release CI signs.

INCIDENT CAUGHT AND FIXED: the first bundle simulation exposed a real
workflow bug - the relative zip path dropped `central-bundle.zip` inside the
module directory while the upload step reads the workspace root. Fixed in all
four workflows (`zip -qr "$GITHUB_WORKSPACE/central-bundle.zip" .`, commits
93f878f / 8a87184 / 64dd550 / 9bd686e). This is the rehearsal doing its job.

### 1.6 Registry state + existence-check behavior

Live probes of the exact URLs the workflows query:

```text
repo1.maven.org/maven2/com/guard-core/            -> 404 (no prior art)
repo1.maven.org/.../guard-core-engine/4.3.2/...pom -> 404
repo1.maven.org/.../guard-core/4.3.2/...pom        -> 404
repo1.maven.org/.../spring-boot-guard/4.3.2/...pom -> 404 (probe used 4.3.2;
    the real consumer check queries the artifact's own tag version)
repo1.maven.org/.../ktor-guard/4.3.2/...pom        -> 404
Central search index g:com.guard-core              -> 0 artifacts
```

404 is the expected pre-release state and maps to the publish path in the
workflows; 200 maps to skip (the changed-only rerun safety); any other code
aborts. The full train is well under the 2026-10-01 publishing limits (34
files for the largest deployment; the 90th-percentile monthly threshold is
1,167 files / 78 MB / 7 releases).

### 1.7 Tag-consistency audit simulation

The exact job logic executed against the real workspaces:

```text
[v4.3.2]      guard-core-jvm    PASS: tag v4.3.2 == version 4.3.2
[v4.3.1]      guard-core-jvm    FAIL: tag v4.3.1 != version 4.3.2
[v4.3.2-rc1]  guard-core-jvm    FAIL (suffix rejected at the equality check)
[v1.0.0]      spring-boot-guard FAIL: version 1.0.0-SNAPSHOT is a SNAPSHOT
                                (flip missing) - the intended message
[v3.2.2]      guard-agent-jvm   FAIL: version 3.2.2-SNAPSHOT (same)
post-flip sim (1.0.0 -> tag v1.0.0) PASS
```

## 2. Auth-path decision and what is pending (operator)

Verified (2026-10-11, central.sonatype.org Publisher API docs + release
notes):

- The Central Portal Publisher API authenticates with a Portal **user token**
  (`Authorization: Bearer base64(username:password)`). The workflows are built
  for this path via four secrets: `CENTRAL_PORTAL_USERNAME`,
  `CENTRAL_PORTAL_PASSWORD`, `GPG_PRIVATE_KEY`, `GPG_PASSPHRASE`.
- **OIDC trusted publishing does not exist for Maven Central** (npm/PyPI/
  Packagist have it; Maven does not). Therefore the publish jobs carry
  `contents: read` only and no `id-token` scope. If Sonatype ships trusted
  publishing, that is a follow-up, not a blocker.
- **GPG signing is mandatory** (every file needs `.asc`; proven in 1.5).
- **New publishing limits** took effect 2026-10-01 (announced 2026-06-16,
  enforcement pushed from Aug 11; 30-day grace): three monthly per-org
  metrics (file count, release size, release count), Usage Center is the
  source of truth. This family is orders of magnitude below the thresholds.

Pending on the operator (each blocks the corresponding step of docs/release.md):

1. Portal namespace `com.guard-core` flipping to **Verified**. History:
   `com.guardcore` was abandoned 2026-10-11 (guardcore.com is a parked domain
   the operator does not own, making that claim unverifiable); `com.guard-core`
   reverses to the owned guard-core.com, TXT record placed, claim
   re-submitted 2026-10-11, DNS verification PENDING on Sonatype's side.
   Blocks: everything (validation fails on an unverified namespace).
2. Portal user token generated and the two `CENTRAL_PORTAL_*` secrets set on
   all four repos. Blocks: the publish jobs' credential gate.
3. GPG key pair created, public key published to a keyserver, armored secret
   key + passphrase set as `GPG_PRIVATE_KEY` / `GPG_PASSPHRASE` on all four
   repos. Blocks: the publish jobs' GPG gate (and Portal validation).
4. GitHub releases created per tag at train time (the publish jobs fire on
   `release: created`, not on the tag push alone). Blocks: publishing only.

## 3. Remaining operator steps (release day, condensed)

The full choreography is docs/release.md; the condensed checklist:

1. Confirm the Portal shows `com.guard-core` Verified; secrets set on all
   four repos (section 2 items 2-3); Usage Center clean.
2. Engine: tag `v4.3.2` on a green master -> gates green -> create the GitHub
   release -> publish job uploads + VALIDATES both deployments (engine first,
   facade second) -> click Release on both in the Portal UI -> repo1 answers
   200 for both artifacts.
3. Adapters + agent, in any order (each guarded by its own pre-flight):
   version-flip PR merged (`1.0.0-SNAPSHOT` -> `1.0.0`, `3.2.2-SNAPSHOT` ->
   `3.2.2`; CHANGELOG `## [SEMVER] - YYYY-MM-DD`) -> tag -> release created ->
   pre-flight proves the engine live -> publish -> Portal release -> repo1 200.
4. Post-release audits (per tag): GitHub release page exists; repo1 200 per
   artifact; no deployment left VALIDATED/PENDING in the Portal; Usage Center
   clean. Then move the consumers' pinned engine refs to the released engine
   SHA in the next regular development PR.

Rollback: before the Portal click, Drop the deployment (nothing published);
after the click there is no undo - only a fix version (artifacts are
immutable; tags of published versions never get deleted).
