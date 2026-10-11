# Contributing to Guard Core JVM

Thanks for considering a contribution to guard-core-jvm, the Kotlin/JVM port of
the [guard-core](https://github.com/Guard-Core/guard-core) engine. The JVM
family follows the ecosystem conventions of the Python baseline (guard-core and
its adapter set): the behavioral spec is normative, and the conformance corpus
is the executable proof.

## Development Setup

Requirements:

- JDK 17 (temurin recommended; the build pins the JVM toolchain to 17)
- Docker (Redis runs as a CI service locally too, via `docker run -p 6379:6379 redis:7-alpine`)

```bash
./gradlew build --no-daemon                                    # detekt + ktfmt check + unit tests
./gradlew :guard-core-conformance:fullCorpusGate --no-daemon   # full spec corpus, needs Redis on 127.0.0.1:6379
osv-scanner scan --lockfile guard-core-engine/gradle.lockfile --lockfile guard-core/gradle.lockfile --lockfile guard-core-conformance/gradle.lockfile --lockfile guard-core-benchmark/gradle.lockfile   # dependency audit (see CI)
```

The version catalog (`gradle/libs.versions.toml`) is the single source of
truth for every third-party pin; per-module `gradle.lockfile` state is
committed and enforced on every resolution (a dependency change without
`./gradlew --write-locks` fails the build). Dependency additions need
justification in the PR adding them (see the supply-chain rules in the
behavioral spec, section 14).

## Quality Gates

Run before pushing (CI enforces the same checks):

```bash
./gradlew detekt ktfmtCheck --no-daemon   # static analysis + formatting
./gradlew :guard-core-conformance:fullCorpusGate --no-daemon   # conformance: red corpus = merge blocked
```

The full corpus gate is fail-closed: totals are pinned (375 cases + 9 cost
budgets), a growing ledger is red, and an unlisted over-ceiling workload
fails the gate.

## Pull Requests

- Every PR closes an open issue ("Delivers issue: #N") or carries the `no-issue` label (chores and dependency bumps).
- Keep the CI green; one clean push per PR is preferred.
- Commit messages: lowercase, imperative, conventional style (`fix(scope): ...`, `feat(scope): ...`, `ci(scope): ...`). No attribution trailers.
- Behavior changes need corpus evidence first: update the pattern ledger or xfail manifests, then the code, then the docs.

## Security

Never open public issues for security vulnerabilities. Follow SECURITY.md and report via GitHub security advisories.

## Questions

Open a GitHub Discussion in this repository or ask in the Guard Discord (#help).
