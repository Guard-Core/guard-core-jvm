<p align="center">
    <a href="https://guard-core.github.io/guard-core/latest/">
        <img src="assets/guard_core_legend.svg" alt="Guard Core">
    </a>
</p>

___

<p align="center">
    <strong>Kotlin/JVM port of the [guard-core](https://github.com/Guard-Core/guard-core) engine. The workspace ships the engine and facade artifacts.</strong>
</p>

<p align="center">
    <a href="https://github.com/Guard-Core/guard-core-jvm/actions/workflows/ci.yml">
        <img src="https://github.com/Guard-Core/guard-core-jvm/actions/workflows/ci.yml/badge.svg" alt="CI">
    </a>
    <a href="https://github.com/Guard-Core/guard-core-jvm/actions/workflows/code-ql.yml">
        <img src="https://github.com/Guard-Core/guard-core-jvm/actions/workflows/code-ql.yml/badge.svg" alt="CodeQL">
    </a>
    <a href="https://github.com/Guard-Core/guard-core-jvm/blob/master/LICENSE-APACHE">
        <img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License Apache-2.0">
    </a>
    <img src="https://img.shields.io/badge/version-4.3.2-0080ff.svg" alt="Version 4.3.2">
</p>

---

## Status

**W0 scaffold.** The workspace skeleton, CI gates, and the vendored spec 4.1.0
conformance corpus are in place; the ported engine code lands in W1+.

**Mirror statement:** guard-core-jvm 4.3.2 mirrors the
[guard-core 4.3.2](https://github.com/Guard-Core/guard-core) release. Versions
move in lockstep, and the conformance corpus records the exact engine commit it
was regenerated at (`adbdccd402ed0fdb0c26023f11c6acc534344521`, spec 4.1.0).

## Modules

| Module | Path | Artifact | W0 contents |
|---|---|---|---|
| Engine | `guard-core-engine/` | `com.guardcore:guard-core-engine:4.3.2` | Placeholder; stays dependency-free (kotlin-stdlib only, no coroutines, no redis, no frameworks) |
| Facade | `guard-core/` | `com.guardcore:guard-core:4.3.2` | Placeholder facade object + coroutine wiring |
| Conformance | `guard-core-conformance/` | unpublished | Corpus smoke test (`ConformanceSmokeTest`); full runner lands in W5 |
| Benchmark | `guard-core-benchmark/` | unpublished | No-op JMH placeholder |

## Toolchain

JDK 17 (Gradle JVM toolchain), Kotlin 2.4.21, Gradle 9.8.1 (wrapper-pinned).
Quality gates: `detekt` + Spotless (`ktfmt`) wired into `check`; JaCoCo applied
with no coverage gate yet. Build with:

```bash
./gradlew build --no-daemon
```

## Conformance

The `conformance/guard-core-spec-4.1.0/cases/` directory vendors the shared
adversarial corpus byte-identical from the guard-core specs/fixtures, generated
by the reference engine and never hand-written. See
[conformance/README.md](conformance/README.md) for provenance and scope; the
comparison contract each port implements lives in the corpus `index.json`.

## License

Dual licensed under [Apache-2.0](LICENSE-APACHE) and [MIT](LICENSE-MIT).
