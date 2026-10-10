# Conformance

Normative conformance harness for [guard-core-jvm](https://github.com/Guard-Core/guard-core-jvm)
against the guard-core spec 4.1.0 fixture corpus. Mirrors the Go and Rust port
layouts (`guard-core-go/conformance/`, `guard-core-rs/conformance/`): the
corpus is vendored byte-identical from the guard-core specs/fixtures, generated
by the reference engine, never hand-written.

## Provenance

- Spec: 4.1.0
- Engine: 4.3.2, commit `adbdccd402ed0fdb0c26023f11c6acc534344521`
- Corpus: `guard-core-spec-4.1.0/cases/` holds 1 index plus 21 suites, vendored
  byte-identical (`cp -p`, verified with `diff -r`). Do not pretty-print,
  re-order, or re-encode the JSON.

## Layout

```
conformance/
├── README.md                      this file: provenance + scope
└── guard-core-spec-4.1.0/
    └── cases/
        ├── index.json             comparison contract, config knobs, cost budgets
        └── (21 suite files)
```

## Scope (W0)

W0 ships only the corpus smoke test (`ConformanceSmokeTest` in the
`guard-core-conformance` module), which reads `cases/index.json` from this
directory via a relative path and asserts the vendored index pins:
`spec_version == "4.1.0"`, `engine_version == "4.3.2"`, 21 suite entries,
`cost_budgets.k == 5`, and `fixed_ip == "203.0.113.7"`.

The full runner, cost-budget measurement, and xfail manifests land in W5. The
comparison rules every port must implement are defined in the `comparison`
object of `cases/index.json` (threat multiset ordering, excluded fields, float
precision, pipeline/event envelope semantics, redis byte equality, and
pattern-safety reason classes).
