# Conformance

Normative conformance harness for [guard-core-jvm](https://github.com/Guard-Core/guard-core-jvm)
against the guard-core spec 4.1.0 fixture corpus. Mirrors the Go and Rust port
layouts (`guard-core-go/conformance/`, `guard-core-rs/conformance/`): the
corpus is vendored byte-identical from the guard-core specs/fixtures, generated
by the reference engine, never hand-written.

## Provenance

- Spec: 4.1.0
- Engine: 4.3.2, commit `37b6a132b7df974f0ea014f3100fd90a76e1ebc5`
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

## Scope (W5, complete)

The full corpus runs in one command:

```bash
./gradlew :guard-core-conformance:fullCorpusGate
```

Runner map (all in the `guard-core-conformance` module):

- `ConformanceSmokeTest` - the W0 vendored-index pins (spec version, engine
  version, suite count, cost budget k, fixed IP).
- `DetectConformanceTest` - the 13 detect suites (193 cases) through the
  engine stack under the index comparison contract.
- `PipelineConformanceTest` - the 5 pipeline suites (35 cases).
- `EventsConformanceTest` - event_stream (39 cases; the 2-entry
  `jvm_events_xfail.json` ledger is the TS-floor reason-string divergence).
- `RedisInteropTest` - redis_interop (14 cases, live Redis).
- `PatternSafetyConformanceTest` - safety_gates (94 cases; the 6-entry
  `jvm_safety_xfail.json` ledger holds cost-verdict timing facts, two of
  them boundary-class).
- `CostBudgetConformanceTest` - the self-relative scan-cost ceilings over
  cost_bodies with the empty fail-closed `jvm_cost_xfail.json`.
- `FullCorpusTest` - the one-gate aggregate with the per-suite summary and
  the pinned totals/ledger floors.

Fail-closed ledger policy everywhere: a failing case not listed is red, a
listed case that heals is a stale baseline (red), and a recorded divergence
that drifts is red. The comparison rules every port must implement are
defined in the `comparison` object of `cases/index.json` (threat multiset
ordering, excluded fields, float precision, pipeline/event envelope
semantics, redis byte equality, and pattern-safety reason classes). See
docs/w5-certification.md for the full W5 accounting.
