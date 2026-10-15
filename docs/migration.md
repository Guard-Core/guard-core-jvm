# Migration

## No prior JVM version exists

guard-core-jvm is a fresh port family: the first stable release is the
current 4.4.0 mirror line, and no earlier JVM major version exists to migrate
from. Nothing was ever published under the interim `com.guardcore` group ID
(see the CHANGELOG's groupId note), so there is no coordinate migration
either. Consumers adopt at `com.guard-core:guard-core:4.4.0` or through an
adapter.

## Porting from another guard family

Behavior is identical across the family (that is the parity bar): the same
verdicts, status codes, headers, Redis key schema, and event surfaces. When
moving an existing deployment from the Python, Go, Rust, TypeScript, or PHP
family to the JVM:

- Configuration translates 1:1 through the canonical snake_case field names
  ([Configuration](configuration.md) lists every field with its Kotlin
  property; adapters map them idiomatically).
- The section 08 Redis state schema is byte-compatible across the family:
  a JVM deployment can take over the Redis state an existing family member
  wrote (same key names, prefixes, and serialization), subject to the
  mixed-version constraints below.
- Detection coverage and category names are identical; the JVM compiles the
  corpus patterns as-is (158-entry pattern ledger, zero translations).

## Mixed-version interop constraints

The section 08 state format is the cross-language contract and changes only
with a spec version bump. Such changes are documented in the CHANGELOG
(targeting the spec version) and in [Release notes](release-notes.md)
before release, and they are the SECURITY-adjacent interop constraints to
check before rolling a JVM port into an existing mixed-family Redis fleet.

## Deprecations

Deprecated config fields or checks are documented in the CHANGELOG with
their replacement and the removal target version. At the 4.4.0 baseline
there are no deprecations.
