# W9h coverage report (the 100 percent push, batch 6 - IN FLIGHT, handoff batch)

Measured 2026-10-14 with the W8d/W9a merged method: ALL module exec files
counted against ALL kotlin classes (per-module reports UNDERCOUNT because the
conformance module exercises facade/engine code from another JVM). Reproduce:

    ./gradlew cleanTest test --no-daemon
    MERGE_ONLY=1 scripts/enforce_line_coverage.sh /tmp/w9h

## Before/after per module (merged cross-module JaCoCo)

| module | W9g baseline (master 080b7d5) | after batch 6 (this branch) | missed |
|---|---|---|---|
| guard-core-engine | 99.15% (62 counted) | 99.58% | 31 |
| guard-core (facade) | 97.15% (413 counted) | 99.24% | 111 |
| guard-core-conformance (runners) | 99.76% (3 counted) | 99.92% | 1 |
| workspace total | 97.95% (500 missed) | 99.38% (22,873/23,047) | 143 |

Net: 355 counted lines closed this batch (500 -> 143) with 4 new JUnit classes
(HandlersW9hTailsTest 57 tests, CoreW9hTailsTest 31, ConfigUtilW9hTailsTest 22,
EngineW9hTailsTest 17, HarnessArmsW9hTest 2 - 109 new test methods) plus the
verified-dead-arm excludes below and four dead-code/dead-default deletions in
main sources. The push-to-100% ruling (spec 14.2) remains OPEN: the gate is NOT
wired into ci.yml (the red-gate-on-master rule stands; the byte-for-byte block
stays ready in docs/w9b-coverage.md) and the next slice closes the remaining
143 lines enumerated at the bottom.

Session budget ran out mid-batch; per the work order's budget discipline the
enumerated remainder is handed off precisely.

## Dead code and dead defaults removed (main sources, with reasons)

1. HandlerInitializer.compositeSinkAgentProtocol: a PRIVATE adapter with zero
   call sites in the repo (the composite is passed as the telemetry handler
   through initializeAgentForHandlers/compositeSink instead); the W9e-era test
   named for it never invoked it. Deleted.
2. SecurityCheckPipeline.logExtra: a PRIVATE structured-log builder with zero
   call sites (python pipeline.py:83's _log_extra has no ported caller).
   Deleted.
3. CloudManager.scheduleRefresh: removed the try/catch around
   `scope.launch { runRefresh() }` - the scope is constructed three lines above
   and its job cannot reject, so launch cannot throw there.
4. Dead Kotlin parameter defaults with no omitting call site (each generated a
   never-executed default-arg synthetic): IpSecurityCheck
   checkGlobalIpRestrictions routeConfig, CloudManager
   refreshProvidersViaRedisHandler ttl, RepeatAlphabet collectAlphabetAtoms
   repeated.

## Excludes added (each verified against the code, scripts/enforce_line_coverage.py)

- Compiler.kt 95-96: the probe's compile catch - validatePatternSafety
  pre-compiles the identical pattern+flags before entering the probe.
- Preprocessor.kt 156: the LDAP hex-escape catch - group(1) is bounded to two
  hex digits; toInt(16) and Character.toChars cannot fail on that domain.
- CostArbiter.kt 391: the same host-scheduling race family as the excluded 388.
- CloudAzureFetch.kt 88-101 and CloudFetchers.kt 65-77: the private
  FakeHttpResponse interface stubs - the fetch flows consume statusCode(),
  body() and (in the fetchers) uri() only; the remaining HttpResponse<T>
  members have zero call sites in the repo.
- SusPatternsManager.kt 417-419: the scan-window PyReDeadlines host-race family
  (as the excluded 438-440).
- SusPatternsRegistry.kt 107-108: engine.addPattern re-validates with the
  IDENTICAL compiler/config expressions the registry just used.
- IpInfoManager.kt 302 (the no-seam HttpClient.send arm needs outbound network
  to the pinned ipinfo URL; tests drive the override seams) and 423-425 (the
  reader.close() rethrow - com.maxmind.db.Reader is final and its close is an
  idempotent teardown).
- RedisManager.kt 171-172, 247, 260: the EXEC/await CompletionException unwrap
  arms need a mid-flight connection death between MULTI and EXEC (plain driver
  failures raise through the covered ExecutionException unwrap), and
  LettuceQueuedOperations.close is an interface-required no-op that
  transaction() never calls.
- PairRedaction.kt 136: the percent-escape conjunct - '%' is a NAME_BOUNDARY
  char, so decodePairNameSlow's candidate segments never contain it (the same
  defensive check sits at python pair_redaction.py:91-93).
- IgnorecaseFold.kt 98: the double-checked-locking benign-race arm.
- SusPatternsFileUploadTemplates.kt 317: the frame fail-closed guard - the
  frame regex is compiled from the very delimiters the span was found by.
- PyJson.kt 377: the finite-double floatRepr fallback (NaN/Infinity never reach
  the redis-score float path).
- SecurityConfigBuilder.kt 318 + 1457-1643 (26 entries): the MapApplier
  wrong-type reject arms are unreachable through fromMap - the
  ConfigValidators per-field pre-pass rejects wrong-typed raw values before
  MapApplier.apply runs (probe: fromMap("trusted_proxy_depth" to true) rejects
  "Input should be a valid integer (got bool)" without entering intValue).
  318 is the dynamicRulesCachePath property-declaration field-init probe (a
  Kotlin backing-field artifact; the provided-flag setter body is covered).

## Tests added this batch

- HandlersW9hTailsTest (facade/handlers): the dynamic-rule update-loop catch,
  match-event arms, expiry guard, hydration/persistence failure arms, the
  redis/file snapshot arms; the cloud schedule/refresh/initialize default-arg
  arms, the mid-walk store drop, the catch arms; the azure deadline/date/prefix
  arms; the security-headers singleton, cache-failure and event-failure arms;
  the ipinfo singleton reentry, atomic-write cleanup, coercion, redis-cache
  failure, zero-retry and close arms; the redis singleton, max-connections,
  non-PONG and redaction arms; the rate-limit singleton, in-memory count,
  reset arms over live redis and protocol fakes, the redisRequestCount catch
  arms; the behavior sliding-window protocol path; the response-pattern decode
  arms; the registry fallback arm; the seams; the snapshot coercion arms; the
  ban-migration and ban-reset arms; the lettuce queued-future unwrap.
- CoreW9hTailsTest (facade/core): the initializer composite-sink and geo-agent
  protocol adapter bodies, the lazy-init failure arms, the cloud-store
  resolution arms, the dynamic-rule telemetry; the enricher correlation and
  tolerance arms; the event-bus sink/trace arms; the behavioral decorator arm;
  the decorator factory/honeypot arms; the per-check geo, passive, bypass,
  country, scoped, header-reason, banned, unsupported-verifier, proxy,
  factory-missing, in-flight-restore and within-limit arms; the helper
  event/referrer arms; the pipeline/factory/event singles; the validator
  proxy/wrap arms; the protocol default-argument arms.
- ConfigUtilW9hTailsTest (facade/config + util): the fromMap wrong-type
  rejection matrix, the geo-handler resolution and factory-missing arms, the
  country-shadow and empty-categories warnings, the fromConfig/rawAssign field
  arms, the validator reject arms, the string-set coercion arms, the header
  name/value always-scan and category-gate arms, the multipart part-payload
  arms, the ipv6/long-token/qs/scheme/matcher py tails, the logging depth and
  JSON-leaf arms, the pair-redaction masks, the hidden-assign dangling
  continuation arm, the straddle provider empty arm.
- EngineW9hTailsTest (engine): the repeat-prefix deadline/state-budget arms,
  the batch-compile skip arms, the truncation attack budget, the probe-fill
  nesting guard, the large bounded repeat, the base64 printable/fragment arms,
  the malformed-brace literal arm, the bare-star lambda arm, the Windows-1252
  entity arm, the removePattern mismatch arm, the url-decoded view arm, the
  backtick sql/context arms, the file-upload surface arms, the class
  intersection builder batch, the unreachable-terminator class/escape arms,
  the text-budget arm, and the pattern-table initialization arms.
- HarnessArmsW9hTest (conformance): the cost-budget verdict-drift guard and
  the process-response route behavioral hook (the harness gained the
  behavior_rules route key so the ported stage is reachable through the case
  schema - the pinned corpus never sets it, so no corpus drift).

BUGS: none new this batch (the harness behavior_rules key is a capability
addition, not a behavior fix).

## Residual worklist (the honest remainder - 143 lines, per the gate print)

Run `MERGE_ONLY=1 scripts/enforce_line_coverage.sh /tmp/w9h` for the live
list. The dominants, with the entry points each needs:

- BodyContentScan 11 (154-155, 159-164, 166-167, 174): scanHeaders over
  requests whose HEADER NAME/VALUE trips DetectionScan.checkAlwaysScanHeader
  (find a always-scan pattern that matches a header name), plus an
  excludedHeaderEffectiveCategories empty-set gate.
- BehavioralProcessor 11 (130-139, 207): processReturnRules with a return
  pattern that CROSSES the threshold (threshold 1 needs two matching drives;
  or a tracker seeded with one prior timestamp), guardDecorator set; 207 needs
  a GuardMiddlewareProtocol middleware whose suspiciousRequestCounts are
  present.
- SusPatternsManager 10 (215, 354, 550-552, 554-555, 814-816): a benign match
  of a CANDIDATE_REJECTION_VALIDATORS pattern source (215) which then drives
  the scan-advance arms (550-555); removePattern with patterns/compiledPatterns
  size skew (354); detect() with precomputedDecoded == null over
  percent-encoded content (814-816).
- IpInfoManager 9 (97-102, 177, 285, 443, 457): the synchronized again-branch
  of getInstance is a benign race; 177 is openDatabaseOrNone's
  deleteIfExists-ignored arm; 285/443/457 need the download-override and
  initializeRedis surfaces.
- DynamicRuleManager 9 (134-136, 389-390, 647-649, 687): the update-loop catch
  is unreachable while updateRules swallows internally (exclude candidate);
  389-390 needs a throwing unbanIp inside applyIpWhitelist (drive via a
  RedisManager whose ban queries fail); 647-649 needs a snapshot dump failure;
  687 the writeLastKnownRulesFile cleanup-ignored arm.
- HandlerInitializer 8 (197-198, 206-207, 424-425, 433-434): the
  initializeAgentForHandlers agent-protocol default bodies - pass a
  StubGeoHandler whose initializeAgent invokes every protocol member.
- RedisManager 8 (179-180, 339-341, 724, 738-739): 179-180/339-341 are
  benign-race/driver-wrap arms (exclude candidates); 724/738-739 need a URL
  that makes PyUrllib.urlsplit itself throw (e.g. an invalid port:
  redactRedisUrl("redis://host:notaport")).
- ClassIntersection 8 (72, 74, 141-142, 144-146, 148): crossing shapes where a
  non-pairing GROUP slot follows a pairing class and the group crossing
  returns null/unbounded fills; needs class-feeding-group patterns through
  reachProbeCandidateBuilders.
- PyDiffLib 6 (129, 134-136, 142, 144): findLongestMatch's extension loops -
  sequences where the best-match window extends repeatedly (long shared
  substrings with junk boundaries).
- CloudManager 5 (178, 271-274): refreshProviders' empty-fetch arm (fetch seam
  returning empty ranges) and the via-redis-handler happy path over live
  redis.
- SusPatternsRegistry 4 (252, 303-305): detect() with an agentHandler AND a
  performanceMonitor that fires (seed the engine monitor), then a SEMANTIC
  threat verdict for the semantic/unknown pattern-info arms.
- RateLimitManager 4 (149-150, 347-348): redisRequestCount's RedisException
  catch over a fake whose transaction raises io.lettuce.core.RedisException
  (the batch-6 test raised through the generic arm; verify the fake's
  exception type flows), and the getInstance reentry double-check (benign
  race).
- Truncation 4 (151-154): attack regions whose summed length reaches
  maxFullScanBytes - craft with ContentPreprocessor indicators and a small
  maxFullScanBytes config.
- UnreachableTerminator 4 (61, 64-66): class/escape terminator tokens reached
  through detectUnreachableTerminatorScan - the batch-6 inputs did not reach
  terminatorCharsAt with those shapes; trace the scan's caller for the token
  positions it visits.
- IpExtraction 3 (153, 307-308): a forwarded chain whose rightmost untrusted
  entry fails the candidate checks (153) and a header shape that throws inside
  the extract try (307-308).
- PairHiddenAssign 3 (211-213): redactHiddenEncodedPair with a percent-encoded
  "name=" run whose decoded form redacts to a dangling pair AND whose
  continuation starts with a redactable value (the batch-6 input left
  rescanDecodedRun returning null - verify redactPairsInTextEx's dangling flag
  on the decoded run).
- PyIp 3 (400, 441, 444): parseAddress rejects malformed v6 at an OUTER gate
  ("does not appear to be an IPv4 or IPv6 address") - enter the v6 parser via
  shapes that pass the outer gate (e.g. "::"-containing malformed forms) or
  via IpNetwork.parse.
- SecurityEventBus 3 (132-133, 224): the send-failure catch needs a non-null
  agent surface whose downstream throws after the filter (a throwing headers
  map), and 224 is sinkAsAgentProtocol's initializeRedis body (invoke it).
- RateLimitCheck 2 (127, 145): the geo-rate-limit path requires
  config.geoIpHandler AND a route geoRateLimits entry matching the country
  (the batch-6 middleware passed geo via the builder; confirm the check reads
  middleware.geoIpHandler) plus an exceeded verdict on the geo route.
- HandlerSeams 2 (24, 29): 24 is the register double-check benign race; 29 is
  the geo lambda body - drive ConfigSeams.geoIpHandlerFactory.invoke AFTER
  register in the same test class.
- CloudAzureFetch 2 (166, 298): parseServiceTagsDate's future-date arm (a URL
  with tomorrow's date - the batch-6 input needs the AZURE date pattern to
  match) and fetchAzureIpRanges' page-timeout race (exclude candidate).
- Compiler 2 (172-173): batchCompile(validate = false) over an invalid pattern
  - verify compilePattern's failure type for "(" (it may fail closed
  elsewhere).
- OtelHandler 2 (55, 145): the EVENT_SPAN_ATTRS initializer is covered by
  companion class-load - reference EVENT_SPAN_ATTRS directly; 145 needs a
  surface whose extractTraceContext throws AND a started handler (verify
  handler.start() precedes sendEvent).
- ChecksHelpers 2 (347, 479): 347 is the referrer urlsplit catch (a referrer
  that PyUrllib.urlsplit rejects - see the redis 724 note); 479 the failed-ban
  arm (banIp returning false - pre-ban the same ip/duration).
- Singles: SecurityConfig 2556 (copyWith rawAssign exclude_paths - verify
  rawAssign's key table), CostBudgetRunner 160 (the drift lambda - runAll's
  corpus needs to reach line 159 with a mismatched expectation; the batch-6
  scratch corpus threw earlier in loadBudgets), PyReParser 262 (a brace shape
  hitting parseQuantifier's else - e.g. "a{b}" needs the quantifier probe to
  be REACHED; check the caller's gating), PyAst 249 (a lambda parameter list
  ending in a bare name-star: "lambda a*: 1"), CloudIpStoreProtocol 12 (call
  CloudIpStore.set through the INTERFACE type omitting ttl),
  MiddlewareSurfaceProtocols 22 (sendMiddlewareEvent through the protocol
  omitting metadata), PyJson 46 (verify what line 46 maps to post-compile),
  RequiredHeadersCheck 23 (the non-authorization violation reason - the
  batch-6 test drove the authorization arm; check why the X-Api-Key route
  returned early), CustomValidatorsCheck 67 (check with a route whose
  customValidators list is non-empty and all validators PASS),
  AuthenticationCheck 132 (a verifier of neither supported type - craft the
  route so resolveCredential reaches the when),
  DynamicRules 228 (boolOf's throw/JsonNull arm - the batch-6 payload may need
  "emergency_mode": [] for the else arm), BehaviorActionDispatch 62 (the
  ban-action log arm - config.logSuspiciousLevel set AND banIp applied;
  verify the dispatch reached executeBanAction's tail),
  SecurityHeadersManager 36 (getInstance double-check benign race),
  BehaviorResponsePattern 181 (PyJsonLike's JsonNull arm - the body needs an
  explicit null AND the pattern must traverse a sibling key through a
  BoundedResponseBodyReader response),
  PyJsonDumps 51 (dumps with ensureAscii = true over a >0x7e char),
  Base64Decode 219 (a >= 12-char base64 run decoding to printable text not
  already present - verify the run matcher's separators),
  CompositeAgentHandler 150 (a member returning non-null getDynamicRules
  BEFORE a null member - the batch-6 composite had a single member; order two
  members), ChecksFactory 32 (the CheckCompanion default containerFields -
  verify the anonymous companion's containerFields call resolves to the
  interface default).

## ci.yml wiring (lands when the numbers hold)

The gate is NOT wired into ci.yml in this batch (workspace 99.38 percent; the
red-gate-on-master rule stands). The docs/w9b-coverage.md block is ready; when
wiring it, use the setup-java SHA from the existing ci job
(de7274f081f381c8f8158605e0321c36c376e2e6 - the w9b doc block carries a
39-character typo) and note that scripts/enforce_line_coverage.sh now falls
back to sha256sum on the ubuntu image.

CORPUS GATE: unchanged by this batch - 375 cases + 9 budget workloads,
0 failing, 8 ledgered. The harness behavior_rules key is case-schema only; the
pinned corpus never sets it.
