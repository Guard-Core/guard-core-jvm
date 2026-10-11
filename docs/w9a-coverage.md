# W9a coverage report (facade module)

Measured 2026-10-11 with the W8d merged method: ALL module exec files counted
against ALL kotlin classes (per-module reports UNDERCOUNT cross-JVM execution).
Reproduce: `./gradlew cleanTest test` then
`scripts/w9a_merged_coverage.sh /tmp/w9a` (jacococli 0.8.15 nodeps), then
`python3 scripts/w9a_class_detail.py /tmp/w9a/merged.xml com/guardcore`
for the exact per-line enumeration below.

## Facade module (guard-core) before/after per package

| package | before (W8d merged) | after (W9a) |
|---|---|---|
| com/guardcore/util | 60.1% (1,131) | 92.3% (219) |
| com/guardcore/config | 70.6% (1,070) | 92.3% (283) |
| com/guardcore/handlers | 80.4% (705 missed) | 89.3% (401) |
| com/guardcore/core/checks/implementations | 82.8% (201) | 92.0% (93) |
| com/guardcore/core/events | 70.5% (188) | 87.3% (81) |
| com/guardcore/decorators | 75.8% (121) | 76.0% (120) |
| com/guardcore/core/initialization | 56.1% (116) | 78.8% (56) |
| com/guardcore/core/checks | 90.0% (52) | 90.0% (52) |
| com/guardcore/core/behavioral | 49.4% (84) | 87.4% (21) |
| com/guardcore/java | 28.6% (35) | 67.4% (16) |
| com/guardcore/core/validation | 78.5% (14) | 78.5% (14) |
| com/guardcore/core/responses | 88.2% (10) | 88.2% (10) |
| com/guardcore/core/bypass | 98.5% (1) | 98.5% (1) |
| com/guardcore/core/routing | 95.8% (1) | 95.8% (1) |

Facade module total: 14,704 lines, 1,391 missed -> **90.54% line coverage**
(13,313/14,704, measured on the merged master c80e621; the wave baseline was
69.12%, 10,122/14,644). The 97% wave gate needs <=441 residual lines; the
remaining ~950 are enumerated per class below with their reason and are the
explicit W9a-inflight worklist (tracked in #26; no JaCoCo excludes were
added; the engine/conformance residuals are W9b scope per the work order).

## Tests added this wave

- 14 new JUnit classes, ~150 test methods: body-scan surface (structured
  json/nosql, depth caps, form value embedded json, non-utf8 bodies, multipart),
  logging + block events, proxy handling + access control + detection scan
  budgets + agent events + body reader, the pair grammar sweep, py stdlib
  tails, config mutation sweeps + fromMap + to_agent_config, cloud fetchers/
  refresh, dynamic-rule lifecycle + full application bodies, redis operations
  sweep, referrer + time window flows, behavioral usage/return, composite
  telemetry, java bridges, otel/logfire surfaces, initializer arms.

## Bugs found and fixed (byte-exact, with regression tests)

1. **global_behavior_rules setter used the wrong revalidator**
   (SecurityConfig.kt): python coerces dict entries to BehaviorRuleConfig at
   assignment (_validate_typed_collection_field_value with
   _GLOBAL_BEHAVIOR_RULES_ADAPTER, pinned by
   test_global_behavior_rules_reassignment_coerces_dicts_to_model); the JVM
   setter ran the str-list validator and DROPPED/REJECTED the entries. Fixed
   with ConfigValidators.validateGlobalBehaviorRulesFieldValue.
2. **nowSeconds() resolution = the recurring rate-limit zwrite loss**
   (IpBanBans.kt): System.currentTimeMillis()/1000.0 has millisecond resolution,
   so two sliding-window zadd calls inside the same millisecond produce the same
   sorted-set member and the second write is a silent no-op. python time.time()
   has microsecond resolution and never collides. The work order's
   "RateLimitManager pipeline+primitive interleave zwrite loss" flake (3
   recurrences this wave) is this bug. Fixed with an Instant-based nowSeconds.
3. **redis_interop runner: score_equals_member compared RAW STRINGS**
   (RedisInteropTest.kt): the reference harness (redis_interop_cases.py:311-313)
   pins the rate-limit zset contract as NUMERIC equality within 1e-6
   (abs(score - float(member)) < 1e-6) because the member is rendered by the
   redis-side Lua, whose float formatting is build-dependent (the docker
   redis builds emit e-notation for sub-microsecond timestamps; glibc/macOS
   builds render positionally). The nowSeconds fidelity fix (item 2) is what
   surfaced it. The verifier now ports the numeric contract, and the CI redis
   images were aligned to the redis 8 major the corpus is generated against
   (matching the python family pin image: redis).
3. **Test-suite state leak (SusPatternsRegistryTest)**: removed a DEFAULT
   pattern from the process-global table and never restored it, disabling one
   detection pattern for every suite running after it.

## Test seams added (main code, mirroring the python monkeypatch surface)

- CloudFetchers.httpGetOverride / CloudAzureFetch.httpGetOverride (the aiohttp
  session-mock analog) and fetchProviderRangesOverride (the
  patch("...cloud_handler.fetch_aws_ip_ranges") analog). Production never sets
  them; the house pattern (CloudManager.isCloudIpOverride et al).

## Residual uncovered facade lines, enumerated with reasons

### W9a scope (in-flight worklist to the 97% gate)

W9a-inflight: per-validator rejection arms (ip lists, categories, cors, threat ban, endpoint limits) need a fromMap invalid-value sweep [106 lines]

- `com/guardcore/config/ConfigValidators.kt` missed=106
  - lines: 27, 44, 52, 61-62, 67-68, 72-73, 93, 99, 152-153, 162, 170, 179-186, 188-190, 193-194, 199, 275-276, 308, 321-323, 329-330, 360, 363, 424, 430-432, 434, 440-441, 447, 451-452, 457, 471-472, 478, 488-489, 493-494, 507-508, 551-553, 577-579, 582-584, 588-590, 595-597, 614-616, 624-629, 638-643, 663-667, 669, 671, 677, 720-722, 729-731, 738-740

W9a-inflight: MapApplier type-coercion reject arms + provided-setter bookkeeping lines [98 lines]

- `com/guardcore/config/SecurityConfigBuilder.kt` missed=98
  - lines: 30, 39, 48, 56, 65, 74, 96, 104, 112, 120, 133, 151, 162, 177, 185, 194, 206, 220, 228, 236, 244, 252, 260, 268, 276, 284, 292, 300, 308, 318, 333, 369, 437, 439, 446, 448, 1010, 1022-1023, 1290, 1292, 1308-1309, 1332-1333, 1457-1458, 1467-1470, 1479, 1488, 1497, 1507, 1519, 1525, 1531, 1537-1539, 1548-1551, 1554, 1562-1563, 1572-1573, 1589, 1592, 1599-1603, 1605, 1609-1624, 1636-1637, 1639, 1643

W9a-inflight: dynamic-rule snapshot store arms, ipinfo download retry loop (network-bound: 401/retry arms need a live endpoint or a transport seam), redis safeOperation error arms [401 lines]

- `com/guardcore/handlers/IpInfoManager.kt` missed=82
  - lines: 26, 33-35, 89, 97-99, 101-102, 134, 161-162, 172, 177, 185-186, 196-200, 223, 279-280, 285, 297, 301, 303-306, 309-310, 312-318, 321, 330, 349, 351, 360-370, 372, 374, 394-399, 401, 415, 422, 424, 432-436, 438, 441-442, 445, 447-450, 456
- `com/guardcore/handlers/DynamicRuleManager.kt` missed=40
  - lines: 90, 131-136, 147, 182, 199, 317, 389-390, 462-465, 548, 573-574, 605-607, 610, 622, 626-627, 647-649, 656-657, 667-668, 684-688, 693
- `com/guardcore/handlers/CloudManager.kt` missed=39
  - lines: 69, 94, 101, 105-106, 119-122, 153, 173, 175-176, 183, 191-193, 195-196, 200, 212-213, 232-235, 242, 244, 248-249, 276-279, 312, 370-371, 451-452
- `com/guardcore/handlers/RedisManager.kt` missed=38
  - lines: 171-172, 179-181, 197, 247, 260, 308, 339-341, 404-405, 427, 476, 720-721, 724-726, 738-739, 748-749, 762-769, 771-772, 777, 782, 786
- `com/guardcore/handlers/RateLimitManager.kt` missed=30
  - lines: 85, 149-152, 178, 183, 347-348, 381-383, 385-386, 449-450, 530-536, 596-597, 610-611, 615, 618-619
- `com/guardcore/handlers/BehaviorResponsePattern.kt` missed=26
  - lines: 30, 40-44, 46, 48, 71, 78-79, 81-82, 84, 88, 101-102, 113-114, 158-159, 178-179, 181, 185, 188
- `com/guardcore/handlers/SecurityHeadersManager.kt` missed=23
  - lines: 36, 50, 118, 244, 413, 488-490, 519-520, 544-545, 593, 598, 660-661, 707-709, 729-730, 737, 782
- `com/guardcore/handlers/CloudAzureFetch.kt` missed=22
  - lines: 87, 89, 91-92, 94-95, 109, 160, 179, 181, 183, 195, 197-199, 227, 232-233, 282-283, 292, 312
- `com/guardcore/handlers/BehaviorActionDispatch.kt` missed=22
  - lines: 23-24, 37-40, 43-46, 52, 55, 62, 82, 91-92, 100-101, 140, 145, 160-161
- `com/guardcore/handlers/BehaviorTracker.kt` missed=18
  - lines: 63, 67, 75, 213, 225-233, 235-238, 240
- `com/guardcore/handlers/SusPatternsRegistry.kt` missed=11
  - lines: 44, 59-60, 94, 108, 195, 233, 252, 303-305
- `com/guardcore/handlers/DynamicRules.kt` missed=9
  - lines: 161, 208, 218, 228, 238, 250, 253, 256, 258
- `com/guardcore/handlers/CorsHandler.kt` missed=9
  - lines: 16, 18-21, 24-27
- `com/guardcore/handlers/CloudFetchers.kt` missed=9
  - lines: 64, 67, 69, 71-73, 159, 184-185
- `com/guardcore/handlers/DynamicRuleEvents.kt` missed=7
  - lines: 33-34, 59-60, 82-83, 88
- `com/guardcore/handlers/IpBanMigration.kt` missed=4
  - lines: 19, 38, 47-48
- `com/guardcore/handlers/IpBanBans.kt` missed=3
  - lines: 60, 234, 237
- `com/guardcore/handlers/HandlerSeams.kt` missed=2
  - lines: 24, 29
- `com/guardcore/handlers/TtlCache.kt` missed=2
  - lines: 66, 105
- `com/guardcore/handlers/DetectionScanRedaction.kt` missed=2
  - lines: 37, 64
- `com/guardcore/handlers/IpBanQueries.kt` missed=2
  - lines: 101, 104
- `com/guardcore/handlers/PyJsonDumps.kt` missed=1
  - lines: 51

W9a-inflight: body-scan tail branches (multipart boundary edge shapes, scan-value cap warnings) [240 lines]

- `com/guardcore/util/BodyContentScan.kt` missed=79
  - lines: 41-43, 49, 69-73, 87-90, 94, 115, 139, 146-149, 154-155, 159-164, 166-167, 174, 199-202, 215, 247, 255-256, 258-268, 271-280, 283-284, 286, 297-300, 306-315, 436-437
- `com/guardcore/util/BodyFormScan.kt` missed=25
  - lines: 62-65, 93-94, 104, 107, 110, 129, 194-196, 198-201, 219-221, 223, 260-263
- `com/guardcore/util/PenetrationDetection.kt` missed=19
  - lines: 75-76, 151, 154, 226-230, 233-240, 255, 268
- `com/guardcore/util/DetectionScan.kt` missed=18
  - lines: 89, 96, 107, 146, 177, 183-185, 187-188, 190-194, 196-197, 209
- `com/guardcore/util/PairHiddenAssign.kt` missed=13
  - lines: 73, 115, 118, 209-211, 218, 223-224, 264, 272-274
- `com/guardcore/util/BodyJsonScan.kt` missed=11
  - lines: 58-59, 81, 87, 94-97, 303, 310-311
- `com/guardcore/util/BodyReader.kt` missed=11
  - lines: 98-100, 102, 125-131
- `com/guardcore/util/RequestLogging.kt` missed=10
  - lines: 260, 263-264, 271, 290, 293, 336, 340, 414, 424
- `com/guardcore/util/DetectionConfig.kt` missed=9
  - lines: 13, 48, 71, 85, 136-137, 146, 159, 178
- `com/guardcore/util/PairRedaction.kt` missed=7
  - lines: 136, 153, 156-157, 223, 226-227
- `com/guardcore/util/py/PyDiffLib.kt` missed=7
  - lines: 49, 129, 134-136, 142, 144
- `com/guardcore/util/py/PyIp.kt` missed=6
  - lines: 92, 130, 290, 400, 441, 444
- `com/guardcore/util/py/PyJson.kt` missed=5
  - lines: 46, 128, 151, 241, 377
- `com/guardcore/util/LoggingUtils.kt` missed=4
  - lines: 28, 50, 119-120
- `com/guardcore/util/IpExtraction.kt` missed=4
  - lines: 40, 153, 307-308
- `com/guardcore/util/DetectionEngineWiring.kt` missed=3
  - lines: 77-78, 97
- `com/guardcore/util/py/PyUrllib.kt` missed=3
  - lines: 70, 146-147
- `com/guardcore/util/AccessControl.kt` missed=2
  - lines: 313-314
- `com/guardcore/util/PairValueScan.kt` missed=2
  - lines: 159, 186
- `com/guardcore/util/DetectionScanBudget.kt` missed=1
  - lines: 136
- `com/guardcore/util/AgentEvents.kt` missed=1
  - lines: 118

W9a-inflight: remaining copyWith/toAgentConfig/assignByName dispatch arms (models.py tail); next test batch [70 lines]

- `com/guardcore/config/SecurityConfig.kt` missed=70
  - lines: 1850-1851, 1854-1855, 2162-2163, 2223, 2251, 2256, 2264, 2444, 2457, 2475, 2481-2482, 2484-2485, 2493, 2503, 2509-2516, 2518-2519, 2522-2523, 2528-2542, 2544-2545, 2547-2568

W9a-inflight: the cloud/geo lazy arms with a REAL RedisManager + the foreign-telemetry halves [56 lines]

- `com/guardcore/core/initialization/HandlerInitializer.kt` missed=56
  - lines: 52, 150-152, 154-158, 165-166, 177-178, 180-181, 187-188, 192-193, 197-198, 202-203, 206-207, 210-211, 214-215, 217, 219, 235-236, 244-245, 256-258, 260, 272, 285, 288, 410, 414-415, 419-420, 422, 424, 426, 428, 430, 462-463, 471-472

W9a-inflight: SecurityDecorator honeypot/cors closure arms + StampedRoute tails [120 lines]

- `com/guardcore/decorators/SecurityDecorator.kt` missed=55
  - lines: 36, 44, 66, 106, 109, 119-122, 127, 130-131, 171, 180, 183-184, 211, 230, 239-240, 249, 264-267, 321-324, 327, 329-333, 335-337, 339-340, 342-343, 345-346, 348-349, 351-352, 357, 361, 374, 421, 429, 437, 452
- `com/guardcore/decorators/RouteConfig.kt` missed=34
  - lines: 53, 55, 59, 62, 66, 68, 74, 79, 83, 85, 87, 89, 91, 110, 113, 122, 128, 130, 132, 152, 154, 160, 162, 164, 166, 168, 172, 176, 207-209, 219-221
- `com/guardcore/decorators/BaseSecurityDecorator.kt` missed=31
  - lines: 32, 36, 70, 99, 115, 121, 143, 147, 177, 181, 183-192, 194, 197, 201, 203-209, 211

W9a-inflight: small check tails (emergency-mode ip extraction, required-header violation reports, rate-limit autoban feed) [145 lines]

- `com/guardcore/core/checks/implementations/RequestSizeContentCheck.kt` missed=34
  - lines: 37, 84-86, 89-94, 96-108, 111-118, 121-122, 125
- `com/guardcore/core/checks/SecurityCheck.kt` missed=26
  - lines: 35, 44, 49, 51-52, 59, 62, 64-68, 70-82, 84
- `com/guardcore/core/checks/implementations/EmergencyModeCheck.kt` missed=17
  - lines: 27, 29, 34, 40-41, 79-89, 93
- `com/guardcore/core/checks/implementations/HttpsEnforcementCheck.kt` missed=15
  - lines: 29-30, 32-34, 43-46, 50-51, 55, 61-62, 75
- `com/guardcore/core/checks/SecurityCheckPipeline.kt` missed=14
  - lines: 23, 38, 53, 65, 93-97, 108-110, 114, 244
- `com/guardcore/core/checks/ChecksHelpers.kt` missed=9
  - lines: 46, 53, 109-110, 127, 134, 347, 474, 479
- `com/guardcore/core/checks/implementations/RequiredHeadersCheck.kt` missed=8
  - lines: 20-21, 23, 86-87, 103-104, 108
- `com/guardcore/core/checks/implementations/RateLimitCheck.kt` missed=6
  - lines: 127, 145, 231, 235, 299, 306
- `com/guardcore/core/checks/implementations/IpSecurityCheck.kt` missed=4
  - lines: 78, 232, 234, 314
- `com/guardcore/core/checks/implementations/CloudProviderCheck.kt` missed=3
  - lines: 79, 83, 92
- `com/guardcore/core/checks/implementations/SuspiciousActivityCheck.kt` missed=2
  - lines: 89, 131
- `com/guardcore/core/checks/ChecksFactory.kt` missed=2
  - lines: 32, 53
- `com/guardcore/core/checks/implementations/CustomRequestCheck.kt` missed=1
  - lines: 43
- `com/guardcore/core/checks/implementations/CustomValidatorsCheck.kt` missed=1
  - lines: 67
- `com/guardcore/core/checks/implementations/AuthenticationCheck.kt` missed=1
  - lines: 132
- `com/guardcore/core/checks/implementations/CloudIpRefreshCheck.kt` missed=1
  - lines: 50
- `com/guardcore/core/checks/Verifier.kt` missed=1
  - lines: 12

W9a-inflight: applyAction dispatch arms per action kind (ban/throttle/alert) [21 lines]

- `com/guardcore/core/behavioral/BehavioralProcessor.kt` missed=21
  - lines: 27, 71-79, 130-139, 207

W9a-inflight: otel/logfire metric-kind arms + enricher correlation tails + bus cloud-event arms [81 lines]

- `com/guardcore/core/events/SecurityEventBus.kt` missed=19
  - lines: 54, 132-133, 196-204, 224, 231, 233, 235, 237, 239, 241
- `com/guardcore/core/events/CompositeAgentHandler.kt` missed=18
  - lines: 15, 23, 27, 84, 90-91, 101-102, 127-128, 138-139, 150, 152-153, 168-170
- `com/guardcore/core/events/OtelHandler.kt` missed=17
  - lines: 55, 93, 119, 138-141, 143-146, 156-157, 179, 184, 187, 190
- `com/guardcore/core/events/EventEnricher.kt` missed=15
  - lines: 99-100, 109-110, 139-141, 143, 146, 149, 151-154, 164
- `com/guardcore/core/events/LogfireHandler.kt` missed=10
  - lines: 48, 51-52, 68, 110, 112, 114, 149, 152, 155
- `com/guardcore/core/events/MetricsCollector.kt` missed=1
  - lines: 39
- `com/guardcore/core/events/EventTypes.kt` missed=1
  - lines: 109

W9a-inflight: the xFuture variants of the handler-manager bridges [16 lines]

- `com/guardcore/java/JavaBridges.kt` missed=16
  - lines: 60, 63, 70, 73, 80, 84, 89, 93, 159-162, 166-169

W9a-inflight: trusted-proxy + excluded-path arms [14 lines]

- `com/guardcore/core/validation/RequestValidator.kt` missed=14
  - lines: 35, 68-69, 82-84, 86-87, 89-90, 92, 94-96

W9a-inflight: custom-response-modifier + CORS-header application arms [10 lines]

- `com/guardcore/core/responses/ErrorResponseFactory.kt` missed=10
  - lines: 44, 58, 115, 118, 131-132, 134, 137, 166-167

W9a-inflight: RuleType/RuleAction enum exhaustive arms + BehaviorRuleConfig hash collision branch [9 lines]

- `com/guardcore/config/RuleConfigs.kt` missed=9
  - lines: 46, 91-98

defensive: the unreachable strict-resolution arm (guard holds, W8a-pinned) [1 lines]

- `com/guardcore/core/bypass/BypassHandler.kt` missed=1
  - lines: 43

W9a-inflight: default method bodies of the agent protocol [2 lines]

- `com/guardcore/protocols/CloudIpStoreProtocol.kt` missed=1
  - lines: 12
- `com/guardcore/protocols/MiddlewareSurfaceProtocols.kt` missed=1
  - lines: 22

defensive: collision fallback arm (JVM object identity cannot collide, W4b study) [1 lines]

- `com/guardcore/core/routing/RouteConfigResolver.kt` missed=1
  - lines: 58

### W9b scope (engine module + conformance runner, not this wave)

- `com/guardcore/engine/detection/ValidationCache.kt` missed=169
  - lines: 14-16, 18-20, 23-25, 29-38, 40, 42-46, 48, 51-53, 57-65, 68-74, 77, 80, 86-88, 92-94, 98-113, 115, 117-123, 125, 127, 129, 132-140, 143-144, 146, 150-155, 157-158, 161-162, 165-166, 168, 173-174, 177-182, 184-193, 195-197, 200, 204-209, 211-217, 219-221, 224, 228-237, 239-241, 243, 245, 247-248, 251-252, 256-260, 262
- `com/guardcore/engine/suspatterns/SusPatternsPickle.kt` missed=141
  - lines: 16, 19, 40, 46-47, 51-54, 58-61, 75-77, 81-87, 101-102, 110-112, 115, 117-118, 121-122, 125-126, 129-130, 133-134, 137-138, 141-142, 145-146, 149-150, 153, 155-156, 158-159, 162-163, 166-167, 170-171, 174-176, 179-181, 184-187, 191-199, 202, 204, 206-208, 210-211, 214-217, 221-222, 224-226, 228-229, 232-233, 236-237, 240, 254-259, 261-262, 275, 279-284, 286-289, 291, 301-303, 316-320, 322-326, 339-343, 350-352
- `com/guardcore/engine/suspatterns/SusPatternsManager.kt` missed=101
  - lines: 54-62, 65, 82, 89, 147, 200, 205-206, 215, 240-248, 251, 256-257, 314, 320, 339-345, 347-352, 354, 357-359, 361, 438-440, 461, 505-509, 550-552, 554-555, 573-576, 675-677, 681-683, 691, 693-694, 696, 698, 814-816, 885-896, 943, 1017-1019, 1082, 1084, 1086, 1088
- `com/guardcore/engine/py/PyAst.kt` missed=93
  - lines: 23, 115, 161, 191-192, 199-200, 203-204, 206, 241-246, 248-249, 251, 253-255, 257, 264-265, 313-315, 318-320, 379-380, 382, 403-404, 408, 415, 420, 425-426, 438, 445, 450-453, 455-459, 474, 512, 516-517, 523-524, 528-529, 539, 561, 569-571, 576, 582-584, 599-602, 604-606, 619-623, 625, 627, 630-632, 634-635, 638-639, 645-646, 650
- `com/guardcore/engine/py/PyReParser.kt` missed=91
  - lines: 91-94, 197, 209, 247, 255-257, 265, 286, 309, 334, 336, 340-342, 344-346, 354-356, 359-361, 367, 370-371, 376-377, 379-382, 385-389, 391, 398, 418-420, 424, 427, 431, 443-445, 447, 450-453, 455, 503, 551, 564, 583-586, 593, 619-621, 646, 649, 652, 655, 658, 663, 682, 686, 697-701, 703-707, 709-710, 712, 714
- `com/guardcore/engine/py/PyRe.kt` missed=80
  - lines: 34, 38, 138-141, 143-145, 147, 149, 168-169, 178-179, 192-193, 216, 292-293, 296, 318, 332, 336, 338-340, 347-349, 351, 353, 357-358, 360-362, 365, 367-368, 370, 376, 389, 404, 414-415, 425-428, 436-437, 439-441, 452-453, 456-457, 460-461, 464-465, 468-469, 472-473, 476-477, 484-485, 524-528, 638, 646, 671, 681
- `com/guardcore/engine/suspatterns/SusPatternsXmlXxe.kt` missed=79
  - lines: 14, 84-89, 98-107, 116-124, 126, 135, 137-141, 143-146, 158-163, 171-182, 186-191, 197-213, 215
- `com/guardcore/engine/detection/RepeatPrefix.kt` missed=79
  - lines: 23-24, 32, 35, 45-49, 51, 53-54, 57-58, 61, 91-92, 99-100, 102, 111-112, 114-116, 170-174, 221-227, 230, 232-233, 235-238, 241, 245-249, 251, 259-263, 266, 281, 287, 294, 297-298, 300-304, 306-315, 317-318
- `com/guardcore/engine/detection/ParseSlots.kt` missed=66
  - lines: 33, 37, 45-48, 51, 86-91, 93-96, 98-101, 106, 109, 115-117, 146, 180, 196, 198, 200, 209-216, 244, 269, 272, 278-282, 284-286, 337-343, 347-348, 351, 371-376
- `com/guardcore/engine/detection/RepeatPrefixState.kt` missed=65
  - lines: 35, 46-48, 53, 66, 81-82, 123-127, 129, 131-143, 146-161, 165, 175-186, 190-198
- `com/guardcore/engine/detection/Monitor.kt` missed=61
  - lines: 32, 221-229, 231, 239-252, 255, 269-272, 282-290, 350-351, 370, 381, 384-385, 405-406, 416, 418-419, 432, 462-465, 470-471, 476, 479, 481-482
- `com/guardcore/engine/detection/AmbiguousTail.kt` missed=59
  - lines: 35-43, 47-64, 66, 68, 92, 113, 121-123, 216, 226-229, 231-233, 235-236, 240-249, 251-253, 255, 257
- `com/guardcore/engine/detection/RepeatLookbehind.kt` missed=52
  - lines: 11-14, 17-18, 20, 23-25, 32-33, 35-47, 53-55, 62-76, 81, 89-92, 103-105, 107
- `com/guardcore/conformance/PipelineHarness.kt` missed=49
  - lines: 138-139, 149-151, 154, 185, 189, 193, 195, 197, 226-227, 239-241, 245, 247, 260, 271, 278, 312, 314, 316, 320, 325, 327-328, 330-331, 391-392, 404, 411, 413, 443, 466, 469, 472, 477, 479, 481, 499, 502, 504, 507, 569-570, 576
- `com/guardcore/conformance/DetectRunner.kt` missed=48
  - lines: 127-130, 171-176, 178-183, 199, 203-204, 208-209, 214-217, 219, 225-226, 233-234, 238-239, 243-244, 248-249, 253-254, 260-261, 266-267, 275-276, 280-281, 285-286
- `com/guardcore/engine/suspatterns/SusPatternsMatchers.kt` missed=44
  - lines: 41-42, 52, 54-59, 62, 65-66, 68, 70, 75, 77-78, 80, 82, 95-103, 143, 151, 247-251, 253-254, 256, 259, 293, 309-311, 316
- `com/guardcore/engine/detection/Base64Decode.kt` missed=40
  - lines: 28, 38, 44, 97, 99, 101-113, 115, 117-122, 151, 153, 155-157, 168, 199, 201, 219, 237-242
- `com/guardcore/conformance/EventsHarness.kt` missed=29
  - lines: 224, 312, 329, 332-333, 335-336, 338, 362-366, 368, 370, 372, 375, 377, 379, 381-382, 384-385, 406, 607, 691, 695, 714, 821
- `com/guardcore/engine/detection/ReachProbe.kt` missed=28
  - lines: 30, 49-51, 95, 99, 102, 118-119, 122, 127, 130, 176, 200-201, 238-242, 244, 255-259, 261, 266
- `com/guardcore/engine/detection/EncodingDecoders.kt` missed=28
  - lines: 45-55, 57-59, 61, 66-72, 74-76, 78, 81, 102
- `com/guardcore/engine/detection/Truncation.kt` missed=26
  - lines: 32-33, 48, 65-66, 68-73, 76, 85-87, 89-91, 106-108, 139, 151-154
- `com/guardcore/engine/detection/ClassIntersection.kt` missed=25
  - lines: 16-19, 32, 34, 46, 72, 74, 76-79, 93-94, 141-142, 144-146, 148, 167, 171-172, 246
- `com/guardcore/engine/suspatterns/SusPatternsFileUploadTemplates.kt` missed=24
  - lines: 15, 67, 96, 142-145, 148, 152, 154, 156, 158, 214, 228, 249, 317, 331, 347, 350-351, 369, 401-403
- `com/guardcore/engine/detection/Compiler.kt` missed=24
  - lines: 35-36, 73-74, 78, 95-96, 103-106, 130-133, 148-151, 170-173, 202
- `com/guardcore/engine/detection/CostArbiter.kt` missed=23
  - lines: 52, 71, 102-103, 113-114, 179, 182, 204, 211, 272-273, 290, 296-297, 310-311, 326, 384-385, 388, 391, 409
- `com/guardcore/engine/detection/ProbeBatches.kt` missed=23
  - lines: 69-75, 77-78, 80, 89-93, 95-101, 103
- `com/guardcore/engine/detection/Preprocessor.kt` missed=17
  - lines: 24, 54, 118, 120, 145, 156, 177, 179, 198, 200, 202-205, 212, 320, 325
- `com/guardcore/engine/detection/PrefixHistory.kt` missed=17
  - lines: 16, 40-41, 69-71, 74-76, 78, 82-84, 86-89
- `com/guardcore/engine/py/PyUnicode.kt` missed=14
  - lines: 37-42, 44, 55, 57, 66, 87, 90, 109-110
- `com/guardcore/engine/detection/PrefixedProbe.kt` missed=14
  - lines: 34-39, 43-47, 50, 71-72
- `com/guardcore/conformance/CostBudgetRunner.kt` missed=12
  - lines: 57-58, 76, 81, 129, 147, 160, 178-180, 182, 184
- `com/guardcore/engine/suspatterns/SusPatternsThreat.kt` missed=12
  - lines: 26-28, 30-34, 70-71, 73-74
- `com/guardcore/engine/suspatterns/SusPatternsLdapIpv4.kt` missed=11
  - lines: 33, 47-48, 51-52, 59, 63-65, 111-112
- `com/guardcore/engine/detection/IgnorecaseFold.kt` missed=10
  - lines: 98, 139-140, 144-148, 150, 159
- `com/guardcore/engine/detection/ProbeFill.kt` missed=9
  - lines: 40, 60-61, 75, 78, 92, 105-107
- `com/guardcore/engine/detection/StrayChooser.kt` missed=9
  - lines: 15, 51, 167, 187, 202-203, 214-216
- `com/guardcore/conformance/PatternSafetyRunner.kt` missed=8
  - lines: 36, 112, 122, 125, 136, 141, 144, 155
- `com/guardcore/conformance/EventsComparison.kt` missed=7
  - lines: 33, 39-41, 44, 59, 74
- `com/guardcore/engine/detection/Semantic.kt` missed=7
  - lines: 44, 111, 257-258, 317, 326-327
- `com/guardcore/engine/detection/RepeatUnits.kt` missed=7
  - lines: 27, 30, 35-36, 51, 54-55
- `com/guardcore/engine/detection/ExactState.kt` missed=6
  - lines: 20, 31-35
- `com/guardcore/engine/detection/UnreachableTerminator.kt` missed=6
  - lines: 25, 61-64, 169
- `com/guardcore/engine/detection/StructureRules.kt` missed=5
  - lines: 26, 69-70, 106-107
- `com/guardcore/engine/detection/LiteralRuns.kt` missed=4
  - lines: 105-106, 121-122
- `com/guardcore/engine/detection/Binary.kt` missed=4
  - lines: 88-91
- `com/guardcore/engine/detection/StructurePrimitives.kt` missed=4
  - lines: 114, 131, 174-175
- `com/guardcore/engine/suspatterns/SusPatternsShell.kt` missed=3
  - lines: 367, 369, 377
- `com/guardcore/engine/suspatterns/SusPatternsSources.kt` missed=3
  - lines: 19, 80, 115
- `com/guardcore/engine/suspatterns/SusPatternsState.kt` missed=3
  - lines: 60, 93, 298
- `com/guardcore/engine/detection/RepeatAlphabet.kt` missed=3
  - lines: 16, 18, 47
- `com/guardcore/engine/py/RegexWorkers.kt` missed=1
  - lines: 32
- `com/guardcore/engine/detection/ScanWindow.kt` missed=1
  - lines: 61
- `com/guardcore/engine/detection/Base64.kt` missed=1
  - lines: 11
- `com/guardcore/engine/detection/IntervalSet.kt` missed=1
  - lines: 128
