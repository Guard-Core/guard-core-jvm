package com.guardcore.handlers

import com.guardcore.config.SecurityConfig
import com.guardcore.config.SecurityConfigBuilder
import java.nio.file.Files
import java.time.OffsetDateTime
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.launch

/** Shared fixture for the dynamic-rule ports (python `_rules`). */
public fun testRules(
    ruleId: String = "test-rule",
    version: Int = 1,
    overrides: List<Pair<String, Any?>> = emptyList(),
): DynamicRules {
  val overrideList = overrides
  var blockedCountries: List<String> = emptyList()
  var whitelistCountries: List<String> = emptyList()
  var globalRateLimit: Int? = null
  var globalRateWindow: Int? = null
  var endpointRateLimits: Map<String, Pair<Int, Int>> = linkedMapOf()
  var blockedCloudProviders: Set<String> = linkedSetOf()
  var blockedUserAgents: List<String> = emptyList()
  var suspiciousPatterns: List<String> = emptyList()
  var emergencyMode: Boolean = false
  var emergencyWhitelist: List<String> = emptyList()
  var ipBlacklist: List<String> = emptyList()
  var ipWhitelist: List<String> = emptyList()
  var autoBanThreshold: Int? = null
  var autoBanDuration: Int? = null
  var enableIpBanning: Boolean? = null
  var expiresAt: OffsetDateTime? = null
  for ((k, v) in overrideList) {
    when (k) {
      "blocked_countries" -> blockedCountries = v as List<String>
      "whitelist_countries" -> whitelistCountries = v as List<String>
      "global_rate_limit" -> globalRateLimit = v as Int?
      "global_rate_window" -> globalRateWindow = v as Int?
      "endpoint_rate_limits" -> endpointRateLimits = v as Map<String, Pair<Int, Int>>
      "blocked_cloud_providers" -> blockedCloudProviders = v as Set<String>
      "blocked_user_agents" -> blockedUserAgents = v as List<String>
      "suspicious_patterns" -> suspiciousPatterns = v as List<String>
      "emergency_mode" -> emergencyMode = v as Boolean
      "emergency_whitelist" -> emergencyWhitelist = v as List<String>
      "ip_blacklist" -> ipBlacklist = v as List<String>
      "ip_whitelist" -> ipWhitelist = v as List<String>
      "auto_ban_threshold" -> autoBanThreshold = v as Int?
      "auto_ban_duration" -> autoBanDuration = v as Int?
      "enable_ip_banning" -> enableIpBanning = v as Boolean?
      "expires_at" -> expiresAt = v as OffsetDateTime?
    }
  }
  return DynamicRules(
      ruleId = ruleId,
      version = version,
      timestamp = OffsetDateTime.now(),
      expiresAt = expiresAt,
      ipBlacklist = ipBlacklist,
      ipWhitelist = ipWhitelist,
      blockedCountries = blockedCountries,
      whitelistCountries = whitelistCountries,
      globalRateLimit = globalRateLimit,
      globalRateWindow = globalRateWindow,
      endpointRateLimits = endpointRateLimits,
      blockedCloudProviders = blockedCloudProviders,
      blockedUserAgents = blockedUserAgents,
      suspiciousPatterns = suspiciousPatterns,
      autoBanThreshold = autoBanThreshold,
      autoBanDuration = autoBanDuration,
      enableIpBanning = enableIpBanning,
      emergencyMode = emergencyMode,
      emergencyWhitelist = emergencyWhitelist,
  )
}

private fun dynamicConfig(): SecurityConfig =
    SecurityConfigBuilder()
        .apply {
          enableRedis = false
          redisUrl = null
          ipinfoToken = "test-token"
        }
        .build()

/**
 * The `patch.object(manager, "_apply_blocking_rules", ...)` idiom: a manager whose step functions
 * can be scripted to fail mid-apply (DynamicRuleManager steps are open members).
 */
private class ScriptedStepManager(
    config: SecurityConfig,
    private val failingStep: Int,
    private val extraFailure: (suspend (DynamicRuleManager) -> Unit)? = null,
) : DynamicRuleManager(config) {
  var step: Int = 0

  override suspend fun applyIpRules(rules: DynamicRules) {
    step = 1
    super.applyIpRules(rules)
  }

  override suspend fun applyBlockingRules(rules: DynamicRules) {
    step = 2
    if (failingStep == 2) throw RuntimeException("kaboom")
    super.applyBlockingRules(rules)
  }

  override suspend fun applyRateLimitRules(rules: DynamicRules) {
    step = 3
    if (failingStep == 3) {
      extraFailure?.invoke(this)
      throw RuntimeException("kaboom")
    }
    super.applyRateLimitRules(rules)
  }

  override suspend fun applyFeatureToggles(rules: DynamicRules) {
    step = 4
    if (failingStep == 4) throw RuntimeException("kaboom")
    super.applyFeatureToggles(rules)
  }
}

private fun scriptedManager(
    config: SecurityConfig,
    failingStep: Int,
    extraFailure: (suspend (DynamicRuleManager) -> Unit)? = null,
): ScriptedStepManager {
  DynamicRuleManager.resetInstance()
  return ScriptedStepManager(config, failingStep, extraFailure)
}

private fun dynamicManager(config: SecurityConfig = dynamicConfig()): DynamicRuleManager {
  DynamicRuleManager.resetInstance()
  return DynamicRuleManager.getInstance(config)
}

/**
 * Ports of tests/test_dynamic_rule_atomicity.py (11 tests). The python mock-patch of
 * `_apply_blocking_rules` maps to a real mid-apply failure: `global_rate_limit=0` passes the
 * DynamicRules bounds but the config revalidator rejects rate_limit=0, throwing after the blocking
 * rules applied - the same rollback path.
 */
class DynamicRuleAtomicityTest {
  init {
    DynamicRuleManager.resetInstance()
    IpBanManager.resetInstance()
  }

  @Test
  fun applyRulesRollsBackOnPartialFailure() = runTest {
    val config = dynamicConfig()
    config.blockedCountries = setOf("XX")
    val manager = scriptedManager(config, failingStep = 2)

    val rules = testRules(overrides = listOf("blocked_countries" to listOf("NEW")))
    assertFailsWithMessage<Exception> {
      manager.applyRules(rules)
    }

    assertEquals(setOf("XX"), config.blockedCountries)
  }

  @Test
  fun applyRulesPersistsOnSuccess() = runTest {
    val config = dynamicConfig()
    val manager = dynamicManager(config)

    manager.applyRules(testRules(overrides = listOf("blocked_countries" to listOf("NEW"))))

    assertEquals(setOf("NEW"), config.blockedCountries)
  }

  @Test
  fun concurrentRuleApplicationSerializes() = runTest {
    val config = dynamicConfig()
    val manager = dynamicManager(config)

    kotlinx.coroutines.coroutineScope {
      val jobs =
          listOf("AA", "BB").map { code ->
            launch {
              manager.applyRules(testRules(overrides = listOf("blocked_countries" to listOf(code))))
            }
          }
      jobs.forEach { it.join() }
    }

    val observed = config.blockedCountries
    assertEquals(1, observed.size)
    assertTrue(observed.first() == "AA" || observed.first() == "BB")
  }

  @Test
  fun rollbackRestoresAllSnapshotFields() = runTest {
    val config = dynamicConfig()
    config.blockedCountries = setOf("OLD_COUNTRY")
    config.rateLimit = 100
    config.enableIpBanning = true
    config.emergencyMode = false
    val manager =
        scriptedManager(config, failingStep = 3) { m ->
          // Partial application: the rate limit mutated before the failure.
          m.config.rateLimit = 999
        }
    val rules =
        testRules(
            overrides =
                listOf(
                    "blocked_countries" to listOf("NEW_COUNTRY"),
                    "global_rate_limit" to 500,
                    "emergency_mode" to true,
                ),
        )
    assertFailsWithMessage<Exception> {
      manager.applyRules(rules)
    }

    assertEquals(setOf("OLD_COUNTRY"), config.blockedCountries)
    assertEquals(100, config.rateLimit)
    assertEquals(true, config.enableIpBanning)
    assertEquals(false, config.emergencyMode)
  }

  @Test
  fun rollbackRestoresAutoBanOverrides() = runTest {
    val config = dynamicConfig()
    config.autoBanThreshold = 5
    config.autoBanDuration = 3600
    config.enableRateLimitAutoBan = false
    val manager = scriptedManager(config, failingStep = 2)
    val rules =
        testRules(
            overrides =
                listOf(
                    "auto_ban_threshold" to 1,
                    "auto_ban_duration" to 60,
                    "enable_ip_banning" to true,
                ),
        )
    assertFailsWithMessage<Exception> {
      manager.applyRules(rules)
    }

    assertEquals(5, config.autoBanThreshold)
    assertEquals(3600, config.autoBanDuration)
    assertEquals(false, config.enableRateLimitAutoBan)
  }

  @Test
  fun applyRulesCapturesBaseSnapshotOnFirstActivation() = runTest {
    val config = dynamicConfig()
    config.autoBanThreshold = 5
    val manager = dynamicManager(config)

    manager.applyRules(testRules(overrides = listOf("auto_ban_threshold" to 7)))

    assertNotNull(manager.activeBaseSnapshot)
    assertEquals(5, manager.activeBaseSnapshot!!["auto_ban_threshold"])
    assertEquals(7, config.autoBanThreshold)
  }

  @Test
  fun applyRulesRetainsBaseSnapshotAcrossSupersedingPush() = runTest {
    val config = dynamicConfig()
    config.autoBanThreshold = 5
    val manager = dynamicManager(config)

    manager.applyRules(testRules(version = 1, overrides = listOf("auto_ban_threshold" to 7)))
    val baseSnapshot = manager.activeBaseSnapshot

    manager.applyRules(testRules(version = 2, overrides = listOf("auto_ban_threshold" to 9)))

    assertTrue(baseSnapshot != null)
    assertEquals(5, baseSnapshot!!["auto_ban_threshold"])
    assertTrue(manager.activeBaseSnapshot === baseSnapshot)
    assertEquals(9, config.autoBanThreshold)
  }

  @Test
  fun checkRuleExpiryRevertsExpiredRuleAndClearsState() = runTest {
    val config = dynamicConfig()
    config.autoBanThreshold = 5
    val manager = dynamicManager(config)

    manager.applyRules(testRules(overrides = listOf("auto_ban_threshold" to 3)))
    assertEquals(3, config.autoBanThreshold)

    manager.currentRules =
        testRules(overrides = listOf("expires_at" to OffsetDateTime.now().minusMinutes(1)))
    manager.checkRuleExpiry()

    assertEquals(5, config.autoBanThreshold)
    assertNull(manager.currentRules)
    assertNull(manager.activeBaseSnapshot)
  }
}

/**
 * Ports of tests/test_dynamic_rule_persistence.py (the snapshot round-trip core set, including the
 * interop-pinned byte shape).
 */
class DynamicRulePersistenceTest {
  init {
    DynamicRuleManager.resetInstance()
  }

  @Test
  fun snapshotDumpMatchesPinnedFieldOrderAndShape() {
    val rules =
        DynamicRules(
            ruleId = "rio-rules",
            version = 3,
            timestamp = OffsetDateTime.parse("2026-01-01T00:00:00+00:00"),
        )
    val payload = dumpLastKnownRulesSnapshot(rules)
    val expected =
        "{\"schema_version\":1,\"rules\":{\"rule_id\":\"rio-rules\",\"version\":3," +
            "\"timestamp\":\"2026-01-01T00:00:00Z\",\"expires_at\":null,\"ttl\":300," +
            "\"ip_blacklist\":[],\"ip_whitelist\":[],\"ip_ban_duration\":3600," +
            "\"blocked_countries\":[],\"whitelist_countries\":[],\"global_rate_limit\":null," +
            "\"global_rate_window\":null,\"endpoint_rate_limits\":{}," +
            "\"blocked_cloud_providers\":[],\"blocked_user_agents\":[],\"suspicious_patterns\":[]," +
            "\"enable_penetration_detection\":null,\"enable_ip_banning\":null," +
            "\"enable_rate_limiting\":null,\"auto_ban_threshold\":null," +
            "\"auto_ban_duration\":null,\"enable_rate_limit_auto_ban\":null," +
            "\"emergency_mode\":false,\"emergency_whitelist\":[]}}"
    assertEquals(expected, payload)
  }

  @Test
  fun snapshotRoundTripPreservesAllFields() {
    val rules =
        DynamicRules(
            ruleId = "r1",
            version = 7,
            timestamp = OffsetDateTime.parse("2026-01-01T00:00:00Z"),
            expiresAt = OffsetDateTime.parse("2026-02-01T00:00:00Z"),
            ttl = 120,
            ipBlacklist = listOf("1.2.3.4"),
            ipWhitelist = listOf("5.6.7.8"),
            ipBanDuration = 600,
            blockedCountries = listOf("US"),
            whitelistCountries = listOf("CA"),
            globalRateLimit = 50,
            globalRateWindow = 30,
            endpointRateLimits = linkedMapOf("/api" to Pair(5, 60)),
            blockedCloudProviders = setOf("AWS"),
            blockedUserAgents = listOf("badbot"),
            suspiciousPatterns = listOf("pattern-[a-z]+"),
            enablePenetrationDetection = false,
            enableIpBanning = true,
            enableRateLimiting = false,
            autoBanThreshold = 3,
            autoBanDuration = 900,
            enableRateLimitAutoBan = true,
            emergencyMode = true,
            emergencyWhitelist = listOf("9.9.9.9"),
        )

    val payload = dumpLastKnownRulesSnapshot(rules)
    val loaded = loadLastKnownRulesSnapshot(payload)

    assertEquals("r1", loaded.ruleId)
    assertEquals(7, loaded.version)
    assertEquals(120, loaded.ttl)
    assertEquals(listOf("1.2.3.4"), loaded.ipBlacklist)
    assertEquals(listOf("5.6.7.8"), loaded.ipWhitelist)
    assertEquals(600, loaded.ipBanDuration)
    assertEquals(listOf("US"), loaded.blockedCountries)
    assertEquals(listOf("CA"), loaded.whitelistCountries)
    assertEquals(50, loaded.globalRateLimit)
    assertEquals(30, loaded.globalRateWindow)
    assertEquals(linkedMapOf("/api" to Pair(5, 60)), loaded.endpointRateLimits)
    assertEquals(setOf("AWS"), loaded.blockedCloudProviders)
    assertEquals(listOf("badbot"), loaded.blockedUserAgents)
    assertEquals(listOf("pattern-[a-z]+"), loaded.suspiciousPatterns)
    assertEquals(false, loaded.enablePenetrationDetection)
    assertEquals(true, loaded.enableIpBanning)
    assertEquals(false, loaded.enableRateLimiting)
    assertEquals(3, loaded.autoBanThreshold)
    assertEquals(900, loaded.autoBanDuration)
    assertEquals(true, loaded.enableRateLimitAutoBan)
    assertEquals(true, loaded.emergencyMode)
    assertEquals(listOf("9.9.9.9"), loaded.emergencyWhitelist)
  }

  @Test
  fun unsupportedSchemaVersionRejected() = runTest {
    val payload =
        """{"schema_version":99,"rules":{"rule_id":"r","version":1,""" +
            """"timestamp":"2026-01-01T00:00:00Z"}}"""
    assertFailsWithMessage<IllegalArgumentException>(
        "Unsupported last-known dynamic rules snapshot schema version: 99",
    ) {
      loadLastKnownRulesSnapshot(payload)
    }
  }

  @Test
  fun unknownFieldsRejected() = runTest {
    val payload =
        """{"schema_version":1,"rules":{"rule_id":"r","version":1,""" +
            """"timestamp":"2026-01-01T00:00:00Z","unknown_field":1}}"""
    assertFailsWithMessage<IllegalArgumentException> {
      loadLastKnownRulesSnapshot(payload)
    }
  }

  @Test
  fun requiredFieldsEnforced() = runTest {
    val payload = """{"schema_version":1,"rules":{"version":1}}"""
    assertFailsWithMessage<IllegalArgumentException> {
      loadLastKnownRulesSnapshot(payload)
    }
  }

  @Test
  fun persistWritesRedisAndFileAtomically() = runTest {
    val tmpDir = Files.createTempDirectory("dynrules")
    val cachePath = tmpDir.resolve("rules.json")
    val config = securityConfigRedis()
    val redis = RedisManager.getInstance(config)
    redis.initialize()
    try {
      val manager = dynamicManager(config)
      manager.initializeDynamicRuleRedis(redis)
      config.dynamicRulesCachePath = cachePath

      val rules = testRules(ruleId = "persist-1", version = 4)
      manager.persistLastKnownRules(rules)

      val redisPayload = redis.getKey(DYNAMIC_RULES_REDIS_NAMESPACE, LAST_KNOWN_RULES_KEY)
      assertNotNull(redisPayload)
      assertEquals("persist-1", loadLastKnownRulesSnapshot(redisPayload.toString()).ruleId)

      assertTrue(Files.exists(cachePath))
      assertFalse(Files.exists(tmpDir.resolve("rules.json.tmp")))
      val filePayload = Files.readString(cachePath)
      assertEquals(4, loadLastKnownRulesSnapshot(filePayload).version)
    } finally {
      redis.close()
    }
  }

  @Test
  fun hydrateRestoresLastKnownRules() = runTest {
    val config = securityConfigRedis()
    val redis = RedisManager.getInstance(config)
    redis.initialize()
    try {
      val rules = testRules(ruleId = "hydrate-1", version = 2)
      redis.setKey(
          DYNAMIC_RULES_REDIS_NAMESPACE,
          LAST_KNOWN_RULES_KEY,
          dumpLastKnownRulesSnapshot(rules),
      )

      val manager = dynamicManager(config)
      manager.initializeDynamicRuleRedis(redis)
      manager.hydrateLastKnownRules()

      assertNotNull(manager.currentRules)
      assertEquals("hydrate-1", manager.currentRules!!.ruleId)
    } finally {
      redis.close()
    }
  }

  @Test
  fun hydrateDiscardsExpiredRules() = runTest {
    val config = securityConfigRedis()
    val redis = RedisManager.getInstance(config)
    redis.initialize()
    try {
      val expired =
          testRules(
              ruleId = "old",
              version = 1,
              overrides = listOf("expires_at" to OffsetDateTime.now().minusMinutes(5)),
          )
      redis.setKey(
          DYNAMIC_RULES_REDIS_NAMESPACE,
          LAST_KNOWN_RULES_KEY,
          dumpLastKnownRulesSnapshot(expired),
      )

      val manager = dynamicManager(config)
      manager.initializeDynamicRuleRedis(redis)
      manager.hydrateLastKnownRules()

      assertNull(manager.currentRules)
    } finally {
      redis.close()
    }
  }

  @Test
  fun updateRulesAppliesFromAgentAndEmitsEvents() = runTest {
    val config = dynamicConfig()
    config.enableDynamicRules = true
    val manager = dynamicManager(config)
    val agent = RecordingDynamicAgent(testRules(ruleId = "agent-1", version = 5))
    manager.agentHandler = agent

    manager.updateRules()

    assertEquals("agent-1", manager.currentRules!!.ruleId)
    assertEquals(2, agent.events.size)
    assertEquals("dynamic_rule_updated", agent.events[0]["event_type"])
    assertEquals("rules_received", agent.events[0]["action_taken"])
    assertEquals("dynamic_rule_applied", agent.events[1]["event_type"])
    assertEquals("rules_updated", agent.events[1]["action_taken"])
  }

  @Test
  fun matchEventRoutesByIpCountryAndType() = runTest {
    val config = dynamicConfig()
    val manager = dynamicManager(config)
    manager.currentRules =
        testRules(
            overrides =
                listOf(
                    "ip_blacklist" to listOf("9.9.9.9"),
                    "blocked_countries" to listOf("RU"),
                    "blocked_cloud_providers" to setOf("AWS"),
                    "global_rate_limit" to 10,
                ),
        )

    assertEquals(
        "test-rule" to 1,
        manager.matchEvent(StaticEvent("9.9.9.9", null, null)),
    )
    assertEquals("test-rule" to 1, manager.matchEvent(StaticEvent(null, "RU", null)))
    assertEquals("test-rule" to 1, manager.matchEvent(StaticEvent(null, null, "rate_limited")))
    assertEquals("test-rule" to 1, manager.matchEvent(StaticEvent(null, null, "cloud_blocked")))
    assertNull(manager.matchEvent(StaticEvent("1.2.3.4", "US", "other")))
    manager.currentRules = null
    assertNull(manager.matchEvent(StaticEvent("9.9.9.9", null, null)))
  }

  private class StaticEvent(
      override val ipAddress: String?,
      override val country: String?,
      override val eventType: String?,
  ) : DynamicRuleEvent
}

/** Recording agent source for update_rules ports. */
private class RecordingDynamicAgent(
    private val rules: DynamicRules,
) : DynamicRuleManager.AgentDynamicRulesSource {
  val events: MutableList<Map<String, Any?>> = mutableListOf()

  override suspend fun getDynamicRules(): DynamicRules? = rules

  override suspend fun sendEvent(event: Map<String, Any?>) {
    events.add(event)
  }
}
