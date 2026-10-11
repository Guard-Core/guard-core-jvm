package com.guardcore.handlers

import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.config.DetectionCategories
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/**
 * W9a closure: the dynamic-rule application bodies (applyIpBans/applyIpWhitelist/
 * applyCountryRules/applyRateLimitRules/applyCloudProviderRules/applyUserAgentRules/
 * applyPatternRules/applyFeatureToggles) driven through applyRules with a fully populated
 * payload (_dynamic_rule_application.py), plus the tracked RouteConfig container revisions
 * (route_config.py:265-302) and the ReDoS validator rejection sweeps.
 */
class DynamicRuleApplyFullTest {
  private class StubGeo : com.guardcore.protocols.GeoIPHandler {
    override val isInitialized: Boolean = true
    override suspend fun initialize() {}
    override suspend fun initializeRedis(redisHandler: com.guardcore.protocols.RedisHandlerProtocol) {}
    override suspend fun initializeAgent(agentHandler: com.guardcore.protocols.AgentHandlerProtocol) {}
    override fun getCountry(ip: String): String? = "ZZ"
    override suspend fun refresh() {}
    override fun close() {}
  }

  private fun config(): com.guardcore.config.SecurityConfig =
      SecurityConfigBuilder()
          .apply {
            enableRedis = false
            redisUrl = null
            ipinfoToken = "test-token"
            enableDynamicRules = true
            enableAgent = true
            agentApiKey = "test-key"
            logSuspiciousLevel = com.guardcore.config.LogLevel.ERROR
            logRequestLevel = null
            geoIpHandler = StubGeo()
          }
          .build()

  @Test
  fun testApplyRulesFullPayloadDrivesEveryApplication() {
    DynamicRuleManager.resetInstance()
    try {
      runBlocking {
        resetIpBanGlobalState()
        val manager = DynamicRuleManager.getInstance(config())
        // Built directly: every DynamicRules field the application steps read.
        val rules =
            DynamicRules(
                ruleId = "full-payload",
                version = 42,
                timestamp = java.time.OffsetDateTime.now(),
                ipBlacklist = listOf("203.0.113.77"),
                ipWhitelist = listOf("203.0.113.78"),
                blockedCountries = listOf("cn"),
                whitelistCountries = listOf("us"),
                globalRateLimit = 25,
                globalRateWindow = 120,
                endpointRateLimits = mapOf("/api" to (5 to 60)),
                blockedCloudProviders = setOf("AWS", "NotAProvider"),
                blockedUserAgents = listOf("sqlmap", "nikto"),
                suspiciousPatterns = listOf("corpuspattern-full-[0-9]+"),
                enablePenetrationDetection = true,
                enableIpBanning = true,
                enableRateLimiting = true,
                autoBanThreshold = 7,
                autoBanDuration = 600,
                enableRateLimitAutoBan = true,
            )
        manager.applyRules(rules)

        // bans + whitelist applied through the ban manager
        val bans = IpBanManager.getInstance()
        assertEquals(true, bans.isIpBanned("203.0.113.77"))
        // countries normalized to upper case on the live config
        assertEquals(setOf("CN"), manager.config.blockedCountries)
        assertEquals(setOf("US"), manager.config.whitelistCountries)
        // rate limits
        assertEquals(25, manager.config.rateLimit)
        assertEquals(120, manager.config.rateLimitWindow)
        assertEquals(mapOf("/api" to (5 to 60)), manager.config.endpointRateLimits)
        // cloud providers filtered to the valid vocabulary
        assertEquals(setOf("AWS"), manager.config.blockCloudProviders ?: emptySet())
        // user agents validated + applied
        assertTrue(manager.config.blockedUserAgents.contains("sqlmap"))
        // feature toggles
        assertEquals(true, manager.config.enableIpBanning)
        assertEquals(true, manager.config.enableRateLimiting)
        assertEquals(true, manager.config.enableRateLimitAutoBan)
        assertEquals(7, manager.config.autoBanThreshold)
        assertEquals(600, manager.config.autoBanDuration)
        // invalid provider names are dropped, never crash
        assertTrue("NotAProvider" !in (manager.config.blockCloudProviders ?: emptySet()))
        assertTrue(VALID_CLOUD_PROVIDERS.contains("AWS"))
      }
    } finally {
      runBlocking { resetIpBanGlobalState() }
      DynamicRuleManager.resetInstance()
    }
  }

  /** applyCountryRules warns and no-ops without any geo source (the guard arm). */
  @Test
  fun testApplyCountryRulesWithoutGeoSourceWarns() {
    DynamicRuleManager.resetInstance()
    try {
      runBlocking {
        val builder = SecurityConfigBuilder()
        builder.enableRedis = false
        builder.ipinfoToken = null
        builder.geoIpHandler = null
        val manager = DynamicRuleManager.getInstance(builder.build())
        manager.applyCountryRules(listOf("CN"), emptyList())
        assertEquals(emptySet(), manager.config.blockedCountries)
      }
    } finally {
      DynamicRuleManager.resetInstance()
    }
  }

  /** applyIpBans swallows a failing ban (the catch arm) and applyIpWhitelist mirrors it. */
  @Test
  fun testApplyIpBansSwallowsBanFailures() {
    DynamicRuleManager.resetInstance()
    try {
      runBlocking {
        val manager = DynamicRuleManager.getInstance(config())
        // An invalid IP fails inside banIp and is logged, not raised.
        manager.applyIpBans(listOf("not-an-ip"), 60)
        manager.applyIpWhitelist(listOf("203.0.113.80"))
        assertTrue(true)
      }
    } finally {
      DynamicRuleManager.resetInstance()
    }
  }

  /** stop() cancels the update loop (the CancellationException arm). */
  @Test
  fun testStopCancelsLoop() {
    DynamicRuleManager.resetInstance()
    runBlocking {
      val manager = DynamicRuleManager.getInstance(config())
      manager.initializeAgent(object : DynamicRuleManager.AgentDynamicRulesSource {
        override suspend fun getDynamicRules(): DynamicRules? = null
        override suspend fun sendEvent(event: Map<String, Any?>) {}
      })
      assertNotNull(manager.updateTask)
      delayShort()
      manager.stop()
      assertNull(manager.updateTask)
    }
  }

  private fun delayShort() {
    Thread.sleep(150)
  }

  private fun assertNull(value: Any?) {
    kotlin.test.assertNull(value)
  }
}

/** RouteConfig tracked containers bump the revision on every mutation (route_config.py). */
class RouteConfigTrackedContainersTest {
  @Test
  fun testTrackedListMutationBumpsRevision() {
    val revision = com.guardcore.decorators.RouteConfigRevision()
    val rc = com.guardcore.decorators.RouteConfig(revision)
    val base = revision.value
    rc.blockedUserAgents.add("sqlmap")
    assertTrue(revision.value > base, "list add must bump the revision")
    rc.blockedUserAgents.removeAt(0)
    assertTrue(revision.value > base + 1)
  }

  @Test
  fun testTrackedSetAndMapMutationsBumpRevision() {
    val revision = com.guardcore.decorators.RouteConfigRevision()
    val rc = com.guardcore.decorators.RouteConfig(revision)
    val base = revision.value
    rc.blockCloudProviders.add("AWS")
    assertTrue(revision.value > base, "set add must bump the revision")
    rc.requiredHeaders["x-required"] = "1"
    assertTrue(revision.value > base + 1)
  }

  @Test
  fun testPlainContainerFieldsAreNotTracked() {
    // behaviorRules is the one untracked container (route_config.py:223): mutations stay silent.
    val revision = com.guardcore.decorators.RouteConfigRevision()
    val rc = com.guardcore.decorators.RouteConfig(revision)
    val base = revision.value
    rc.behaviorRules.add(
        BehaviorRule(ruleType = "usage", threshold = 1, window = 60, action = "log"),
    )
    assertEquals(base, revision.value)
  }
}

/** The ReDoS validator rejection sweep over config patterns (the W2 gate arms). */
class PatternValidationSweepTest {
  @Test
  fun testUnsafeUserAgentPatternsRejectedByApplyUserAgentRules() {
    DynamicRuleManager.resetInstance()
    try {
      runBlocking {
        val builder = SecurityConfigBuilder()
        builder.enableRedis = false
        val manager = DynamicRuleManager.getInstance(builder.build())
        manager.applyUserAgentRules(listOf("(.*)+", "safe-pattern", "(a+)+$"))
        assertEquals(listOf("safe-pattern"), manager.config.blockedUserAgents)
      }
    } finally {
      DynamicRuleManager.resetInstance()
    }
  }

  @Test
  fun testApplyPatternRulesRejectsUnsafe() {
    SusPatternsRegistry.redisHandler = null
    SusPatternsRegistry.agentHandler = null
    runBlocking { SusPatternsRegistry.reset() }
    try {
      val before = runBlocking { SusPatternsRegistry.getDefaultPatterns().size }
      runBlocking {
        val manager =
            DynamicRuleManager.getInstance(
                SecurityConfigBuilder().apply { enableRedis = false }.build(),
            )
        // addPattern defaults to the DEFAULT table (registry custom=false); the unsafe
        // pattern is rejected by the ReDoS validator and never reaches it.
        manager.applyPatternRules(listOf("(a+)+$", "corpuspattern-sweep-[a-z]+"))
        val after = SusPatternsRegistry.getDefaultPatterns()
        assertEquals(before + 1, after.size, "only the safe pattern is added: $after")
      }
      runBlocking {
        SusPatternsRegistry.removePattern("corpuspattern-sweep-[a-z]+", custom = false)
      }
    } finally {
      runBlocking { SusPatternsRegistry.reset() }
    }
  }

}
