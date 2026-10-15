package com.guardcore.handlers

import com.guardcore.config.SecurityConfig
import com.guardcore.config.SecurityConfigBuilder
import java.nio.file.Files
import java.time.OffsetDateTime
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The `patch.object(manager, "_apply_feature_toggles", ...)` idiom: a scripted mid-apply failure.
 */
private class FailingManager(config: SecurityConfig) : DynamicRuleManager(config) {
  var failFeatureToggles: Boolean = false

  override suspend fun applyFeatureToggles(rules: DynamicRules) {
    if (failFeatureToggles) throw RuntimeException("boom")
    super.applyFeatureToggles(rules)
  }
}

/**
 * Ports of tests/test_dynamic_rule_overlay.py (guard-core #169): every rule version is applied over
 * the base config, never over the previous version's result.
 */
class DynamicRuleOverlayTest {
  init {
    DynamicRuleManager.resetInstance()
    IpBanManager.resetInstance()
  }

  @AfterTest
  fun tearDown() {
    DynamicRuleManager.resetInstance()
  }

  private fun config(): SecurityConfig =
      SecurityConfigBuilder()
          .apply {
            enableRedis = false
            redisUrl = null
            ipinfoToken = "test-token"
          }
          .build()

  private fun manager(config: SecurityConfig): DynamicRuleManager {
    DynamicRuleManager.resetInstance()
    return DynamicRuleManager.getInstance(config)
  }

  private suspend fun apply(manager: DynamicRuleManager, rules: DynamicRules) {
    manager.applyRules(rules)
    manager.currentRules = rules
  }

  @Test
  fun emergencyHalvingDoesNotCompoundAcrossVersions() = runTest {
    val config = config()
    config.autoBanThreshold = 16
    val manager = manager(config)

    val seen = mutableListOf<Int>()
    for (version in 1..3) {
      apply(
          manager,
          testRules(
              version = version,
              ruleId = "r1",
              overrides =
                  listOf("emergency_mode" to true, "emergency_whitelist" to emptyList<String>()),
          ),
      )
      seen.add(config.autoBanThreshold)
    }

    assertEquals(listOf(8, 8, 8), seen)
    assertNotNull(manager.activeBaseSnapshot)
    assertEquals(16, manager.activeBaseSnapshot!!["auto_ban_threshold"])
  }

  @Test
  fun collectionValuesDoNotAccumulateAcrossVersions() = runTest {
    val config = config()
    config.blockedUserAgents = listOf("base-bot")
    config.blockCloudProviders = setOf("AWS")
    val manager = manager(config)

    apply(
        manager,
        testRules(
            version = 1,
            ruleId = "r1",
            overrides =
                listOf(
                    "blocked_user_agents" to listOf("bot-a"),
                    "blocked_cloud_providers" to setOf("GCP"),
                    "blocked_countries" to listOf("AA"),
                    "endpoint_rate_limits" to mapOf("/a" to (1 to 60)),
                ),
        ),
    )
    apply(
        manager,
        testRules(
            version = 2,
            ruleId = "r1",
            overrides =
                listOf(
                    "blocked_user_agents" to listOf("bot-b"),
                    "blocked_cloud_providers" to setOf("Azure"),
                    "blocked_countries" to listOf("BB"),
                    "endpoint_rate_limits" to mapOf("/b" to (2 to 60)),
                ),
        ),
    )

    assertEquals(listOf("bot-b"), config.blockedUserAgents)
    assertEquals(setOf("Azure"), config.blockCloudProviders)
    assertEquals(setOf("BB"), config.blockedCountries)
    assertEquals(mapOf("/b" to (2 to 60)), config.endpointRateLimits)
  }

  @Test
  fun newVersionDropsChangeFromPreviousVersion() = runTest {
    val config = config()
    config.rateLimit = 100
    config.enableIpBanning = true
    config.autoBanThreshold = 5
    val manager = manager(config)

    apply(
        manager,
        testRules(
            version = 1,
            ruleId = "r1",
            overrides =
                listOf(
                    "global_rate_limit" to 7,
                    "enable_ip_banning" to false,
                    "auto_ban_threshold" to 2,
                ),
        ),
    )
    assertEquals(7, config.rateLimit)
    assertEquals(false, config.enableIpBanning)

    apply(
        manager,
        testRules(version = 2, ruleId = "r1", overrides = listOf("global_rate_limit" to 9)),
    )

    assertEquals(9, config.rateLimit)
    assertEquals(true, config.enableIpBanning)
    assertEquals(5, config.autoBanThreshold)
  }

  @Test
  fun differentRuleIdOverlaysTheBase() = runTest {
    val config = config()
    config.rateLimit = 100
    config.autoBanThreshold = 16
    val manager = manager(config)

    apply(
        manager,
        testRules(
            ruleId = "r1",
            overrides =
                listOf("emergency_mode" to true, "emergency_whitelist" to emptyList<String>()),
        ),
    )
    apply(manager, testRules(ruleId = "r2", overrides = listOf("global_rate_limit" to 3)))

    assertEquals(3, config.rateLimit)
    assertEquals(16, config.autoBanThreshold)
    assertEquals(false, config.emergencyMode)
  }

  @Test
  fun failedApplyRollsBackToTheActiveVersion() = runTest {
    val config = config()
    config.rateLimit = 100
    config.autoBanThreshold = 16
    DynamicRuleManager.resetInstance()
    val manager = FailingManager(config)
    apply(
        manager,
        testRules(
            ruleId = "r1",
            overrides = listOf("global_rate_limit" to 7, "auto_ban_threshold" to 4),
        ),
    )

    manager.failFeatureToggles = true
    assertFailsWithMessage<Exception>("boom") {
      manager.applyRules(
          testRules(version = 2, ruleId = "r1", overrides = listOf("global_rate_limit" to 9)),
      )
    }

    assertEquals(7, config.rateLimit)
    assertEquals(4, config.autoBanThreshold)
    assertNotNull(manager.activeBaseSnapshot)
    assertEquals(100, manager.activeBaseSnapshot!!["rate_limit"])
  }

  @Test
  fun expiryRestoresTheTrueBaseAfterSeveralVersions() = runTest {
    val config = config()
    config.autoBanThreshold = 16
    val manager = manager(config)
    val emergency = listOf("emergency_mode" to true, "emergency_whitelist" to emptyList<String>())
    apply(manager, testRules(version = 1, ruleId = "r1", overrides = emergency))
    apply(
        manager,
        testRules(
            version = 2,
            ruleId = "r1",
            overrides = emergency + ("expires_at" to OffsetDateTime.now().minusSeconds(1)),
        ),
    )
    assertEquals(8, config.autoBanThreshold)

    manager.checkRuleExpiry()

    assertEquals(16, config.autoBanThreshold)
    assertEquals(false, config.emergencyMode)
    assertNull(manager.currentRules)
    assertNull(manager.activeBaseSnapshot)
  }

  @Test
  fun newVersionAfterHydrationOverlaysTheBase() = runTest {
    val config = config()
    config.enableDynamicRules = true
    config.autoBanThreshold = 16
    val cache = Files.createTempFile("dynrules-overlay", ".json")
    try {
      val emergency = listOf("emergency_mode" to true, "emergency_whitelist" to emptyList<String>())
      Files.writeString(
          cache,
          dumpLastKnownRulesSnapshot(testRules(version = 1, ruleId = "r1", overrides = emergency)),
      )
      config.dynamicRulesCachePath = cache
      val manager = manager(config)
      manager.hydrateLastKnownRules()
      assertEquals(8, config.autoBanThreshold)
      manager.agentHandler =
          object : DynamicRuleManager.AgentDynamicRulesSource {
            override suspend fun getDynamicRules(): DynamicRules? =
                testRules(version = 2, ruleId = "r1", overrides = emergency)

            override suspend fun sendEvent(event: Map<String, Any?>) {}
          }

      manager.updateRules()

      assertEquals(2, manager.currentRules!!.version)
      assertEquals(8, config.autoBanThreshold)
      assertEquals(16, manager.activeBaseSnapshot!!["auto_ban_threshold"])
    } finally {
      Files.deleteIfExists(cache)
    }
  }

  @Test
  fun suspiciousPatternsAreNotDuplicatedAcrossVersions() = runTest {
    val manager = manager(config())
    val pattern = "overlay-unique-marker-[0-9]{3}"
    SusPatternsRegistry.removePattern(pattern)
    try {
      for (version in 1..3) {
        apply(
            manager,
            testRules(
                version = version,
                ruleId = "r1",
                overrides = listOf("suspicious_patterns" to listOf(pattern)),
            ),
        )
      }

      assertEquals(1, SusPatternsRegistry.getDefaultPatterns().count { it == pattern })
    } finally {
      SusPatternsRegistry.removePattern(pattern)
      assertTrue(pattern !in SusPatternsRegistry.getDefaultPatterns())
    }
  }
}
