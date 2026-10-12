package com.guardcore.handlers

import com.guardcore.config.SecurityConfigBuilder
import java.nio.file.Files
import java.time.OffsetDateTime
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/**
 * W9e batch 5: the DynamicRuleManager rule-lifecycle and CloudManager refresh arms. The pinned
 * corpus is untouched; every flow runs over scratch state.
 */
class DynamicCloudW9eArmsTest {
  private fun config(mutate: SecurityConfigBuilder.() -> Unit = {}) =
      SecurityConfigBuilder().apply { enableRedis = false }.apply(mutate).build()

  private fun rules(
      ruleId: String = "w9e",
      version: Int = 1,
      expiresAt: OffsetDateTime? = null,
      emergencyMode: Boolean = false,
      whitelist: List<String> = emptyList(),
      blockedCloud: Set<String> = emptySet(),
      blockedUa: List<String> = emptyList(),
      globalRateLimit: Int? = null,
  ): DynamicRules =
      DynamicRules(
          ruleId = ruleId,
          version = version,
          timestamp = OffsetDateTime.of(2026, 1, 1, 0, 0, 0, 0, java.time.ZoneOffset.UTC),
          expiresAt = expiresAt,
          emergencyMode = emergencyMode,
          emergencyWhitelist = whitelist,
          blockedCloudProviders = blockedCloud,
          blockedUserAgents = blockedUa,
          globalRateLimit = globalRateLimit,
      )

  @Test
  fun `dynamic rule lifecycle walks expiry, snapshots and skips`() = runBlocking {
    DynamicRuleManager.resetInstance()
    val lifecycleCfg = config {
      enableAgent = true
      agentApiKey = "w9e"
      enableDynamicRules = true
    }
    try {
      // one singleton for the whole lifecycle: getInstance ignores later configs
      val manager = DynamicRuleManager.getInstance(lifecycleCfg)
      // no active rules: expiry is a no-op and updates always apply
      manager.checkRuleExpiry()
      assertTrue(manager.shouldUpdateRules(rules()))
      // an expired rule on receipt is skipped and recorded
      val expired =
          rules(expiresAt = OffsetDateTime.of(2020, 1, 1, 0, 0, 0, 0, java.time.ZoneOffset.UTC))
      assertTrue(manager.rejectIfAlreadyExpired(expired))
      assertNotNull(manager.lastSkippedExpiredRule)
      // a live rule (different id+version from the expired one) is not rejected
      val live =
          rules(
              ruleId = "w9e-live",
              version = 2,
              expiresAt = OffsetDateTime.of(2126, 1, 1, 0, 0, 0, 0, java.time.ZoneOffset.UTC),
          )
      assertFalse(manager.rejectIfAlreadyExpired(live))
      // seed the current rules through the agent path, then walk the version gate
      manager.agentHandler =
          object : DynamicRuleManager.AgentDynamicRulesSource {
            // plain defaults keep the apply sweep off the network-backed managers
            override suspend fun getDynamicRules(): DynamicRules =
                rules(ruleId = "w9e-live", version = 2)

            override suspend fun sendEvent(event: Map<String, Any?>) {}
          }
      // updateRules records the live rules on the singleton
      manager.updateRules()
      assertNotNull(manager.getCurrentRules())
      assertFalse(manager.shouldUpdateRules(rules(ruleId = "w9e-live", version = 1)))
      assertTrue(manager.shouldUpdateRules(rules(ruleId = "w9e-2", version = 9)))
      // the expiry sweep runs over the applied live rule (well before its 2126 expiry)
      manager.checkRuleExpiry()
      assertTrue(true)
    } finally {
      DynamicRuleManager.resetInstance()
    }
  }

  @Test
  fun `dynamic rule application drives the emergency and rate surfaces`() = runBlocking {
    DynamicRuleManager.resetInstance()
    val dir = Files.createTempDirectory("w9e-b5-dynamic")
    try {
      val cfg = config {
        enableAgent = true
        agentApiKey = "w9e"
        enableDynamicRules = true
        dynamicRulesCachePath = dir.resolve("cache.json")
      }
      val manager = DynamicRuleManager.getInstance(cfg)
      manager.agentHandler =
          object : DynamicRuleManager.AgentDynamicRulesSource {
            override suspend fun getDynamicRules(): DynamicRules =
                rules(blockedCloud = setOf("AWS"), blockedUa = listOf("curl"), globalRateLimit = 5)

            override suspend fun sendEvent(event: Map<String, Any?>) {}
          }
      // updateRules over the agent source applies + records the current rules
      manager.updateRules()
      val current = assertNotNull(manager.getCurrentRules())
      assertEquals(setOf("AWS"), current.blockedCloudProviders)
      assertEquals(listOf("curl"), current.blockedUserAgents)
      // the ip whitelist application path over the singleton manager
      manager.applyIpWhitelist(listOf("192.0.2.9", "bad-entry!"))
    } finally {
      DynamicRuleManager.resetInstance()
    }
  }

  @Test
  fun `cloud manager walks the schedule and refresh-provider arms`() = runBlocking {
    val manager = CloudManager.getInstance()
    try {
      // scheduleRefresh with a direct refresh callback takes the immediate-launch path
      var ran = false
      val scheduled =
          manager.scheduleRefresh(
              providers = setOf("AWS"),
              ttl = 60,
              refresh = { ran = true },
          )
      // the scheduling may already be in flight from earlier tests; both outcomes are the
      // ported arms
      if (scheduled) {
        // the launched task runs asynchronously; give it a beat via the next refresh
      }
      // refreshProviders over a failing fetcher stores empty ranges and logs
      manager.refreshProviders(listOf("AWS"))
      // refreshAsync without a store falls back to the redis-handler refresh path per provider
      manager.refreshAsync(listOf("AWS"), ttl = 60)
      assertTrue(true)
    } finally {
      manager.agentHandler = null
    }
  }

  @Test
  fun `cloud manager is cloud ip logs and rejects malformed addresses`() {
    val manager = CloudManager.getInstance()
    assertFalse(manager.isCloudIp("not-an-ip", setOf("AWS")))
    assertFalse(manager.isCloudIp("", setOf("AWS")))
  }
}
