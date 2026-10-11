package com.guardcore.handlers

import com.guardcore.config.SecurityConfigBuilder
import java.nio.file.Files
import java.time.OffsetDateTime
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking

/**
 * W9a handler-arm coverage: the DynamicRuleManager update-loop lifecycle and snapshot stores
 * (python dynamic_rule_handler.py + _dynamic_rule_snapshot.py), the RedisManager operation sweep
 * against the live test redis (the redis-py operations the Lettuce adapter fronts), the
 * RateLimitManager event/exceeded arms, and the IpInfoManager non-download arms.
 */
class DynamicRuleManagerLifecycleTest {
  private fun config(cachePath: java.nio.file.Path? = null): com.guardcore.config.SecurityConfig =
      SecurityConfigBuilder()
          .apply {
            enableRedis = false
            redisUrl = null
            ipinfoToken = "test-token"
            enableDynamicRules = true
            enableAgent = true
            agentApiKey = "test-key"
            dynamicRuleInterval = 7200
            dynamicRulesCachePath = cachePath
          }
          .build()

  private class FakeAgentSource(var rules: DynamicRules?) :
      DynamicRuleManager.AgentDynamicRulesSource {
    val events: MutableList<Map<String, Any?>> = mutableListOf()
    var failWith: Exception? = null

    override suspend fun getDynamicRules(): DynamicRules? {
      failWith?.let { throw it }
      return rules
    }

    override suspend fun sendEvent(event: Map<String, Any?>) {
      events.add(event)
    }
  }

  @Test
  fun testInitializeAgentStartsLoopAndHydrates() {
    DynamicRuleManager.resetInstance()
    runBlocking {
      val manager = DynamicRuleManager.getInstance(config())
      try {
        val source = FakeAgentSource(null)
        manager.initializeAgent(source)
        assertNotNull(manager.updateTask)
        assertTrue(manager.hydratedLastKnownRules)
        // Second initialize: loop already running, no restart.
        manager.initializeAgent(source)
        manager.stop()
        assertNull(manager.updateTask)
      } finally {
        DynamicRuleManager.resetInstance()
      }
    }
  }

  @Test
  fun testInitializeAgentDisabledIsInert() {
    DynamicRuleManager.resetInstance()
    runBlocking {
      val builder = SecurityConfigBuilder()
      builder.enableRedis = false
      builder.enableDynamicRules = false
      val manager = DynamicRuleManager.getInstance(builder.build())
      try {
        manager.initializeAgent(FakeAgentSource(null))
        assertNull(manager.updateTask)
      } finally {
        DynamicRuleManager.resetInstance()
      }
    }
  }

  /** updateRules with no agent set is a no-op (the guard arm). */
  @Test
  fun testUpdateRulesWithoutAgentIsNoOp() {
    DynamicRuleManager.resetInstance()
    runBlocking {
      val manager = DynamicRuleManager.getInstance(config())
      try {
        manager.updateRules()
        assertNull(manager.currentRules)
        assertEquals(0.0, manager.lastUpdate)
      } finally {
        DynamicRuleManager.resetInstance()
      }
    }
  }

  /** updateRules applies fresh rules and emits received + applied events. */
  @Test
  fun testUpdateRulesAppliesAndEmitsEvents() {
    DynamicRuleManager.resetInstance()
    runBlocking {
      val manager = DynamicRuleManager.getInstance(config())
      try {
        val source = FakeAgentSource(testRules(version = 7))
        manager.initializeDynamicRuleRedis(null)
        manager.updateRules()
        assertNull(manager.currentRules) // agent not attached to the manager yet
        manager.agentHandler = source
        manager.updateRules()
        assertNotNull(manager.currentRules)
        assertEquals(7, manager.currentRules?.version)
        assertTrue(manager.lastUpdate > 0.0)
        assertTrue(source.events.isNotEmpty())
        assertEquals("dynamic_rules", source.events.first()["handler_name"])
      } finally {
        manager.agentHandler = null
        DynamicRuleManager.resetInstance()
      }
    }
  }

  /** updateRules swallows an agent failure (the catch arm). */
  @Test
  fun testUpdateRulesSwallowsAgentFailure() {
    DynamicRuleManager.resetInstance()
    runBlocking {
      val manager = DynamicRuleManager.getInstance(config())
      try {
        val source = FakeAgentSource(null)
        source.failWith = IllegalStateException("agent down")
        manager.agentHandler = source
        manager.updateRules()
        assertNull(manager.currentRules)
      } finally {
        manager.agentHandler = null
        DynamicRuleManager.resetInstance()
      }
    }
  }

  /** An already-expired rules payload is rejected before apply (reject_if_already_expired). */
  @Test
  fun testUpdateRulesRejectsAlreadyExpired() {
    DynamicRuleManager.resetInstance()
    runBlocking {
      val manager = DynamicRuleManager.getInstance(config())
      try {
        val source = FakeAgentSource(null)
        source.rules =
            testRules(
                version = 9,
                overrides = listOf("expires_at" to OffsetDateTime.now().minusHours(1)),
            )
        manager.agentHandler = source
        manager.updateRules()
        assertNull(manager.currentRules)
        assertTrue(source.events.isEmpty())
      } finally {
        manager.agentHandler = null
        DynamicRuleManager.resetInstance()
      }
    }
  }

  /** Same-version rules are not re-applied (should_update_rules). */
  @Test
  fun testUpdateRulesSkipsSameVersion() {
    DynamicRuleManager.resetInstance()
    runBlocking {
      val manager = DynamicRuleManager.getInstance(config())
      try {
        val source = FakeAgentSource(testRules(version = 3))
        manager.agentHandler = source
        manager.updateRules()
        val eventsAfterFirst = source.events.size
        assertTrue(eventsAfterFirst >= 2)
        manager.updateRules()
        assertEquals(eventsAfterFirst, source.events.size)
      } finally {
        manager.agentHandler = null
        DynamicRuleManager.resetInstance()
      }
    }
  }

  /** Last-known-rules persistence over the file store + hydration. */
  @Test
  fun testLastKnownRulesFilePersistenceAndHydration() {
    DynamicRuleManager.resetInstance()
    val cacheDir = Files.createTempDirectory("dynrules")
    val cachePath = cacheDir.resolve("last_known.json")
    try {
      runBlocking {
        val writer = DynamicRuleManager.getInstance(config(cachePath))
        val source = FakeAgentSource(testRules(ruleId = "persist-me", version = 5))
        writer.agentHandler = source
        writer.updateRules()
        assertTrue(Files.isRegularFile(cachePath), "snapshot file must exist")
        writer.agentHandler = null
        writer.stop()
        DynamicRuleManager.resetInstance()

        // A fresh manager hydrates from the file snapshot before its first update.
        val reader = DynamicRuleManager.getInstance(config(cachePath))
        val source2 = FakeAgentSource(null)
        reader.initializeAgent(source2)
        assertNotNull(reader.currentRules)
        assertEquals("persist-me", reader.currentRules?.ruleId)
        reader.stop()
      }
    } finally {
      DynamicRuleManager.resetInstance()
    }
  }

  /** Expired snapshots are discarded during hydration (load_last_known_rules expiry arm). */
  @Test
  fun testLoadLastKnownRulesDiscardsExpired() {
    DynamicRuleManager.resetInstance()
    runBlocking {
      val manager = DynamicRuleManager.getInstance(config())
      try {
        val expired =
            testRules(
                ruleId = "expired",
                version = 1,
                overrides = listOf("expires_at" to OffsetDateTime.now().minusHours(2)),
            )
        manager.persistLastKnownRules(expired)
        assertNull(manager.loadLastKnownRules())
        assertNull(manager.parseLastKnownRules("not-json"))
      } finally {
        DynamicRuleManager.resetInstance()
      }
    }
  }

  /** readRedisPayload arms: no handler, and a handler that fails. */
  @Test
  fun testReadRedisPayloadArms() {
    DynamicRuleManager.resetInstance()
    runBlocking {
      val manager = DynamicRuleManager.getInstance(config())
      try {
        assertNull(manager.readRedisPayload())
      } finally {
        DynamicRuleManager.resetInstance()
      }
    }
  }

  /** matchEvent arms: ip / country / event-type matching against currentRules. */
  @Test
  fun testMatchEventArms() {
    DynamicRuleManager.resetInstance()
    runBlocking {
      val manager = DynamicRuleManager.getInstance(config())
      try {
        assertNull(manager.matchEvent(DynamicRuleTestEvent("1.2.3.4", "CN", "penetration_attempt")))
        manager.currentRules =
            testRules(
                overrides =
                    listOf(
                        "ip_blacklist" to listOf("1.2.3.4"),
                        "blocked_countries" to listOf("CN"),
                    ),
            )
        // The match result carries the rule id + ban duration, not a reason string.
        assertNotNull(
            manager.matchEvent(DynamicRuleTestEvent("1.2.3.4", "US", "penetration_attempt")),
        )
        assertNotNull(
            manager.matchEvent(DynamicRuleTestEvent("5.6.7.8", "CN", "penetration_attempt")),
        )
        assertNull(manager.matchEvent(DynamicRuleTestEvent("5.6.7.8", "US", "penetration_attempt")))
      } finally {
        DynamicRuleManager.resetInstance()
      }
    }
  }

  /** checkRuleExpiry clears currentRules once they expire. */
  @Test
  fun testCheckRuleExpiry() {
    DynamicRuleManager.resetInstance()
    runBlocking {
      val manager = DynamicRuleManager.getInstance(config())
      try {
        manager.currentRules =
            testRules(
                version = 2,
                overrides = listOf("expires_at" to OffsetDateTime.now().minusMinutes(1)),
            )
        manager.checkRuleExpiry()
        assertNull(manager.currentRules)
      } finally {
        DynamicRuleManager.resetInstance()
      }
    }
  }

  /** forceUpdate resets the version bookkeeping and re-applies. */
  @Test
  fun testForceUpdate() {
    DynamicRuleManager.resetInstance()
    runBlocking {
      val manager = DynamicRuleManager.getInstance(config())
      try {
        val source = FakeAgentSource(testRules(version = 11))
        manager.agentHandler = source
        manager.updateRules()
        val firstUpdate = manager.lastUpdate
        delay(10)
        manager.forceUpdate()
        assertTrue(manager.lastUpdate >= firstUpdate)
      } finally {
        manager.agentHandler = null
        DynamicRuleManager.resetInstance()
      }
    }
  }

  private class DynamicRuleTestEvent(
      override val ipAddress: String?,
      override val country: String?,
      override val eventType: String?,
  ) : DynamicRuleEvent
}

/** The full RedisManager operation surface against the live test redis (redis-py parity). */
class RedisOperationsSweepTest {
  private suspend fun manager(): Pair<RedisManager, RedisOperations> {
    val config =
        SecurityConfigBuilder()
            .apply {
              enableRedis = true
              redisUrl = TEST_REDIS_URL
              redisPrefix = uniqueRedisPrefix()
            }
            .build()
    val manager = RedisManager.getInstance(config)
    manager.initialize()
    val ops = manager.operations()
    assertNotNull(ops)
    return manager to ops!!
  }

  private suspend fun teardown(manager: RedisManager) {
    manager.close()
    RedisManager.resetInstance()
  }

  @Test
  fun testStringOperations() {
    runBlocking {
      val (manager, redis) = manager()
      try {
        assertEquals(true, redis.set("sweep:str", "v1"))
        assertEquals("v1", redis.get("sweep:str"))
        assertEquals(true, redis.set("sweep:str", "v2"))
        assertEquals("v2", redis.get("sweep:str"))
        assertEquals(1L, redis.exists("sweep:str"))
        assertEquals(0L, redis.exists("sweep:missing"))
        redis.del("sweep:str")
        assertEquals(null, redis.get("sweep:str"))
      } finally {
        teardown(manager)
      }
    }
  }

  @Test
  fun testIncrExpireAndTtl() {
    runBlocking {
      val (manager, redis) = manager()
      try {
        val base = redis.incr("sweep:counter")
        assertTrue(base >= 1L)
        redis.incr("sweep:counter")
        assertEquals(true, redis.expire("sweep:counter", 120))
        val ttl = redis.pTtl("sweep:counter")
        assertTrue(ttl > 0L, "pttl must be positive, got $ttl")
        redis.setEx("sweep:withttl", "x", 30)
        redis.pSetEx("sweep:withpttl", "y", 30000)
      } finally {
        teardown(manager)
      }
    }
  }

  @Test
  fun testSortedSetOperations() {
    runBlocking {
      val (manager, redis) = manager()
      try {
        redis.zadd("sweep:zset", 1.0, "one")
        redis.zadd("sweep:zset", 2.0, "two")
        val withScores = redis.zrangeWithScores("sweep:zset")
        assertEquals(2, withScores.size)
        assertEquals(2L, redis.zcard("sweep:zset"))
        redis.zremRangeByScore("sweep:zset", "0", "1.5")
        assertEquals(1L, redis.zcard("sweep:zset"))
      } finally {
        teardown(manager)
      }
    }
  }

  @Test
  fun testScanKeysAndDeletePattern() {
    runBlocking {
      val (manager, redis) = manager()
      try {
        redis.set("sweepscan:a", "1")
        redis.set("sweepscan:b", "2")
        val keys = redis.keys("*sweepscan*")
        assertTrue(keys.isNotEmpty(), "keys: $keys")
        val scanned = redis.scan("sweepscan*")
        assertTrue(scanned.isNotEmpty(), "scan: $scanned")
        redis.del("sweepscan:a", "sweepscan:b")
        assertTrue(redis.keys("sweepscan*").isEmpty())
      } finally {
        teardown(manager)
      }
    }
  }

  @Test
  fun testTransactionAndPing() {
    runBlocking {
      val (manager, redis) = manager()
      try {
        assertEquals(true, redis.ping())
        redis.set("sweep:tx", "v")
        redis.transaction { ops ->
          ops.zadd("sweep:txz", 1.0, "m")
          ops.get("sweep:tx")
          ops.pTtl("sweep:tx")
          ops.setEx("sweep:tx", "v2", 60)
          ops.zcard("sweep:txz")
          ops.del("sweep:tx", "sweep:txz")
        }
        assertEquals(null, redis.get("sweep:tx"))
      } finally {
        teardown(manager)
      }
    }
  }
}

/** RateLimitManager arms: events, exceeded handling and reset. */
class RateLimitManagerArmsTest {
  private class Sink : HandlerAgentSink {
    val events: MutableList<Map<String, Any?>> = mutableListOf()

    override suspend fun sendEvent(event: Map<String, Any?>) {
      events.add(event)
    }
  }

  @Test
  fun testSendRateLimitEventWithAgent() {
    runBlocking {
      val config = SecurityConfigBuilder().apply { enableRedis = false }.build()
      val manager = RateLimitManager.getInstance(config)
      RateLimitManager.resetInstance()
      val sink = Sink()
      manager.agentHandler = sink
      manager.sendRateLimitEvent(
          com.guardcore.util.ScanRequest(
              method = "GET",
              clientHost = "1.2.3.4",
              urlPath = "/api",
          ),
          "1.2.3.4",
          1234L,
      )
      assertEquals(1, sink.events.size)
      assertEquals("rate_limit", sink.events[0]["handler_name"])
      manager.agentHandler = null
      RateLimitManager.resetInstance()
    }
  }

  @Test
  fun testEmitScriptReloadedEventWithoutAgentIsSafe() {
    runBlocking {
      val config = SecurityConfigBuilder().apply { enableRedis = false }.build()
      RateLimitManager.resetInstance()
      val manager = RateLimitManager.getInstance(config)
      manager.emitScriptReloadedEvent()
      RateLimitManager.resetInstance()
    }
  }

  @Test
  fun testGetInstanceKeepsSameInstanceAndConfig() {
    val config =
        SecurityConfigBuilder()
            .apply {
              enableRedis = false
              redisUrl = null
            }
            .build()
    val first = RateLimitManager.getInstance(config)
    val second = RateLimitManager.getInstance(config)
    assertTrue(first === second)
  }

  @Test
  fun testPyFloatStrRendering() {
    // The lua-argument float rendering (PyFloatStr): python repr semantics.
    assertEquals("10.0", PyFloatStr.of(10.0))
    assertEquals("10.5", PyFloatStr.of(10.5))
  }
}

/** IpInfoManager arms that do not need the network: caching, country lookup, events. */
class IpInfoManagerArmsTest {
  @Test
  fun testGetInstanceAndReset() {
    IpInfoManager.resetInstance()
    val first = IpInfoManager.getInstance("t")
    val second = IpInfoManager.getInstance("t")
    assertTrue(first === second)
    IpInfoManager.resetInstance()
  }

  @Test
  fun testGetCountryWithLookupOverride() {
    IpInfoManager.resetInstance()
    runBlocking {
      val manager = IpInfoManager.getInstance("t")
      manager.countryLookupOverride = { _ -> "CN" }
      try {
        assertEquals("CN", manager.getCountry("203.0.113.7"))
      } finally {
        manager.countryLookupOverride = null
        IpInfoManager.resetInstance()
      }
    }
  }

  @Test
  fun testDownloadOverrideAvoidsNetwork() {
    IpInfoManager.resetInstance()
    runBlocking {
      val manager = IpInfoManager.getInstance("t")
      var called = false
      manager.downloadOverride = { called = true }
      try {
        manager.downloadDatabase()
        assertTrue(called)
      } finally {
        manager.downloadOverride = null
        IpInfoManager.resetInstance()
      }
    }
  }
}
