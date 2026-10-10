package com.guardcore.handlers

import com.guardcore.config.SecurityConfig
import com.guardcore.config.SecurityConfigBuilder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.delay

/** Shared manager fixture for the ipban test classes (python `_manager_with_config`). */
public fun ipBanManagerWithConfig(): IpBanManager {
  val manager = IpBanManager.getInstance()
  manager.config = ipbanTestConfig()
  manager.redisHandler = null
  return manager
}

public fun ipbanTestConfig(): SecurityConfig =
    SecurityConfigBuilder()
        .apply {
          trustedProxies = listOf(TRUSTED_PROXY_EXACT, TRUSTED_PROXY_CIDR)
        }
        .build()

/** Ports of tests/test_ipban_lifecycle.py (16 tests). */
class IpBanLifecycleTest {
  init {
    IpBanManager.resetInstance()
  }

  private fun manager(): IpBanManager {
    val m = IpBanManager.getInstance()
    m.redisHandler = null
    return m
  }

  @Test
  fun initializeBanRedisAssignsHandler() = runTest {
    val m = manager()
    val redis = RecordingRedis()
    m.initializeBanRedis(redis)
    assertEquals(redis, m.redisHandler)
  }

  @Test
  fun initializeAgentAssignsHandler() = runTest {
    val m = manager()
    val agent = RecordingAgent()
    m.initializeBanAgent(agent)
    assertTrue(m.agentHandler === agent)
  }

  @Test
  fun banExactIpSendsEventWhenAgentHandlerPresent() = runTest {
    val m = manager()
    val agent = RecordingAgent()
    m.agentHandler = HandlerAgentSink.of(testAgentProtocol(agent))

    m.banIp("10.0.0.20", duration = 60, reason = "r")

    assertEquals(1, agent.events.size)
    assertEquals("10.0.0.20", agent.events[0]["ip_address"])
    assertEquals("banned", agent.events[0]["action_taken"])
  }

  @Test
  fun sendBanEventLogsErrorWhenAgentRaises() = runTest {
    val m = manager()
    val agent = RecordingAgent()
    agent.failWith = RuntimeException("boom")
    m.agentHandler = HandlerAgentSink.of(testAgentProtocol(agent))

    captureLogs("guard_core.handlers.ipban", java.util.logging.Level.SEVERE) { capture ->
      m.banIp("10.0.0.21", duration = 60, reason = "r")
      assertTrue(
          capture.messages(java.util.logging.Level.SEVERE).any {
            it.contains("Failed to send ban event")
          },
      )
    }
  }

  @Test
  fun unbanRemovesLocalEntryAndCallsRedisDelete() = runTest {
    val m = manager()
    val redis = RecordingRedis()
    m.redisHandler = redis

    m.bannedIps["10.0.0.30"] = nowSeconds() + 60
    val agent = RecordingAgent()
    m.agentHandler = HandlerAgentSink.of(testAgentProtocol(agent))

    m.unbanIp("10.0.0.30")

    assertFalse(m.bannedIps.containsKey("10.0.0.30"))
    assertEquals(listOf("banned_ips" to "10.0.0.30"), redis.deleteCalls)
    assertEquals(1, agent.events.size)
    assertEquals("unbanned", agent.events[0]["action_taken"])
  }

  @Test
  fun unbanWhenIpAbsentAndNoRedisNoAgentIsNoop() = runTest {
    val m = manager()
    m.redisHandler = null
    m.agentHandler = null

    m.unbanIp("10.0.0.31")

    assertFalse(m.bannedIps.containsKey("10.0.0.31"))
  }

  @Test
  fun sendUnbanEventLogsErrorWhenAgentRaises() = runTest {
    val m = manager()
    val agent = RecordingAgent()
    agent.failWith = RuntimeException("kaboom")
    m.agentHandler = HandlerAgentSink.of(testAgentProtocol(agent))

    captureLogs("guard_core.handlers.ipban", java.util.logging.Level.SEVERE) { capture ->
      m.unbanIp("10.0.0.32")
      assertTrue(
          capture.messages(java.util.logging.Level.SEVERE).any {
            it.contains("Failed to send unban event")
          },
      )
    }
  }

  @Test
  fun isIpBannedClearsExpiredLocalEntryAndReturnsFalse() = runTest {
    val m = manager()
    m.bannedIps["10.0.0.40"] = nowSeconds() - 1

    assertEquals(false, m.isIpBanned("10.0.0.40"))
    assertFalse(m.bannedIps.containsKey("10.0.0.40"))
  }

  @Test
  fun isIpBannedUsesRedisWhenLocalMiss() = runTest {
    val m = manager()
    val redis = RecordingRedis()
    redis.getKeyReturns[("banned_ips" to "10.0.0.41")] = PyTimeStr.of(nowSeconds() + 60)
    m.redisHandler = redis

    assertEquals(true, m.isIpBanned("10.0.0.41"))
    assertEquals(listOf("banned_ips" to "10.0.0.41"), redis.getKeyCalls)
  }

  @Test
  fun checkRedisExactReturnsFalseWhenNoEntry() = runTest {
    val m = manager()
    val redis = RecordingRedis()
    redis.getKeyReturns[("banned_ips" to "10.0.0.42")] = null
    m.redisHandler = redis

    assertEquals(false, m.isIpBanned("10.0.0.42"))
  }

  @Test
  fun checkRedisExactDeletesExpiredEntryAndReturnsFalse() = runTest {
    val m = manager()
    val redis = RecordingRedis()
    redis.getKeyReturns[("banned_ips" to "10.0.0.43")] = PyTimeStr.of(nowSeconds() - 10)
    m.redisHandler = redis

    assertEquals(false, m.isIpBanned("10.0.0.43"))
    assertEquals(listOf("banned_ips" to "10.0.0.43"), redis.deleteCalls)
  }

  @Test
  fun resetClearsLocalStateAndRedisKeys() = runTest {
    val m = manager()

    val redis = RecordingRedis(redisPrefix = "guard:")
    redis.keysReturn = listOf("guard:banned_ips:1", "guard:banned_ips:2")
    m.redisHandler = redis

    m.bannedIps["x"] = nowSeconds() + 60
    m.bannedNetworks.add(com.guardcore.util.py.IpNetwork.parse("10.0.0.0/24") to nowSeconds() + 60)

    m.reset()

    assertEquals(0, m.bannedIps.size)
    assertEquals(emptyList(), m.bannedNetworks)
  }

  @Test
  fun resetWithNoRedisAndNoKeysSkipsDelete() = runTest {
    val m = manager()

    val redis = RecordingRedis(redisPrefix = "guard:")
    redis.keysReturn = emptyList()
    m.redisHandler = redis

    m.reset()

    assertEquals(emptyList(), redis.deleteCalls)
  }

  @Test
  fun resetWithoutRedisJustClearsLocal() = runTest {
    val m = manager()
    m.redisHandler = null
    m.bannedIps["x"] = nowSeconds() + 60

    m.reset()

    assertEquals(0, m.bannedIps.size)
  }

  @Test
  fun resetGlobalStateClearsAPopulatedSingleton() = runTest {
    val m = IpBanManager.getInstance()
    m.bannedIps["203.0.113.250"] = nowSeconds() + 60
    m.bannedNetworks.add(com.guardcore.util.py.IpNetwork.parse("203.0.113.0/24") to 0.0)
    m.redisHandler = RecordingRedis()
    m.agentHandler = RecordingAgent()

    resetIpBanGlobalState()

    assertFalse(m.bannedIps.containsKey("203.0.113.250"))
    assertEquals(emptyList(), m.bannedNetworks)
    assertNull(m.redisHandler)
    assertNull(m.agentHandler)
  }
}

/** Ports of tests/test_ipban_ttl.py (7 tests). */
class IpBanTtlTest {
  init {
    IpBanManager.resetInstance()
  }

  @Test
  fun banShortDurationSucceedsWhenRedisUnavailable() = runTest {
    val manager = IpBanManager.getInstance()
    manager.redisHandler = null
    manager.bannedIps.clear()

    captureLogs("guard_core.handlers.ipban", java.util.logging.Level.WARNING) { capture ->
      manager.banIp("8.8.8.5", duration = 300, reason = "test")

      assertTrue(manager.bannedIps.containsKey("8.8.8.5"))
      val expiry = manager.bannedIps["8.8.8.5"]!!
      assertTrue(kotlin.math.abs(expiry - (nowSeconds() + 300)) < 2)
      assertEquals(emptyList(), capture.messages(java.util.logging.Level.WARNING))
    }
  }

  @Test
  fun banAtCapSucceedsWhenRedisUnavailable() = runTest {
    val manager = IpBanManager.getInstance()
    manager.redisHandler = null
    manager.bannedIps.clear()

    captureLogs("guard_core.handlers.ipban", java.util.logging.Level.WARNING) { capture ->
      manager.banIp(
          "8.8.8.6",
          duration = IpBanManager.LOCAL_CACHE_TTL_CAP_SECONDS,
          reason = "test",
      )

      assertTrue(manager.bannedIps.containsKey("8.8.8.6"))
      assertEquals(emptyList(), capture.messages(java.util.logging.Level.WARNING))
    }
  }

  @Test
  fun banLongerThanCapClampsAndWarnsWhenRedisUnavailable() = runTest {
    val manager = IpBanManager.getInstance()
    manager.redisHandler = null
    manager.bannedIps.clear()

    captureLogs("guard_core.handlers.ipban", java.util.logging.Level.WARNING) { capture ->
      manager.banIp(
          "8.8.8.7",
          duration = IpBanManager.LOCAL_CACHE_TTL_CAP_SECONDS + 1,
          reason = "test",
      )

      assertTrue(manager.bannedIps.containsKey("8.8.8.7"))
      val expiry = manager.bannedIps["8.8.8.7"]!!
      assertTrue(
          kotlin.math.abs(expiry - (nowSeconds() + IpBanManager.LOCAL_CACHE_TTL_CAP_SECONDS)) < 2,
      )
      assertEquals(true, manager.isIpBanned("8.8.8.7"))

      val warnings = capture.messages(java.util.logging.Level.WARNING)
      assertEquals(1, warnings.size)
      val message = warnings[0]
      assertTrue(message.contains("not configured"))
      assertTrue(message.contains("3601s to 3600s"))
    }
  }

  @Test
  fun banZeroOrNegativeDurationRaises() = runTest {
    val manager = IpBanManager.getInstance()
    manager.redisHandler = null

    assertFailsWithMessage<IllegalArgumentException> {
      manager.banIp("10.0.0.8", duration = 0, reason = "test")
    }
    assertFailsWithMessage<IllegalArgumentException> {
      manager.banIp("10.0.0.9", duration = -1, reason = "test")
    }
  }

  @Test
  fun banLongerThanCapSucceedsWhenRedisAvailable() = runTest {
    val manager = IpBanManager.getInstance()
    val redis = RecordingRedis()
    manager.redisHandler = redis
    manager.bannedIps.clear()

    val duration = IpBanManager.LOCAL_CACHE_TTL_CAP_SECONDS + 1
    manager.banIp("10.0.0.10", duration = duration, reason = "test")

    assertTrue(manager.bannedIps.containsKey("10.0.0.10"))
    assertEquals(1, redis.setKeyCalls.size)
    assertEquals(duration, redis.setKeyTtls[0])
  }

  @Test
  fun banExactIpLongerThanCapClampsAndWarnsWhenRedisSetKeyFails() = runTest {
    val manager = IpBanManager.getInstance()
    manager.redisHandler = FailingSetKeyRedis()
    manager.bannedIps.clear()

    captureLogs("guard_core.handlers.ipban", java.util.logging.Level.WARNING) { capture ->
      manager.banIp(
          "8.8.8.11",
          duration = IpBanManager.LOCAL_CACHE_TTL_CAP_SECONDS + 1,
          reason = "test",
      )

      assertTrue(manager.bannedIps.containsKey("8.8.8.11"))
      val expiry = manager.bannedIps["8.8.8.11"]!!
      assertTrue(
          kotlin.math.abs(expiry - (nowSeconds() + IpBanManager.LOCAL_CACHE_TTL_CAP_SECONDS)) < 2,
      )

      val warnings = capture.messages(java.util.logging.Level.WARNING)
      assertEquals(1, warnings.size)
      assertTrue(warnings[0].contains("request failed"))
      assertTrue(warnings[0].contains("to 3600s"))
    }
  }

  @Test
  fun banExactIpAtCapSucceedsWhenRedisSetKeyFails() = runTest {
    val manager = IpBanManager.getInstance()
    manager.redisHandler = FailingSetKeyRedis()
    manager.bannedIps.clear()

    captureLogs("guard_core.handlers.ipban", java.util.logging.Level.WARNING) { capture ->
      manager.banIp(
          "8.8.8.12",
          duration = IpBanManager.LOCAL_CACHE_TTL_CAP_SECONDS,
          reason = "test",
      )

      assertTrue(manager.bannedIps.containsKey("8.8.8.12"))
      val expiry = manager.bannedIps["8.8.8.12"]!!
      assertTrue(
          kotlin.math.abs(expiry - (nowSeconds() + IpBanManager.LOCAL_CACHE_TTL_CAP_SECONDS)) < 2,
      )
      assertEquals(emptyList(), capture.messages(java.util.logging.Level.WARNING))
    }
  }
}

/** Ports of tests/test_ipban_eviction.py (3 tests). */
class IpBanEvictionTest {
  init {
    IpBanManager.resetInstance()
  }

  @Test
  fun bannedIpsOverflowIncrementsEvictionCounterAndLogsAtThreshold() = runTest {
    val manager = IpBanManager.getInstance()
    manager.redisHandler = null
    manager.swapBannedIpsCache(maxsize = 2)

    captureLogs("guard_core.handlers.ipban", java.util.logging.Level.WARNING) { capture ->
      manager.banIp("8.8.0.1", duration = 300, reason = "t")
      manager.banIp("8.8.0.2", duration = 300, reason = "t")
      manager.banIp("8.8.0.3", duration = 300, reason = "t")

      assertEquals(1, manager.evictionsCount)
      assertEquals(emptyList(), capture.messages(java.util.logging.Level.WARNING))

      for (i in 4..102) {
        manager.banIp("8.8.${i / 256}.${i % 256}", duration = 300, reason = "t")
      }

      assertEquals(100, manager.evictionsCount)
      val warnings = capture.messages(java.util.logging.Level.WARNING)
      assertEquals(1, warnings.size)
      assertTrue(warnings[0].contains("100"))
      assertTrue(warnings[0].contains("silent overflow"))
    }
  }

  @Test
  fun ttlExpiryDoesNotIncrementEvictionCounter() = runTest {
    val manager = IpBanManager.getInstance()
    manager.redisHandler = null
    manager.bannedIps = TtlCache(maxsize = 10, ttlSeconds = 1.0, onEvict = { manager.onEviction() })

    manager.banIp("10.0.0.1", duration = 1, reason = "t")
    manager.banIp("10.0.0.2", duration = 1, reason = "t")

    delay(1100)

    manager.banIp("10.0.0.3", duration = 1, reason = "t")

    assertEquals(0, manager.evictionsCount)
  }

  @Test
  fun evictionCounterPersistsAcrossSingletonCalls() = runTest {
    val manager = IpBanManager.getInstance()
    manager.redisHandler = null
    manager.swapBannedIpsCache(maxsize = 1)

    manager.banIp("10.0.0.1", duration = 300, reason = "t")
    manager.banIp("10.0.0.2", duration = 300, reason = "t")
    assertEquals(1, manager.evictionsCount)

    val second = IpBanManager.getInstance()
    assertTrue(second === manager)
    assertEquals(1, second.evictionsCount)
  }
}

/** Ports of tests/test_ipban_cidr.py (13 tests). */
class IpBanCidrTest {
  init {
    IpBanManager.resetInstance()
  }

  @Test
  fun cidrBanMatchesAddressesInV4Range() = runTest {
    val manager = IpBanManager.getInstance()
    manager.redisHandler = null
    manager.bannedIps.clear()
    manager.bannedNetworks.clear()

    manager.banIp("10.0.0.0/24", duration = 300, reason = "cidr_test")

    assertEquals(true, manager.isIpBanned("10.0.0.5"))
    assertEquals(true, manager.isIpBanned("10.0.0.255"))
    assertEquals(false, manager.isIpBanned("10.0.1.1"))
  }

  @Test
  fun cidrBanMatchesAddressesInV6Range() = runTest {
    val manager = IpBanManager.getInstance()
    manager.redisHandler = null
    manager.bannedIps.clear()
    manager.bannedNetworks.clear()

    manager.banIp("2001:db8::/32", duration = 300, reason = "cidr_v6")

    assertEquals(true, manager.isIpBanned("2001:db8:1::1"))
    assertEquals(false, manager.isIpBanned("2001:db9::1"))
  }

  @Test
  fun exactIpBanStillWorksAlongsideCidr() = runTest {
    val manager = IpBanManager.getInstance()
    manager.redisHandler = null
    manager.bannedIps.clear()
    manager.bannedNetworks.clear()

    manager.banIp("192.168.1.50", duration = 300, reason = "exact")
    manager.banIp("172.16.0.0/16", duration = 300, reason = "cidr")

    assertEquals(true, manager.isIpBanned("192.168.1.50"))
    assertEquals(true, manager.isIpBanned("172.16.42.99"))
    assertEquals(false, manager.isIpBanned("192.168.1.51"))
  }

  @Test
  fun invalidCidrRaises() = runTest {
    val manager = IpBanManager.getInstance()
    manager.redisHandler = null

    assertFailsWithMessage<IllegalArgumentException>("Invalid CIDR network") {
      manager.banIp("bad/24", duration = 300, reason = "bad")
    }
  }

  @Test
  fun invalidIpAddressInIsIpBannedReturnsFalse() = runTest {
    val manager = IpBanManager.getInstance()
    manager.redisHandler = null
    manager.bannedIps.clear()
    manager.bannedNetworks.clear()

    assertEquals(false, manager.isIpBanned("not-an-ip"))
  }

  @Test
  fun cidrBanExpiryPrunedAtCheckTime() = runTest {
    val manager = IpBanManager.getInstance()
    manager.redisHandler = null
    manager.bannedIps.clear()
    manager.bannedNetworks.clear()

    manager.banIp("10.0.0.0/24", duration = 1, reason = "short")
    assertEquals(true, manager.isIpBanned("10.0.0.5"))

    delay(1100)
    assertEquals(false, manager.isIpBanned("10.0.0.5"))
  }

  @Test
  fun cidrBanRedisPathStoresNetwork() = runTest {
    val manager = IpBanManager.getInstance()
    val redis = RecordingRedis()
    manager.redisHandler = redis
    manager.bannedIps.clear()
    manager.bannedNetworks.clear()

    manager.banIp("10.0.0.0/24", duration = 300, reason = "cidr_redis")

    assertEquals(1, redis.setKeyCalls.size)
    val (namespace, key) = redis.setKeyCalls[0].first to redis.setKeyCalls[0].second
    assertEquals("banned_networks", namespace)
    assertTrue(key.contains("10.0.0.0/24"))
  }

  @Test
  fun cidrBanRedisFailureFallsBackToLocal() = runTest {
    val manager = IpBanManager.getInstance()
    manager.redisHandler = FailingSetKeyRedis()
    manager.bannedIps.clear()
    manager.bannedNetworks.clear()

    manager.banIp("10.0.0.0/24", duration = 300, reason = "cidr_fallback")

    assertEquals(1, manager.bannedNetworks.size)
  }

  @Test
  fun cidrBanRedisFailureExceedsCapClampsAndWarns() = runTest {
    val manager = IpBanManager.getInstance()
    manager.redisHandler = FailingSetKeyRedis()
    manager.bannedIps.clear()
    manager.bannedNetworks.clear()

    captureLogs("guard_core.handlers.ipban", java.util.logging.Level.WARNING) { capture ->
      manager.banIp(
          "8.8.8.0/24",
          duration = IpBanManager.LOCAL_CACHE_TTL_CAP_SECONDS + 1,
          reason = "cidr_fallback_cap",
      )

      assertEquals(1, manager.bannedNetworks.size)
      val (network, expiry) = manager.bannedNetworks[0]
      assertEquals("8.8.8.0/24", network.text)
      assertTrue(
          kotlin.math.abs(expiry - (nowSeconds() + IpBanManager.LOCAL_CACHE_TTL_CAP_SECONDS)) < 2,
      )
      assertEquals(true, manager.isIpBanned("8.8.8.5"))

      val warnings = capture.messages(java.util.logging.Level.WARNING)
      assertEquals(1, warnings.size)
      assertTrue(warnings[0].contains("request failed"))
      assertTrue(warnings[0].contains("3601s to 3600s"))
    }
  }

  @Test
  fun invalidExactIpRaises() = runTest {
    val manager = IpBanManager.getInstance()
    manager.redisHandler = null

    assertFailsWithMessage<IllegalArgumentException>("Invalid IP address") {
      manager.banIp("not-an-ip-no-slash", duration = 300, reason = "bad_ip")
    }
  }

  @Test
  fun v4AddressNotInV6Network() = runTest {
    val manager = IpBanManager.getInstance()
    manager.redisHandler = null
    manager.bannedIps.clear()
    manager.bannedNetworks.clear()

    manager.banIp("2001:db8::/32", duration = 300, reason = "v6_only")

    assertEquals(false, manager.isIpBanned("10.0.0.1"))
  }

  @Test
  fun cidrBanNoRedisExceedsCapClampsAndWarns() = runTest {
    val manager = IpBanManager.getInstance()
    manager.redisHandler = null
    manager.bannedIps.clear()
    manager.bannedNetworks.clear()

    captureLogs("guard_core.handlers.ipban", java.util.logging.Level.WARNING) { capture ->
      manager.banIp(
          "8.8.8.0/24",
          duration = IpBanManager.LOCAL_CACHE_TTL_CAP_SECONDS + 1,
          reason = "cap_exceeded",
      )

      assertEquals(1, manager.bannedNetworks.size)
      val (network, expiry) = manager.bannedNetworks[0]
      assertEquals("8.8.8.0/24", network.text)
      assertTrue(
          kotlin.math.abs(expiry - (nowSeconds() + IpBanManager.LOCAL_CACHE_TTL_CAP_SECONDS)) < 2,
      )
      assertEquals(true, manager.isIpBanned("8.8.8.5"))

      val warnings = capture.messages(java.util.logging.Level.WARNING)
      assertEquals(1, warnings.size)
      assertTrue(warnings[0].contains("not configured"))
      assertTrue(warnings[0].contains("3601s to 3600s"))
    }
  }

  @Test
  fun cidrBanNoRedisAtCapNoWarning() = runTest {
    val manager = IpBanManager.getInstance()
    manager.redisHandler = null
    manager.bannedIps.clear()
    manager.bannedNetworks.clear()

    manager.banIp(
        "10.0.0.0/24",
        duration = IpBanManager.LOCAL_CACHE_TTL_CAP_SECONDS,
        reason = "at_cap",
    )

    assertEquals(1, manager.bannedNetworks.size)
    val (_, expiry) = manager.bannedNetworks[0]
    assertTrue(
        kotlin.math.abs(expiry - (nowSeconds() + IpBanManager.LOCAL_CACHE_TTL_CAP_SECONDS)) < 2,
    )
  }
}

/** python assertRaises-with-message helper. */
public suspend inline fun <reified T : Exception> assertFailsWithMessage(
    messagePart: String? = null,
    block: () -> Unit,
) {
  try {
    block()
  } catch (e: T) {
    if (messagePart != null) {
      assertTrue(
          e.message!!.contains(messagePart),
          "expected message to contain '$messagePart', got '${e.message}'",
      )
    }
    return
  }
  throw AssertionError("expected ${T::class.simpleName} to be thrown")
}

/** Adapter wrapping a RecordingAgent as the production AgentHandlerProtocol sink. */
public fun testAgentProtocol(agent: RecordingAgent): com.guardcore.protocols.AgentHandlerProtocol =
    object : com.guardcore.protocols.AgentHandlerProtocol {
      override suspend fun initializeRedis(
          redisHandler: com.guardcore.protocols.RedisHandlerProtocol,
      ) {}

      override suspend fun sendEvent(event: Any?) {
        @Suppress("UNCHECKED_CAST") agent.sendEvent(event as Map<String, Any?>)
      }

      override suspend fun sendMetric(metric: Any?) {}

      override suspend fun start() {}

      override suspend fun stop() {}

      override suspend fun flushBuffer() {}

      override suspend fun getDynamicRules(): Any? = null

      override suspend fun healthCheck(): Boolean = true
    }
