package com.guardcore.handlers

import com.guardcore.util.py.IpNetwork
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Ports of the handler-scope tests in tests/test_handler_edge_cases.py (the check/pipeline halves
 * belong to W4).
 */
class HandlerEdgeCasesTest {
  init {
    IpBanManager.resetInstance()
    RateLimitManager.resetInstance()
    CloudManager.resetInstance()
  }

  @Test
  fun ipbanInMemoryExpired() = runTest {
    val manager = IpBanManager.getInstance()
    manager.redisHandler = null
    manager.bannedIps["10.0.0.1"] = nowSeconds() - 1
    assertEquals(false, manager.isIpBanned("10.0.0.1"))
  }

  @Test
  fun ipbanInMemoryValid() = runTest {
    val manager = IpBanManager.getInstance()
    manager.redisHandler = null
    manager.bannedIps["10.0.0.2"] = nowSeconds() + 60
    assertEquals(true, manager.isIpBanned("10.0.0.2"))
  }

  @Test
  fun ipbanResetGlobalState() = runTest {
    val manager = IpBanManager.getInstance()
    manager.bannedIps["10.0.0.3"] = nowSeconds() + 60
    resetIpBanGlobalState()
    assertFalse(manager.bannedIps.containsKey("10.0.0.3"))
  }

  @Test
  fun ratelimitPopleftStaleTimestamps() {
    val mgr = RateLimitManager.getInstance(rateLimitConfigForEdge())
    val oldTime = nowSeconds() - 120
    val current = nowSeconds()
    mgr.requestTimestamps["1.2.3.4"] = java.util.ArrayDeque(listOf(oldTime, oldTime + 1))
    val count = mgr.getInMemoryRequestCount("1.2.3.4", current - 60, current)
    assertEquals(0L, count)
  }

  @Test
  fun cloudHandlerGetDetailsMatch() = runTest {
    val manager = CloudManager.getInstance()
    manager.ipRanges["AWS"] = setOf(IpNetwork.parse("13.248.0.0/20"))
    val details = manager.getCloudProviderDetails("13.248.1.1")
    assertEquals("AWS" to "13.248.0.0/20", details)
  }

  @Test
  fun cloudHandlerGetDetailsNoMatch() = runTest {
    val manager = CloudManager.getInstance()
    manager.ipRanges["AWS"] = setOf(IpNetwork.parse("13.248.0.0/20"))
    assertNull(manager.getCloudProviderDetails("8.8.8.8"))
  }

  @Test
  fun redisDeletePatternWithKeys() = runTest {
    val config = securityConfigRedis()
    val redis = RedisManager.getInstance(config)
    redis.initialize()
    try {
      redis.setKey("edge", "k1", "v1")
      redis.setKey("edge", "k2", "v2")
      val deleted = redis.deletePattern("edge:*")
      assertEquals(2, deleted)
      assertNull(redis.getKey("edge", "k1"))
    } finally {
      redis.close()
    }
  }

  @Test
  fun securityHeadersGetHeadersAgentEvent() = runTest {
    SecurityHeadersManager.resetInstance()
    val manager = SecurityHeadersManager.getInstance()
    val agent = RecordingAgent()
    manager.agentHandler = agent
    manager.getHeaders("/x")
    assertEquals(1, agent.events.size)
    assertEquals("security_headers", agent.events[0]["handler_name"])
  }

  @Test
  fun securityHeadersWildcardCredentialsTrue() = runTest {
    SecurityHeadersManager.resetInstance()
    val manager = SecurityHeadersManager.getInstance()
    manager.corsConfig =
        linkedMapOf<String, Any?>(
            "origins" to listOf("*"),
            "allow_credentials" to true,
        )
    assertEquals(
        true,
        manager.isWildcardWithCredentials(listOf("*"), manager.corsConfig),
    )
  }

  @Test
  fun securityHeadersGetHeadersCacheHit() = runTest {
    SecurityHeadersManager.resetInstance()
    val manager = SecurityHeadersManager.getInstance()
    val first = manager.getHeaders("/cached/path")
    val second = manager.getHeaders("/cached/path")
    assertEquals(first, second)
    assertEquals(1, manager.headersCache.size)
  }

  @Test
  fun isWildcardWithCredentialsVariants() = runTest {
    SecurityHeadersManager.resetInstance()
    val manager = SecurityHeadersManager.getInstance()
    assertEquals(false, manager.isWildcardWithCredentials(listOf("a.example.com")))
    manager.corsConfig = null
    assertEquals(false, manager.isWildcardWithCredentials(listOf("*")))
    manager.corsConfig =
        linkedMapOf<String, Any?>(
            "origins" to listOf("*"),
            "allow_credentials" to false,
        )
    assertEquals(false, manager.isWildcardWithCredentials(listOf("*")))
  }

  @Test
  fun getCloudProviderDetailsSkipsProviderNotInRanges() = runTest {
    // Provider NOT in self.ip_ranges: loop continues (cloud_handler.py:367-368).
    CloudManager.resetInstance()
    val mgr = CloudManager.getInstance()
    mgr.ipRanges.clear()
    mgr.ipRanges["AWS"] = emptySet()
    assertNull(mgr.getCloudProviderDetails("1.2.3.4", setOf("AWS", "Unknown")))
  }

  private fun rateLimitConfigForEdge(): com.guardcore.config.SecurityConfig =
      com.guardcore.config
          .SecurityConfigBuilder()
          .apply {
            enableRedis = false
            redisUrl = null
          }
          .build()

  @Test
  fun ipbanManagerReturnsExistingSingleton() = runTest {
    val first = IpBanManager.getInstance()
    val second = IpBanManager.getInstance()
    assertTrue(first === second)
  }

  @Test
  fun isIpBannedNotInMemoryAndNoRedis() = runTest {
    val manager = IpBanManager.getInstance()
    manager.redisHandler = null
    manager.bannedIps.clear()
    manager.bannedNetworks.clear()
    assertEquals(false, manager.isIpBanned("203.0.113.77"))
  }

  @Test
  fun isIpBannedRedisMissReturnsFalse() = runTest {
    val manager = IpBanManager.getInstance()
    val redis = RecordingRedis()
    manager.redisHandler = redis
    assertEquals(false, manager.isIpBanned("203.0.113.78"))
  }

  @Test
  fun isIpBannedRedisStaleExpiryCleanup() = runTest {
    val manager = IpBanManager.getInstance()
    val redis = RecordingRedis()
    redis.getKeyReturns[("banned_ips" to "203.0.113.79")] = PyTimeStr.of(nowSeconds() - 5)
    manager.redisHandler = redis
    assertEquals(false, manager.isIpBanned("203.0.113.79"))
    assertEquals(listOf("banned_ips" to "203.0.113.79"), redis.deleteCalls)
  }

  @Test
  fun ipbanResetNoopWhenNoRedisHandler() = runTest {
    val manager = IpBanManager.getInstance()
    manager.redisHandler = null
    manager.bannedIps["x"] = nowSeconds() + 60
    manager.reset()
    assertEquals(0, manager.bannedIps.size)
  }

  @Test
  fun fetchGcpParsesBothPrefixFamilies() {
    // The GCP fetcher maps ipv4Prefix/ipv6Prefix entries; the parsing kernel is the
    // network constructor used per prefix (the HTTP half is environment-bound).
    assertEquals(
        true,
        IpNetwork.parse("34.0.0.0/8").contains(com.guardcore.util.py.parseAddress("34.1.2.3")),
    )
    assertEquals(
        true,
        IpNetwork.parse("2001:db8::/32")
            .contains(com.guardcore.util.py.parseAddress("2001:db8::1")),
    )
  }
}
