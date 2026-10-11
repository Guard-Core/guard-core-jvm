package com.guardcore.handlers

import com.guardcore.config.SecurityConfig
import com.guardcore.config.SecurityConfigBuilder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/**
 * The remaining handler-side halves of tests/test_core/test_check_rate_limit_by_ip_autoban.py (the
 * first halves landed in W3's RateLimitManagerTest.CheckRateLimitByIpAutobanTest): the loopback
 * self-DoS refusal, the rejected-input no-counter guarantee, the redis-backed over-limit feed, and
 * the autoban-counter LRU eviction at the production cap.
 */
public class CheckRateLimitByIpAutobanHalvesTest {
  /**
   * python rebuilds every mock per test; the ban fault-injection seam lives on the process
   * singleton, so it is dropped after each test or it intercepts real bans in later classes.
   */
  @org.junit.jupiter.api.AfterEach
  fun dropBanOverride() {
    com.guardcore.handlers.IpBanManager.getInstance().banIpOverride = null
  }

  private fun autobanConfig(mutate: SecurityConfigBuilder.() -> Unit = {}): SecurityConfig =
      SecurityConfigBuilder()
          .apply {
            enableRedis = false
            redisUrl = null
            rateLimit = 1
            rateLimitWindow = 60
            enableRateLimitAutoBan = true
            enableIpBanning = true
            autoBanThreshold = 1
          }
          .apply(mutate)
          .build()

  private suspend fun resetAll() {
    RateLimitState.reset()
    resetIpBanGlobalState()
  }

  private fun recordingBan(
      banCalls: MutableList<Triple<String, Int, String>>,
      config: SecurityConfig,
      failWith: Throwable? = null,
  ) {
    IpBanManager.resetInstance()
    val manager = IpBanManager.getInstance()
    manager.redisHandler = null
    manager.config = config
    manager.bannedIps.clear()
    manager.banIpOverride = { ip, duration, reason ->
      // python's AsyncMock(side_effect=...) records the call, then raises.
      banCalls.add(Triple(ip, duration, reason))
      failWith?.let { throw it }
      true
    }
  }

  // ------------------------------- test_check_rate_limit_by_ip_autoban.py:148-168

  @Test
  fun loopbackIpNotBannedDespiteThresholdCrossing() {
    runTestBlock {
      resetAll()
      val config = autobanConfig()
      IpBanManager.resetInstance()
      val manager = IpBanManager.getInstance()
      manager.redisHandler = null
      manager.config = config
      manager.bannedIps.clear()

      assertEquals(true, checkRateLimitByIp("127.0.0.1", config))
      assertEquals(false, checkRateLimitByIp("127.0.0.1", config))

      assertFalse(manager.bannedIps.containsKey("127.0.0.1"))
    }
  }

  // ------------------------------- test_check_rate_limit_by_ip_autoban.py:171-188

  @Test
  fun rejectedIpInputRecordsNoAutobanCount() {
    runTestBlock {
      resetAll()
      val config = autobanConfig()
      val badIp = "not-an-ip-192.0.2.106"

      assertFailsWith<IllegalArgumentException> {
        checkRateLimitByIp(badIp, config)
      }

      assertFalse(RateLimitState.byIpAutobanCounts.containsKey(badIp))
    }
  }

  // ------------------------------- test_check_rate_limit_by_ip_autoban.py:191-222
  // python monkeypatches _redis_request_count to return 5; the JVM preseeds the real redis zset
  // for the ip's rate key, so the over-limit count arrives through the live Lua path.

  @Test
  fun redisBackedOverLimitFeedsAutobanCounter() {
    runTestBlock {
      resetAll()
      val config = autobanConfig {
        enableRedis = true
        autoBanThreshold = 1
        autoBanDuration = 111
      }
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls, config)

      val handler = RedisManager.getInstance(securityConfigRedis())
      handler.initialize()
      try {
        val ip = "192.0.2.107"
        val rateKey = "${redisPrefixOf(handler)}rate_limit:rate:$ip"
        // Preseed INSIDE the sliding window (old scores are pruned by the Lua script).
        withRedisConnection(handler) { conn ->
          for (i in 0 until 5) {
            val score = nowSeconds() - 1
            conn.zadd(rateKey, score, score.toString())
          }
        }

        val result = checkRateLimitByIp(ip, config, handler)

        assertEquals(false, result)
        assertEquals(listOf(Triple(ip, 111, "rate_limit_exceeded")), banCalls)
      } finally {
        handler.deletePattern("*")
        handler.close()
      }
    }
  }

  // ------------------------------- test_check_rate_limit_by_ip_autoban.py:333-368
  // python shrinks _MAX_TRACKED_RATE_LIMIT_KEYS to 3; the cap here is the production constant,
  // so the touched-key-survives eviction property runs at real scale over a prefilled store.

  @Test
  fun autobanCounterEvictsTheOldestIpATouchedIpSurvives() {
    runTestBlock {
      resetAll()
      val store = RateLimitState.byIpAutobanCounts
      val config = autobanConfig { autoBanThreshold = 1000000 }
      val banCalls = mutableListOf<Triple<String, Int, String>>()
      recordingBan(banCalls, config)

      for (i in 0 until RateLimitState.MAX_TRACKED_RATE_LIMIT_KEYS - 3) {
        store["172.16.$i.1"] = 0
      }

      // Two calls per ip: the first is allowed, the second crosses the limit and feeds the
      // dedicated counter (python: `await check(ip); await check(ip)`).
      for (ip in listOf("198.51.100.1", "198.51.100.2", "198.51.100.3")) {
        checkRateLimitByIp(ip, config)
        checkRateLimitByIp(ip, config)
      }
      for (ip in listOf("198.51.100.1", "198.51.100.2", "198.51.100.3")) {
        assertTrue(ip in store, "$ip must be counted")
      }

      checkRateLimitByIp("198.51.100.1", config)
      checkRateLimitByIp("198.51.100.4", config)
      checkRateLimitByIp("198.51.100.4", config)

      assertEquals(RateLimitState.MAX_TRACKED_RATE_LIMIT_KEYS, store.size)
      assertTrue(store.keys.first().startsWith("172.16."), "the untouched oldest entry is evicted")
      assertTrue("198.51.100.1" in store, "a touched ip survives")
      assertTrue("198.51.100.4" in store)
    }
  }
}

/** runTest helper for the file (mirrors the handler-test runBlocking idiom). */
private fun runTestBlock(block: suspend () -> Unit) {
  runBlocking { block() }
}
