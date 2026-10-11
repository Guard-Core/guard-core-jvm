package com.guardcore.handlers

import com.guardcore.config.SecurityConfig
import com.guardcore.config.SecurityConfigBuilder
import java.util.ArrayDeque
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The remaining handler-side halves of tests/test_core/test_check_rate_limit_by_ip.py (the first
 * halves landed in W3's RateLimitManagerTest.CheckRateLimitByIpTest): input validation shapes,
 * endpoint-path redaction on the redis and in-memory keys, rejected-input no-hit guarantees, the
 * ipv6 pipeline bucket, and the in-memory LRU eviction property at the production cap.
 */
public class CheckRateLimitByIpHalvesTest {
  private fun halvesConfig(mutate: SecurityConfigBuilder.() -> Unit = {}): SecurityConfig =
      SecurityConfigBuilder()
          .apply {
            enableRedis = false
            redisUrl = null
            rateLimit = 1
            rateLimitWindow = 60
          }
          .apply(mutate)
          .build()

  private fun resetStores() {
    RateLimitState.reset()
  }

  // ------------------------------- test_check_rate_limit_by_ip.py:256-273

  @Test
  fun unparseableIpRaisesValueErrorWsCollisionString() {
    runTest {
      resetStores()
      val config = halvesConfig {}

      assertFailsWith<IllegalArgumentException> {
        checkRateLimitByIp("1.2.3.4:ws", config)
      }
    }
  }

  @Test
  fun unparseableIpRaisesValueErrorEmptyString() {
    runTest {
      resetStores()
      val config = halvesConfig {}

      assertFailsWith<IllegalArgumentException> {
        checkRateLimitByIp("", config)
      }
    }
  }

  // ------------------------------- test_check_rate_limit_by_ip.py:311-335

  @Test
  fun redisKeyNeverContainsEndpointPathText() {
    runTest {
      val config = securityConfigRedis()
      config.rateLimit = 5
      config.rateLimitWindow = 60
      val handler = RedisManager.getInstance(config)
      handler.initialize()
      val secretPath = "/orders/password=hunter2topsecretvalue"
      val ip = "203.0.113.40"
      try {
        checkRateLimitByIp(ip, config, redisHandler = handler, endpointPath = secretPath)

        val keys =
            withRedisConnection(handler) { conn ->
              conn.keys("${config.redisPrefix}rate_limit:rate:$ip:*")
            } ?: emptyList()
        assertTrue(keys.isNotEmpty(), "expected a rate-limit key for this ip")
        for (rawKey in keys) {
          assertTrue(!rawKey.contains(secretPath), "key must not carry the raw path: $rawKey")
          assertTrue(!rawKey.contains("hunter2topsecretvalue"))
        }
      } finally {
        handler.deletePattern("*")
        handler.close()
      }
    }
  }

  // ------------------------------- test_check_rate_limit_by_ip.py:338-363

  @Test
  fun redisEqualPathsShareAKeyDifferentPathsDoNot() {
    runTest {
      val config = securityConfigRedis()
      config.rateLimit = 100
      config.rateLimitWindow = 60
      val handler = RedisManager.getInstance(config)
      handler.initialize()
      val ip = "203.0.113.42"
      try {
        checkRateLimitByIp(ip, config, redisHandler = handler, endpointPath = "/orders/1")
        checkRateLimitByIp(ip, config, redisHandler = handler, endpointPath = "/orders/1")
        checkRateLimitByIp(ip, config, redisHandler = handler, endpointPath = "/orders/2")

        val keys =
            withRedisConnection(handler) { conn ->
              conn.keys("${config.redisPrefix}rate_limit:rate:$ip:*")
            } ?: emptyList()
        assertEquals(2, keys.size, keys.toString())
      } finally {
        handler.deletePattern("*")
        handler.close()
      }
    }
  }

  // ------------------------------- test_check_rate_limit_by_ip.py:366-379

  @Test
  fun inMemoryKeyNeverContainsEndpointPathText() {
    runTest {
      resetStores()
      val config = halvesConfig {}
      val secretPath = "/orders/password=hunter2topsecretvalue"
      val ip = "203.0.113.41"

      checkRateLimitByIp(ip, config, endpointPath = secretPath)

      val matchingKeys = RateLimitState.byIpRequestTimestamps.keys.filter { it.startsWith("$ip:") }
      assertTrue(matchingKeys.isNotEmpty(), "expected an in-memory bucket for this ip")
      for (key in matchingKeys) {
        assertTrue(!key.contains(secretPath), "key must not carry the raw path: $key")
        assertTrue(!key.contains("hunter2topsecretvalue"))
      }
    }
  }

  // ------------------------------- test_check_rate_limit_by_ip.py:382-415

  @Test
  fun rejectedIpRecordsNoHitWhenRateLimitingEnabled() {
    runTest {
      resetStores()
      val config = halvesConfig {}

      try {
        checkRateLimitByIp("not-an-ip", config)
      } catch (expected: IllegalArgumentException) {}

      assertEquals(true, checkRateLimitByIp("203.0.113.21", config))
    }
  }

  @Test
  fun rejectedIpRecordsNoHitWhenRateLimitingDisabled() {
    runTest {
      resetStores()
      val disabledConfig = SecurityConfigBuilder().apply { enableRateLimiting = false }.build()

      try {
        checkRateLimitByIp("not-an-ip", disabledConfig)
      } catch (expected: IllegalArgumentException) {}

      val enabledConfig = halvesConfig {}
      assertEquals(true, checkRateLimitByIp("203.0.113.22", enabledConfig))
    }
  }

  @Test
  fun rejectedEndpointPathRecordsNoHit() {
    runTest {
      resetStores()
      val config = halvesConfig {}

      try {
        checkRateLimitByIp("203.0.113.23", config, endpointPath = "a:b")
      } catch (expected: IllegalArgumentException) {}

      assertEquals(true, checkRateLimitByIp("203.0.113.23", config))
    }
  }

  // ------------------------------- test_check_rate_limit_by_ip.py:418-427

  @Test
  fun validIpv4Accepted() {
    runTest {
      resetStores()
      val config = halvesConfig { rateLimit = 5 }

      assertEquals(true, checkRateLimitByIp("203.0.113.24", config))
    }
  }

  @Test
  fun validIpv6LiteralAccepted() {
    runTest {
      resetStores()
      val config = halvesConfig { rateLimit = 5 }

      assertEquals(true, checkRateLimitByIp("2001:db8::1", config))
    }
  }

  // ------------------------------- test_check_rate_limit_by_ip.py:430-456

  @Test
  fun ipv6SharesPipelineBucketBidirectionally() {
    runTest {
      val config = securityConfigRedis()
      config.rateLimit = 3
      config.rateLimitWindow = 60
      val handler = RedisManager.getInstance(config)
      handler.initialize()
      try {
        val ip = "2001:db8::99"
        val pipeline = RateLimitManager.getInstance(config)
        pipeline.redisHandler = handler

        var count = pipeline.getRedisRequestCount(ip, nowSeconds(), nowSeconds() - 60)
        assertEquals(1L, count)

        assertEquals(true, checkRateLimitByIp(ip, config, handler))

        count = pipeline.getRedisRequestCount(ip, nowSeconds(), nowSeconds() - 60)
        assertEquals(3L, count)

        assertEquals(false, checkRateLimitByIp(ip, config, handler))
      } finally {
        handler.close()
      }
    }
  }

  // ------------------------------- test_check_rate_limit_by_ip.py:459-486
  // The pipeline count RECORDS a hit on every call, so a failed primitive call shows up as the
  // count NOT advancing past the manual call's own record.

  @Test
  fun primitiveRaisesInsteadOfCollidingWithPipelineBucket() {
    runTest {
      val config = securityConfigRedis()
      config.rateLimit = 2
      config.rateLimitWindow = 60
      val handler = RedisManager.getInstance(config)
      handler.initialize()
      try {
        val pipeline = RateLimitManager.getInstance(config)
        pipeline.redisHandler = handler

        val count =
            pipeline.getRedisRequestCount(
                "1.2.3.4",
                nowSeconds(),
                nowSeconds() - 60,
                endpointPath = "ws",
            )
        assertEquals(1L, count)

        assertFailsWith<IllegalArgumentException> {
          checkRateLimitByIp("1.2.3.4:ws", config, handler)
        }

        val countAfter =
            pipeline.getRedisRequestCount(
                "1.2.3.4",
                nowSeconds(),
                nowSeconds() - 60,
                endpointPath = "ws",
            )
        assertEquals(2L, countAfter)
      } finally {
        handler.close()
      }
    }
  }

  // ------------------------------- test_check_rate_limit_by_ip.py:489-522
  // python shrinks _MAX_TRACKED_RATE_LIMIT_KEYS to 3; the cap here is the production constant
  // (10,000), so the eviction property runs at real scale over a prefilled store.

  @Test
  fun inMemoryStoreEvictsTheOldestKeyAtCapacity() {
    runTest {
      resetStores()
      val config = halvesConfig { rateLimit = 1000 }
      val store = RateLimitState.byIpRequestTimestamps
      for (i in 0 until RateLimitState.MAX_TRACKED_RATE_LIMIT_KEYS - 3) {
        store["172.16.$i.1"] = ArrayDeque()
      }

      for (ip in listOf("10.0.0.1", "10.0.0.2", "10.0.0.3")) {
        checkRateLimitByIp(ip, config)
      }
      for (ip in listOf("10.0.0.1", "10.0.0.2", "10.0.0.3")) {
        assertTrue(ip in store, "$ip must be tracked")
      }

      checkRateLimitByIp("10.0.0.4", config)

      assertEquals(RateLimitState.MAX_TRACKED_RATE_LIMIT_KEYS, store.size)
      assertTrue(store.keys.first().startsWith("172.16."), "the untouched oldest entry is evicted")
      assertTrue("10.0.0.4" in store)
    }
  }

  @Test
  fun inMemoryStoreATouchedKeySurvivesEviction() {
    runTest {
      resetStores()
      val config = halvesConfig { rateLimit = 1000 }
      val store = RateLimitState.byIpRequestTimestamps
      for (i in 0 until RateLimitState.MAX_TRACKED_RATE_LIMIT_KEYS - 3) {
        store["172.16.$i.1"] = ArrayDeque()
      }

      for (ip in listOf("10.0.1.1", "10.0.1.2", "10.0.1.3")) {
        checkRateLimitByIp(ip, config)
      }

      checkRateLimitByIp("10.0.1.1", config)
      checkRateLimitByIp("10.0.1.4", config)

      assertTrue("10.0.1.1" in store, "a touched key survives eviction")
      assertEquals(RateLimitState.MAX_TRACKED_RATE_LIMIT_KEYS, store.size)
    }
  }
}
