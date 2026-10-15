package com.guardcore.handlers

import com.guardcore.config.SecurityConfig
import com.guardcore.config.SecurityConfigBuilder
import com.guardcore.config.ThreatBanConfig
import com.guardcore.errors.GuardRedisError
import com.guardcore.protocols.GuardRedisConnection
import com.guardcore.protocols.RedisHandlerProtocol
import io.lettuce.core.RedisException
import io.lettuce.core.RedisNoScriptException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.delay

/** Scripted-connection protocol fake backing the noscript/ratelimit tests. */
public class FakeScriptedRedis(
    public val redisPrefix: String = "test:",
    public val evalShaScript: (Long) -> Long = { 1L },
    public var evalShaSequence: MutableList<Any> = mutableListOf(),
    public var scriptLoadResult: Any = "newsha",
) : RedisHandlerProtocol {
  public var scriptLoadCalls: Int = 0
    private set

  public var evalShaCalls: Int = 0
    private set

  private var lastEvalShaEffect: Any? = null

  public val scriptedOps: RedisOperations =
      object : RedisOperations by NoopRedisOperations() {
        override suspend fun evalSha(sha: String, keys: List<String>, argv: List<String>): Long {
          evalShaCalls += 1
          val next =
              if (evalShaSequence.isEmpty()) {
                lastEvalShaEffect
              } else {
                evalShaSequence.removeAt(0).also { lastEvalShaEffect = it }
              }
          if (next is Exception) {
            throw next
          }
          if (next is RedisNoScriptException) {
            throw next
          }
          if (next is Long) {
            return next
          }
          return evalShaScript(0L)
        }

        override suspend fun scriptLoad(script: String): String? {
          scriptLoadCalls += 1
          return when (val r = scriptLoadResult) {
            is Exception -> throw r
            is String -> r
            else -> null
          }
        }
      }

  override suspend fun getKey(namespace: String, key: String): Any? = null

  override suspend fun setKey(namespace: String, key: String, value: Any?, ttl: Int?): Boolean? =
      true

  override suspend fun delete(namespace: String, key: String): Int? = 1

  override suspend fun keys(pattern: String): List<String>? = emptyList()

  override suspend fun initialize() {}

  override fun getConnection(): GuardRedisConnection =
      object : GuardRedisConnection {
        override val client: Any? = scriptedOps

        override fun close() {}
      }
}

/** A redis handler whose every operation raises RedisException (python `_broken_redis_handler`). */
public class BrokenRedisHandler(
    public val redisPrefix: String = "test:",
) : RedisHandlerProtocol {
  private val ops =
      object : RedisOperations by NoopRedisOperations() {
        override suspend fun get(key: String): String? = throw RedisException("down")

        override suspend fun zadd(key: String, score: Double, member: String): Long =
            throw RedisException("down")

        override suspend fun zremRangeByScore(key: String, min: String, max: String): Long =
            throw RedisException("down")

        override suspend fun zcard(key: String): Long = throw RedisException("down")

        override suspend fun expire(key: String, seconds: Long): Boolean =
            throw RedisException("down")

        override suspend fun transaction(ops: suspend (QueuedRedisOperations) -> Unit): List<Any?> =
            throw RedisException("down")
      }

  override suspend fun getKey(namespace: String, key: String): Any? = throw RedisException("down")

  override suspend fun setKey(namespace: String, key: String, value: Any?, ttl: Int?): Boolean? =
      throw RedisException("down")

  override suspend fun delete(namespace: String, key: String): Int? = throw RedisException("down")

  override suspend fun keys(pattern: String): List<String>? = throw RedisException("down")

  override suspend fun initialize() {}

  override fun getConnection(): GuardRedisConnection =
      object : GuardRedisConnection {
        override val client: Any? = ops

        override fun close() {}
      }
}

private fun rateLimitConfig(
    enableRedis: Boolean = false,
    rateLimit: Int = 10,
    rateLimitWindow: Int = 60,
): SecurityConfig =
    SecurityConfigBuilder()
        .apply {
          this.enableRedis = enableRedis
          if (!enableRedis) redisUrl = null
          this.rateLimit = rateLimit
          this.rateLimitWindow = rateLimitWindow
        }
        .build()

private fun resetRateLimitState() {
  RateLimitManager.resetInstance()
  RateLimitState.reset()
}

/**
 * Ports of tests/test_core/test_rate_limit_noscript.py (11 handler tests) plus the handler-scope
 * tests of test_rate_limit_edge_cases.py (initialize_redis/reset).
 */
class RateLimitNoscriptTest {
  init {
    resetRateLimitState()
  }

  @Test
  fun noscriptTriggersReloadAndRetrySucceeds() = runTest {
    val config = rateLimitConfig(enableRedis = true)
    val manager = RateLimitManager.getInstance(config)
    manager.rateLimitScriptSha = "deadbeef"
    val conn = FakeScriptedRedis()
    conn.evalShaSequence = mutableListOf(RedisNoScriptException("NOSCRIPT"), 1L)
    manager.redisHandler = conn

    val result =
        manager.getRedisRequestCount(clientIp = "1.1.1.1", currentTime = 100.0, windowStart = 40.0)

    assertEquals(1L, result)
    assertEquals(1, conn.scriptLoadCalls)
    assertEquals(2, conn.evalShaCalls)
    assertEquals("newsha", manager.rateLimitScriptSha)
  }

  @Test
  fun noscriptReloadFailureRaisesWhenFailOpenIsFalse() = runTest {
    val config = rateLimitConfig(enableRedis = true)
    val manager = RateLimitManager.getInstance(config)
    manager.rateLimitScriptSha = "deadbeef"
    val conn = FakeScriptedRedis()
    conn.evalShaSequence = mutableListOf(RedisNoScriptException("NOSCRIPT"))
    conn.scriptLoadResult = RedisException("connection lost")
    manager.redisHandler = conn

    captureLogs("guard_core.handlers.ratelimit", java.util.logging.Level.SEVERE) { capture ->
      assertFailsWithMessage<GuardRedisError> {
        manager.getRedisRequestCount(clientIp = "1.1.1.1", currentTime = 100.0, windowStart = 40.0)
      }
      assertTrue(capture.records.any { it.message.contains("Redis rate limiting error") })
    }
  }

  @Test
  fun noscriptReloadFailureFallsBackWhenFailOpenIsTrue() = runTest {
    val config =
        SecurityConfigBuilder()
            .apply {
              enableRedis = true
              redisUrl = null
              rateLimit = 100
              rateLimitWindow = 60
              redisFailOpen = true
            }
            .build()
    val manager = RateLimitManager.getInstance(config)
    manager.rateLimitScriptSha = "deadbeef"
    val conn = FakeScriptedRedis()
    conn.evalShaSequence = mutableListOf(RedisNoScriptException("NOSCRIPT"))
    conn.scriptLoadResult = RedisException("connection lost")
    manager.redisHandler = conn

    captureLogs("guard_core.handlers.ratelimit", java.util.logging.Level.WARNING) { capture ->
      val result =
          manager.getRedisRequestCount(
              clientIp = "1.1.1.1",
              currentTime = 100.0,
              windowStart = 40.0,
          )
      assertNull(result)
      assertTrue(capture.records.any { it.message.contains("Redis unavailable for rate limiting") })
    }
  }

  @Test
  fun doubleNoscriptRaisesWhenFailOpenIsFalse() = runTest {
    val config = rateLimitConfig(enableRedis = true)
    val manager = RateLimitManager.getInstance(config)
    manager.rateLimitScriptSha = "deadbeef"
    val conn = FakeScriptedRedis()
    conn.evalShaSequence =
        mutableListOf(RedisNoScriptException("first"), RedisNoScriptException("second"))
    conn.scriptLoadResult = "newsha"
    manager.redisHandler = conn

    assertFailsWithMessage<GuardRedisError> {
      manager.getRedisRequestCount(clientIp = "1.1.1.1", currentTime = 100.0, windowStart = 40.0)
    }
  }

  @Test
  fun doubleNoscriptFallsBackWhenFailOpenIsTrue() = runTest {
    val config =
        SecurityConfigBuilder()
            .apply {
              enableRedis = true
              redisUrl = null
              rateLimit = 100
              rateLimitWindow = 60
              redisFailOpen = true
            }
            .build()
    val manager = RateLimitManager.getInstance(config)
    manager.rateLimitScriptSha = "deadbeef"
    val conn = FakeScriptedRedis()
    conn.evalShaSequence =
        mutableListOf(RedisNoScriptException("first"), RedisNoScriptException("second"))
    conn.scriptLoadResult = "newsha"
    manager.redisHandler = conn

    val result =
        manager.getRedisRequestCount(clientIp = "1.1.1.1", currentTime = 100.0, windowStart = 40.0)
    assertNull(result)
  }

  @Test
  fun genericRedisErrorRaisesWhenFailOpenIsFalse() = runTest {
    val config = rateLimitConfig(enableRedis = true)
    val manager = RateLimitManager.getInstance(config)
    manager.rateLimitScriptSha = "deadbeef"
    val conn = FakeScriptedRedis()
    conn.evalShaSequence = mutableListOf(RedisException("connection refused"))
    manager.redisHandler = conn

    assertFailsWithMessage<GuardRedisError> {
      manager.getRedisRequestCount(clientIp = "1.1.1.1", currentTime = 100.0, windowStart = 40.0)
    }
  }

  @Test
  fun genericRedisErrorFallsBackWhenFailOpenIsTrue() = runTest {
    val config =
        SecurityConfigBuilder()
            .apply {
              enableRedis = true
              redisUrl = null
              rateLimit = 100
              rateLimitWindow = 60
              redisFailOpen = true
            }
            .build()
    val manager = RateLimitManager.getInstance(config)
    manager.rateLimitScriptSha = "deadbeef"
    val conn = FakeScriptedRedis()
    conn.evalShaSequence = mutableListOf(RedisException("connection refused"))
    manager.redisHandler = conn

    val result =
        manager.getRedisRequestCount(clientIp = "1.1.1.1", currentTime = 100.0, windowStart = 40.0)
    assertNull(result)
  }

  @Test
  fun failOpenWarningLoggedOnceAcrossManyCalls() = runTest {
    val config =
        SecurityConfigBuilder()
            .apply {
              enableRedis = true
              redisUrl = null
              rateLimit = 100
              rateLimitWindow = 60
              redisFailOpen = true
            }
            .build()
    val manager = RateLimitManager.getInstance(config)
    manager.rateLimitScriptSha = "deadbeef"
    val conn = FakeScriptedRedis()
    conn.evalShaSequence = mutableListOf(RedisException("connection refused"))
    manager.redisHandler = conn

    captureLogs("guard_core.handlers.ratelimit", java.util.logging.Level.WARNING) { capture ->
      repeat(5) {
        val result =
            manager.getRedisRequestCount(
                clientIp = "1.1.1.1",
                currentTime = 100.0,
                windowStart = 40.0,
            )
        assertNull(result)
      }

      val warnings =
          capture.records.filter { it.message.contains("Redis unavailable for rate limiting") }
      assertEquals(1, warnings.size)
      assertEquals(0, conn.scriptLoadCalls)
    }
  }

  @Test
  fun scriptReloadedEmitsAgentEvent() = runTest {
    val config = rateLimitConfig(enableRedis = true)
    val manager = RateLimitManager.getInstance(config)
    manager.rateLimitScriptSha = "deadbeef"
    val conn = FakeScriptedRedis()
    conn.evalShaSequence = mutableListOf(RedisNoScriptException("NOSCRIPT"), 1L)
    manager.redisHandler = conn

    val agent = RecordingAgent()
    manager.agentHandler = agent

    manager.getRedisRequestCount(clientIp = "1.1.1.1", currentTime = 100.0, windowStart = 40.0)

    assertEquals(1, agent.events.size)
    assertEquals("rate_limit_script_reloaded", agent.events[0]["event_type"])
    assertEquals("rate_limit", agent.events[0]["handler_name"])
  }

  @Test
  fun scriptReloadedWithoutAgentHandlerNoError() = runTest {
    val config = rateLimitConfig(enableRedis = true)
    val manager = RateLimitManager.getInstance(config)
    manager.rateLimitScriptSha = "deadbeef"
    val conn = FakeScriptedRedis()
    conn.evalShaSequence = mutableListOf(RedisNoScriptException("NOSCRIPT"), 1L)
    manager.redisHandler = conn
    manager.agentHandler = null

    val result =
        manager.getRedisRequestCount(clientIp = "1.1.1.1", currentTime = 100.0, windowStart = 40.0)
    assertEquals(1L, result)
  }

  @Test
  fun scriptReloadEventEmissionFailureSwallowed() = runTest {
    val config = rateLimitConfig(enableRedis = true)
    val manager = RateLimitManager.getInstance(config)
    manager.rateLimitScriptSha = "deadbeef"
    val conn = FakeScriptedRedis()
    conn.evalShaSequence = mutableListOf(RedisNoScriptException("NOSCRIPT"), 1L)
    manager.redisHandler = conn

    val agent = RecordingAgent()
    agent.failWith = RuntimeException("agent down")
    manager.agentHandler = agent

    captureLogs("guard_core.handlers.ratelimit", java.util.logging.Level.SEVERE) { capture ->
      val result =
          manager.getRedisRequestCount(
              clientIp = "1.1.1.1",
              currentTime = 100.0,
              windowStart = 40.0,
          )
      assertEquals(1L, result)
      assertTrue(capture.records.any { it.message.contains("Failed to send script-reload event") })
    }
  }

  /** test_rate_limit_edge_cases.py::test_initialize_redis_noop_when_redis_disabled. */
  @Test
  fun initializeRedisNoopWhenRedisDisabled() = runTest {
    val config = rateLimitConfig(enableRedis = false)
    val manager = RateLimitManager.getInstance(config)
    val redis = FakeScriptedRedis()
    manager.initializeRedis(redis)
    assertTrue(manager.redisHandler === redis)
    // script_sha not loaded because enable_redis was False.
    assertEquals(0, redis.scriptLoadCalls)
  }

  /** test_rate_limit_edge_cases.py::test_reset_noop_when_redis_keys_missing. */
  @Test
  fun resetNoopWhenRedisKeysMissing() = runTest {
    val config = rateLimitConfig(enableRedis = true)
    val manager = RateLimitManager.getInstance(config)
    val redis = FakeScriptedRedis()
    manager.redisHandler = redis
    manager.reset()
  }
}

/**
 * Ports of tests/test_core/test_rate_limit_singleton_isolation.py (singleton identity/config
 * surface; the RateLimitCheck harness half is W4).
 */
class RateLimitSingletonIsolationTest {
  init {
    resetRateLimitState()
  }

  @Test
  fun singletonIdentityHoldsAcrossConfigUpdates() = runTest {
    val configTight = rateLimitConfig(rateLimit = 1, rateLimitWindow = 60)
    val configLoose = rateLimitConfig(rateLimit = 100, rateLimitWindow = 60)

    val tight = RateLimitManager.getInstance(configTight)
    val loose = RateLimitManager.getInstance(configLoose)

    assertTrue(tight === loose)
    // python __new__ re-assigns cls._instance.config on every construction.
    assertTrue(loose.config === configLoose)
  }

  @Test
  fun inMemoryBucketsArePerIpAndSharedThroughTheSingletonStore() = runTest {
    val config = rateLimitConfig(rateLimit = 1, rateLimitWindow = 60)
    val manager = RateLimitManager.getInstance(config)

    val now = 1_000_000.0
    assertEquals(0L, manager.getInMemoryRequestCount("198.51.100.10", now - 60, now))
    assertEquals(1L, manager.getInMemoryRequestCount("198.51.100.10", now - 60, now))
    assertEquals(0L, manager.getInMemoryRequestCount("198.51.100.20", now - 60, now))
  }
}

/**
 * Ports of tests/test_core/test_check_rate_limit_by_ip.py (30 tests; the request-free primitive
 * surface of ratelimit_handler.py).
 */
class CheckRateLimitByIpTest {
  init {
    resetRateLimitState()
  }

  @Test
  fun underLimitStaysAllowed() = runTest {
    val config = rateLimitConfig(rateLimit = 2, rateLimitWindow = 60)

    assertEquals(true, checkRateLimitByIp("203.0.113.1", config))
    assertEquals(true, checkRateLimitByIp("203.0.113.1", config))
  }

  @Test
  fun overLimitBecomesBlocked() = runTest {
    val config = rateLimitConfig(rateLimit = 1, rateLimitWindow = 60)

    assertEquals(true, checkRateLimitByIp("203.0.113.2", config))
    assertEquals(false, checkRateLimitByIp("203.0.113.2", config))
  }

  @Test
  fun windowExpiryRecoversAfterBlock() = runTest {
    val config = rateLimitConfig(rateLimit = 1, rateLimitWindow = 1)

    assertEquals(true, checkRateLimitByIp("203.0.113.3", config))
    assertEquals(false, checkRateLimitByIp("203.0.113.3", config))

    delay(1100)

    assertEquals(true, checkRateLimitByIp("203.0.113.3", config))
  }

  @Test
  fun redisPathEnforcesLimit() = runTest {
    val config = securityConfigRedis()
    config.rateLimit = 2
    config.rateLimitWindow = 60
    val handler = RedisManager.getInstance(config)
    handler.initialize()
    try {
      val ip = "203.0.113.4"
      assertEquals(true, checkRateLimitByIp(ip, config, handler, endpointPath = "ws"))
      assertEquals(true, checkRateLimitByIp(ip, config, handler, endpointPath = "ws"))
      assertEquals(false, checkRateLimitByIp(ip, config, handler, endpointPath = "ws"))
    } finally {
      handler.close()
    }
  }

  @Test
  fun fallsBackToInMemoryWhenRedisHandlerNotSupplied() = runTest {
    val config = rateLimitConfig(enableRedis = true, rateLimit = 1, rateLimitWindow = 60)

    val ip = "203.0.113.5"
    assertEquals(true, checkRateLimitByIp(ip, config))
    assertEquals(false, checkRateLimitByIp(ip, config))
  }

  @Test
  fun redisErrorRaisesWhenFailOpenIsFalse() = runTest {
    val config = rateLimitConfig(enableRedis = true, rateLimit = 1, rateLimitWindow = 60)
    val redis = BrokenRedisHandler()

    assertFailsWithMessage<GuardRedisError> {
      checkRateLimitByIp("203.0.113.6", config, redisHandler = redis)
    }
  }

  @Test
  fun redisErrorFallsBackToInMemoryCountWhenFailOpenIsTrue() = runTest {
    val config =
        SecurityConfigBuilder()
            .apply {
              enableRedis = true
              redisUrl = null
              rateLimit = 1
              rateLimitWindow = 60
              redisFailOpen = true
            }
            .build()
    val redis = BrokenRedisHandler()

    val ip = "203.0.113.106"
    assertEquals(true, checkRateLimitByIp(ip, config, redisHandler = redis))
    assertEquals(false, checkRateLimitByIp(ip, config, redisHandler = redis))
  }

  @Test
  fun noSingletonMutationRegression() = runTest {
    val configA = rateLimitConfig(rateLimit = 5, rateLimitWindow = 60)
    val pipelineManager = RateLimitManager.getInstance(configA)

    val configB = rateLimitConfig(rateLimit = 1, rateLimitWindow = 60)
    checkRateLimitByIp("203.0.113.7", configB)

    assertTrue(RateLimitManager.getInstance(configA) === pipelineManager)
  }

  @Test
  fun endpointPathNamespacingIsolatesBudgets() = runTest {
    val config = rateLimitConfig(rateLimit = 1, rateLimitWindow = 60)
    val ip = "203.0.113.8"

    assertEquals(true, checkRateLimitByIp(ip, config, endpointPath = "a"))
    assertEquals(false, checkRateLimitByIp(ip, config, endpointPath = "a"))
    assertEquals(true, checkRateLimitByIp(ip, config, endpointPath = "b"))
  }

  @Test
  fun defaultEndpointPathSharesPipelineBucketBidirectionally() = runTest {
    val config = securityConfigRedis()
    config.rateLimit = 3
    config.rateLimitWindow = 60
    val handler = RedisManager.getInstance(config)
    handler.initialize()
    try {
      val ip = "203.0.113.9"
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

  @Test
  fun endpointPathWsIsDisjointFromPipelineBucket() = runTest {
    val config = securityConfigRedis()
    config.rateLimit = 2
    config.rateLimitWindow = 60
    val handler = RedisManager.getInstance(config)
    handler.initialize()
    try {
      val ip = "203.0.113.12"
      val pipeline = RateLimitManager.getInstance(config)
      pipeline.redisHandler = handler

      assertEquals(1L, pipeline.getRedisRequestCount(ip, nowSeconds(), nowSeconds() - 60))
      assertEquals(2L, pipeline.getRedisRequestCount(ip, nowSeconds(), nowSeconds() - 60))

      assertEquals(true, checkRateLimitByIp(ip, config, handler, endpointPath = "ws"))
      assertEquals(true, checkRateLimitByIp(ip, config, handler, endpointPath = "ws"))
      assertEquals(false, checkRateLimitByIp(ip, config, handler, endpointPath = "ws"))

      val count = pipeline.getRedisRequestCount(ip, nowSeconds(), nowSeconds() - 60)
      assertEquals(3L, count)
    } finally {
      handler.close()
    }
  }

  @Test
  fun enableRateLimitingFalseReturnsTrue() = runTest {
    val config =
        SecurityConfigBuilder()
            .apply {
              enableRateLimiting = false
            }
            .build()

    assertEquals(true, checkRateLimitByIp("203.0.113.10", config))
  }

  @Test
  fun redisRequestCountReloadWithoutCallback() = runTest {
    val conn = FakeScriptedRedis()
    conn.evalShaSequence = mutableListOf(RedisNoScriptException("NOSCRIPT"), 1L)
    conn.scriptLoadResult = "newsha"

    val (count, newSha) =
        redisRequestCount(
            conn,
            RateLimitState.logger,
            "203.0.113.11",
            100.0,
            40.0,
            60,
            100,
            "deadbeef",
            null,
        )

    assertEquals(1L, count)
    assertEquals("newsha", newSha)
  }

  @Test
  fun invalidIpRaisesBeforeAnyCounting() = runTest {
    val config = rateLimitConfig(rateLimit = 1, rateLimitWindow = 60)
    RateLimitState.byIpRequestTimestamps.clear()

    assertFailsWithMessage<IllegalArgumentException>("invalid ip") {
      checkRateLimitByIp("not-an-ip", config)
    }
    assertEquals(0, RateLimitState.byIpRequestTimestamps.size)
  }

  @Test
  fun endpointPathWithColonRaisesRedacted() = runTest {
    val config = rateLimitConfig(rateLimit = 1, rateLimitWindow = 60)
    config.logSensitiveParams = setOf("token")

    assertFailsWithMessage<IllegalArgumentException>("endpoint_path must not contain ':'") {
      checkRateLimitByIp("203.0.113.13", config, endpointPath = "/resource;token=super-secret:80")
    }
  }

  @Test
  fun endpointPathIsolationUnderRedisFailsClosedToInMemoryStoreOnly() = runTest {
    // python: "The in-memory fallback is process-local and never shares counts with the
    // pipeline singleton's own in-memory store" - the primitive store is separate.
    val config = rateLimitConfig(rateLimit = 1, rateLimitWindow = 60)
    val ip = "203.0.113.14"

    assertEquals(true, checkRateLimitByIp(ip, config, endpointPath = "ws"))
    assertEquals(false, checkRateLimitByIp(ip, config, endpointPath = "ws"))

    // The pipeline singleton store is untouched.
    val pipeline = RateLimitManager.getInstance(config)
    assertEquals(0L, pipeline.getInMemoryRequestCount(ip, nowSeconds() - 60, nowSeconds()))
  }
}

/**
 * Ports of tests/test_core/test_check_rate_limit_by_ip_autoban.py (the recording-ban-manager
 * surface).
 */
class CheckRateLimitByIpAutobanTest {
  init {
    resetRateLimitState()
    IpBanManager.resetInstance()
  }

  /**
   * python monkeypatches `manager.ban_ip` with a recording fake; the JVM extension dispatch is
   * static, so the recording surfaces through the real manager's local ban store instead.
   */
  private suspend fun installRecordingBanManager(config: SecurityConfig) {
    IpBanManager.resetInstance()
    val manager = IpBanManager.getInstance()
    manager.redisHandler = null
    manager.config = config
    manager.bannedIps.clear()
  }

  @Test
  fun knobOffDefaultNeverBansOnRepeatedViolations() = runTest {
    val config =
        SecurityConfigBuilder()
            .apply {
              enableRedis = false
              redisUrl = null
              rateLimit = 1
              rateLimitWindow = 60
              enableIpBanning = true
              autoBanThreshold = 1
            }
            .build()
    assertFalse(config.enableRateLimitAutoBan)
    installRecordingBanManager(config)
    try {
      val ip = "192.0.2.101"
      checkRateLimitByIp(ip, config)
      checkRateLimitByIp(ip, config)
      checkRateLimitByIp(ip, config)

      assertFalse(IpBanManager.getInstance().bannedIps.containsKey(ip))
    } finally {
      IpBanManager.resetInstance()
    }
  }

  @Test
  fun thresholdCrossingBansWithConfiguredDurationAndReason() = runTest {
    val config =
        SecurityConfigBuilder()
            .apply {
              enableRedis = false
              redisUrl = null
              rateLimit = 1
              rateLimitWindow = 60
              enableRateLimitAutoBan = true
              enableIpBanning = true
              autoBanThreshold = 2
              autoBanDuration = 1234
            }
            .build()
    installRecordingBanManager(config)
    try {
      val ip = "192.0.2.102"
      val banManager = IpBanManager.getInstance()

      assertEquals(true, checkRateLimitByIp(ip, config))
      assertEquals(false, checkRateLimitByIp(ip, config))
      assertFalse(banManager.bannedIps.containsKey(ip))

      assertEquals(false, checkRateLimitByIp(ip, config))
      val expiry = banManager.bannedIps[ip]
      assertTrue(expiry != null, "threshold crossing must ban")
      assertTrue(kotlin.math.abs(expiry - (nowSeconds() + 1234)) < 5)
    } finally {
      IpBanManager.resetInstance()
    }
  }

  @Test
  fun perCategoryThreatBanConfigOverrideHonored() = runTest {
    val config =
        SecurityConfigBuilder()
            .apply {
              enableRedis = false
              redisUrl = null
              rateLimit = 1
              rateLimitWindow = 60
              enableRateLimitAutoBan = true
              enableIpBanning = true
              autoBanThreshold = 1000
              autoBanDuration = 60
              threatBanConfig =
                  mapOf("rate_limit" to ThreatBanConfig(threshold = 1, duration = 999))
            }
            .build()
    installRecordingBanManager(config)
    try {
      val ip = "192.0.2.103"
      val banManager = IpBanManager.getInstance()

      assertEquals(true, checkRateLimitByIp(ip, config))
      assertEquals(false, checkRateLimitByIp(ip, config))

      val expiry = banManager.bannedIps[ip]
      assertTrue(expiry != null, "threat_ban_config override must ban")
      assertTrue(kotlin.math.abs(expiry - (nowSeconds() + 999)) < 5)
    } finally {
      IpBanManager.resetInstance()
    }
  }

  @Test
  fun passiveModeSuppressesCountingAndBan() = runTest {
    val config =
        SecurityConfigBuilder()
            .apply {
              passiveMode = true
              enableRedis = false
              redisUrl = null
              rateLimit = 1
              rateLimitWindow = 60
              enableRateLimitAutoBan = true
              enableIpBanning = true
              autoBanThreshold = 1
            }
            .build()
    installRecordingBanManager(config)
    try {
      val ip = "192.0.2.104"

      assertEquals(true, checkRateLimitByIp(ip, config))
      assertEquals(false, checkRateLimitByIp(ip, config))

      assertFalse(IpBanManager.getInstance().bannedIps.containsKey(ip))
      assertFalse(RateLimitState.byIpAutobanCounts.containsKey(ip))
    } finally {
      IpBanManager.resetInstance()
    }
  }

  @Test
  fun enableIpBanningFalseSuppressesBan() = runTest {
    val config =
        SecurityConfigBuilder()
            .apply {
              enableRedis = false
              redisUrl = null
              rateLimit = 1
              rateLimitWindow = 60
              enableRateLimitAutoBan = true
              enableIpBanning = false
              autoBanThreshold = 1
            }
            .build()
    installRecordingBanManager(config)
    try {
      val ip = "192.0.2.105"
      checkRateLimitByIp(ip, config)
      checkRateLimitByIp(ip, config)

      assertFalse(IpBanManager.getInstance().bannedIps.containsKey(ip))
    } finally {
      IpBanManager.resetInstance()
    }
  }

  @Test
  fun alreadyBannedIpShortCircuitsBeforeCounterIncrement() = runTest {
    val config =
        SecurityConfigBuilder()
            .apply {
              enableRedis = false
              redisUrl = null
              rateLimit = 1
              rateLimitWindow = 60
              enableRateLimitAutoBan = true
              enableIpBanning = true
              autoBanThreshold = 1
              autoBanDuration = 3600
            }
            .build()
    installRecordingBanManager(config)
    try {
      val ip = "192.0.2.106"
      val banManager = IpBanManager.getInstance()
      banManager.bannedIps[ip] = nowSeconds() + 3600

      // Pre-banned: no counting, no re-ban attempts on the manager's local state.
      RateLimitState.byIpAutobanCounts.clear()
      assertEquals(true, checkRateLimitByIp(ip, config))
      assertEquals(false, checkRateLimitByIp(ip, config))
      assertFalse(RateLimitState.byIpAutobanCounts.containsKey(ip))
    } finally {
      IpBanManager.resetInstance()
    }
  }

  @Test
  fun countsAreDedicatedPerProcessStoreNotSharedWithPipeline() = runTest {
    val config =
        SecurityConfigBuilder()
            .apply {
              enableRedis = false
              redisUrl = null
              rateLimit = 1
              rateLimitWindow = 60
              enableRateLimitAutoBan = true
              enableIpBanning = true
              autoBanThreshold = 2
            }
            .build()
    installRecordingBanManager(config)
    try {
      val ip = "192.0.2.107"
      checkRateLimitByIp(ip, config)
      checkRateLimitByIp(ip, config)
      checkRateLimitByIp(ip, config)

      assertEquals(2, RateLimitState.byIpAutobanCounts[ip])
    } finally {
      IpBanManager.resetInstance()
    }
  }

  @Test
  fun passiveRateLimitHitLogNamesTheRateLimitNotAPenetrationAttempt() = runTest {
    val config =
        SecurityConfigBuilder()
            .apply {
              enableRedis = false
              passiveMode = true
            }
            .build()
    val manager = RateLimitManager.getInstance(config)
    captureLogs("guard_core.handlers.ratelimit", java.util.logging.Level.WARNING) { capture ->
      manager.handleRateLimitExceeded(
          com.guardcore.core.TestRequest(),
          "1.2.3.4",
          10,
          createErrorResponse = { code: Int, message: String ->
            object : com.guardcore.protocols.GuardResponse {
              override val headers: MutableMap<String, String> = linkedMapOf()
              override val statusCode: Int = code
              override val body: ByteArray = message.encodeToByteArray()
            }
          },
      )
      val text = capture.records.joinToString("\n") { it.message ?: "" }
      assertTrue("Rate limit exceeded for IP: 1.2.3.4" in text, text)
      assertFalse("Penetration attempt" in text, text)
    }
  }
}
