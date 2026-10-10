package com.guardcore.handlers

import com.guardcore.errors.GuardRedisError
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.delay

/**
 * Ports of tests/test_redis/test_redis.py and tests/test_redis/test_redis_resilience.py against the
 * live local Redis (conftest REDIS_URL).
 */
class RedisManagerTest {
  init {
    RedisManager.resetInstance()
  }

  private fun newHandler(
      config: com.guardcore.config.SecurityConfig = securityConfigRedis(),
  ): RedisManager = RedisManager.getInstance(config)

  @Test
  fun redisBasicOperations() = runTest {
    val config = securityConfigRedis()
    val handler = newHandler(config)
    handler.initialize()

    handler.setKey("test", "key1", "value1")
    val value = handler.getKey("test", "key1")
    assertEquals("value1", value)

    val exists = handler.exists("test", "key1")
    assertEquals(true, exists)

    handler.delete("test", "key1")
    val existsAfter = handler.exists("test", "key1")
    assertEquals(false, existsAfter)

    handler.close()
  }

  @Test
  fun redisDisabled() = runTest {
    val config = securityConfigNoRedis()
    val handler = newHandler(config)
    handler.initialize()

    assertFalse(config.enableRedis)
    assertNull(handler.redisOrNull())
    val result = handler.setKey("test", "key1", "value1")
    assertNull(result)
    val value = handler.getKey("test", "key1")
    assertNull(value)
  }

  @Test
  fun redisErrorHandling() = runTest {
    val handler = newHandler()
    handler.initialize()

    suspend fun failOperation(conn: RedisOperations): Any? =
        throw io.lettuce.core.RedisException("Test connection error")

    try {
      handler.safeOperation { conn -> failOperation(conn) }
      kotlin.test.fail("expected GuardRedisError")
    } catch (e: GuardRedisError) {
      assertEquals(503, e.statusCode)
    }

    handler.close()
  }

  @Test
  fun redisTtlOperations() = runTest {
    val handler = newHandler()
    handler.initialize()

    val key = "ttl_key_${java.util.UUID.randomUUID().toString().replace("-", "")}"
    handler.setKey("test", key, "value", ttl = 1)
    assertEquals("value", handler.getKey("test", key))
    delay(1100)
    assertNull(handler.getKey("test", key))

    handler.close()
  }

  @Test
  fun redisIncrementOperations() = runTest {
    val config = securityConfigRedis()
    val handler = newHandler(config)
    handler.initialize()

    val conn = handler.operations()
    conn!!.del("${config.redisPrefix}test:counter", "${config.redisPrefix}test:ttl_counter")

    assertEquals(1L, handler.incr("test", "counter"))
    assertEquals(2L, handler.incr("test", "counter"))

    assertEquals(1L, handler.incr("test", "ttl_counter", ttl = 1))
    delay(1100)
    assertEquals(false, handler.exists("test", "ttl_counter"))

    handler.close()
  }

  @Test
  fun recordSlidingWindowHitAccumulatesAndTrips() = runTest {
    val config = securityConfigRedis()
    val handler = newHandler(config)
    handler.initialize()

    handler.operations()!!.del("${config.redisPrefix}sliding_window_test:accumulate")

    val base = 2_000_000_000.0
    val windowStart = base - 60

    assertEquals(
        1L,
        handler.recordSlidingWindowHit("sliding_window_test", "accumulate", base, windowStart, 60),
    )
    assertEquals(
        2L,
        handler.recordSlidingWindowHit(
            "sliding_window_test",
            "accumulate",
            base + 1,
            windowStart,
            60,
        ),
    )
    assertEquals(
        3L,
        handler.recordSlidingWindowHit(
            "sliding_window_test",
            "accumulate",
            base + 2,
            windowStart,
            60,
        ),
    )

    handler.close()
  }

  @Test
  fun recordSlidingWindowHitIdenticalTimestampsEachCountSeparately() = runTest {
    val config = securityConfigRedis()
    val handler = newHandler(config)
    handler.initialize()

    val key = "frozen_clock_${java.util.UUID.randomUUID().toString().replace("-", "")}"
    handler.operations()!!.del("${config.redisPrefix}sliding_window_test:$key")

    val frozenTimestamp = 2_000_000_500.0
    val windowStart = frozenTimestamp - 60

    var count = 0L
    repeat(50) {
      count =
          handler.recordSlidingWindowHit(
              "sliding_window_test",
              key,
              frozenTimestamp,
              windowStart,
              60,
          )
    }
    assertEquals(50L, count)

    handler.close()
  }

  @Test
  fun recordSlidingWindowHitPrunesEntriesBeforeWindowStart() = runTest {
    val config = securityConfigRedis()
    val handler = newHandler(config)
    handler.initialize()

    handler.operations()!!.del("${config.redisPrefix}sliding_window_test:prune")

    val base = 2_000_000_100.0

    handler.recordSlidingWindowHit("sliding_window_test", "prune", base - 200, base - 260, 60)
    val count = handler.recordSlidingWindowHit("sliding_window_test", "prune", base, base - 60, 60)
    assertEquals(1L, count)

    handler.close()
  }

  @Test
  fun recordSlidingWindowHitWindowStartBoundaryIsInclusive() = runTest {
    val config = securityConfigRedis()
    val handler = newHandler(config)
    handler.initialize()

    handler
        .operations()!!
        .del(
            "${config.redisPrefix}sliding_window_test:boundary_at",
            "${config.redisPrefix}sliding_window_test:boundary_before",
        )

    val windowStart = 2_000_000_200.0

    val atBoundaryCount =
        handler.recordSlidingWindowHit(
            "sliding_window_test",
            "boundary_at",
            windowStart,
            windowStart,
            60,
        )
    assertEquals(1L, atBoundaryCount)

    val beforeBoundaryCount =
        handler.recordSlidingWindowHit(
            "sliding_window_test",
            "boundary_before",
            windowStart - 0.001,
            windowStart,
            60,
        )
    assertEquals(0L, beforeBoundaryCount)

    handler.close()
  }

  @Test
  fun recordSlidingWindowHitKeyExpiresWithTtl() = runTest {
    val config = securityConfigRedis()
    val handler = newHandler(config)
    handler.initialize()

    handler.operations()!!.del("${config.redisPrefix}sliding_window_test:expiry")

    val now = nowSeconds()
    val count = handler.recordSlidingWindowHit("sliding_window_test", "expiry", now, now - 1, 1)
    assertEquals(1L, count)

    delay(1200)
    assertEquals(false, handler.exists("sliding_window_test", "expiry"))

    handler.close()
  }

  @Test
  fun recordSlidingWindowHitDisabledRedisReturnsZero() = runTest {
    val config = securityConfigNoRedis()
    val handler = newHandler(config)
    handler.initialize()

    assertFalse(config.enableRedis)
    val count = handler.recordSlidingWindowHit("sliding_window_test", "disabled", 1.0, 0.0, 60)
    assertEquals(0L, count)
  }

  @Test
  fun redisConnectionContextGetError() = runTest {
    val handler = newHandler()
    handler.initialize()

    // Python patches conn.get to raise inside the get_connection block; the JVM port raises
    // inside withConnection.
    try {
      handler.withConnection { conn ->
        // simulate a raw command failure on the live client
        throw io.lettuce.core.RedisException("Test connection error on get")
      }
      kotlin.test.fail("expected GuardRedisError")
    } catch (e: GuardRedisError) {
      assertEquals(503, e.statusCode)
    }

    handler.close()
  }

  @Test
  fun redisConnectionFailures() = runTest {
    val config = securityConfigRedis()
    val badConfig =
        securityConfigRedis().let {
          com.guardcore.config
              .SecurityConfigBuilder()
              .apply {
                enableRedis = true
                redisUrl = "redis://nonexistent.invalid:6379"
              }
              .build()
        }
    val handler = newHandler(badConfig)
    try {
      handler.initialize()
      kotlin.test.fail("expected GuardRedisError")
    } catch (e: GuardRedisError) {
      assertEquals(503, e.statusCode)
    }
    assertNull(handler.redisOrNull())

    val good = newHandler(config)
    good.initialize()

    good.close()
    try {
      good.getKey("test", "key")
      kotlin.test.fail("expected GuardRedisError")
    } catch (e: GuardRedisError) {
      assertEquals(503, e.statusCode)
    }

    good.setRedisForTests(null)
    try {
      good.safeOperation { conn -> conn.get("test:key") }
      kotlin.test.fail("expected GuardRedisError")
    } catch (e: GuardRedisError) {
      assertEquals(503, e.statusCode)
    }
  }

  @Test
  fun redisDisabledOperations() = runTest {
    val config = securityConfigRedis()
    config.enableRedis = false
    val handler = newHandler(config)

    assertNull(handler.getKey("test", "key"))
    assertNull(handler.setKey("test", "key", "value"))
    assertNull(handler.incr("test", "counter"))
    assertNull(handler.exists("test", "key"))
    assertNull(handler.delete("test", "key"))
  }

  @Test
  fun redisFailedInitializationOperations() = runTest {
    val badConfig =
        com.guardcore.config
            .SecurityConfigBuilder()
            .apply {
              enableRedis = true
              redisUrl = "redis://invalid.invalid:6379"
            }
            .build()
    val handler = newHandler(badConfig)

    try {
      handler.getKey("test", "key")
      kotlin.test.fail("expected GuardRedisError")
    } catch (e: GuardRedisError) {
      assertEquals(503, e.statusCode)
    }

    try {
      handler.setKey("test", "key", "value")
      kotlin.test.fail("expected GuardRedisError")
    } catch (e: GuardRedisError) {
      assertEquals(503, e.statusCode)
    }
  }

  @Test
  fun redisUrlNone() = runTest {
    val config = securityConfigRedis()
    config.redisUrl = null

    val handler = newHandler(config)

    captureLogs("guard_core.handlers.redis") { capture ->
      handler.initialize()
      assertTrue(
          capture.messages(java.util.logging.Level.WARNING).any {
            it.contains("Redis URL is None")
          },
      )
    }
    assertNull(handler.redisOrNull())
  }

  @Test
  fun safeOperationRedisDisabled() = runTest {
    val handler = newHandler(securityConfigNoRedis())

    var called = false
    val result = handler.safeOperation { _ ->
      called = true
      "x"
    }

    assertNull(result)
    assertFalse(called)
  }

  @Test
  fun connectionContextRedisNone() = runTest {
    val config = securityConfigRedis()
    // python monkeypatches handler.initialize into a no-op; the JVM idiom is an override.
    var initializeCalled = false
    val handler =
        object : RedisManager(config) {
          override suspend fun initialize() {
            initializeCalled = true
          }
        }

    handler.setClosedForTests(false)
    handler.setRedisForTests(null)

    try {
      handler.withConnection { _ -> "x" }
      kotlin.test.fail("expected GuardRedisError")
    } catch (e: GuardRedisError) {
      assertTrue(initializeCalled, "initialize() was not called")
      assertEquals(503, e.statusCode)
      assertTrue(e.detail.contains("Redis connection failed"))
    }
  }

  @Test
  fun redisKeysAndDeletePatternWithRedisDisabled() = runTest {
    val config = securityConfigNoRedis()
    val handler = newHandler(config)

    assertNull(handler.keys("*"))
    assertNull(handler.deletePattern("*"))
  }

  @Test
  fun initializeLogsWarningWhenRedisUrlIsNone() = runTest {
    RedisManager.resetInstance()
    val config = securityConfigRedis()
    config.redisUrl = null
    val manager = newHandler(config)
    captureLogs("guard_core.handlers.redis") { capture ->
      manager.initialize()
      assertTrue(capture.records.isNotEmpty())
    }
    RedisManager.resetInstance()
  }

  @Test
  fun closeNoopWhenRedisNotConnected() = runTest {
    RedisManager.resetInstance()
    val manager = newHandler(securityConfigRedis())
    manager.setRedisForTests(null)
    manager.close()
    assertTrue(manager.isClosed())
    RedisManager.resetInstance()
  }

  @Test
  fun initializeTwiceClosesPreviousClientExactlyOnce() = runTest {
    RedisManager.resetInstance()
    val config = securityConfigRedis()
    val manager = newHandler(config)

    manager.initialize()
    val firstClient = manager.redisOrNull()
    manager.initialize()
    val secondClient = manager.redisOrNull()

    assertTrue(firstClient !== secondClient)
    // The first client was closed (its connection is gone): a command against it fails.
    try {
      firstClient!!.ping()
    } catch (e: Exception) {
      assertIs<Exception>(e)
    }
    assertTrue(secondClient!!.ping())
    manager.close()
    RedisManager.resetInstance()
  }

  @Test
  fun initializeDisabledRedisClosesExistingClient() = runTest {
    RedisManager.resetInstance()
    val config = securityConfigRedis()
    val manager = newHandler(config)
    manager.initialize()
    val existing = manager.redisOrNull()

    config.enableRedis = false
    manager.initialize()

    assertNull(manager.redisOrNull())
    try {
      existing!!.ping()
    } catch (e: Exception) {
      assertIs<Exception>(e)
    }
    RedisManager.resetInstance()
  }

  @Test
  fun initializePingFailureClosesNewClientBeforeRaising() = runTest {
    RedisManager.resetInstance()
    val config = securityConfigRedis()
    val manager =
        RedisManager(
            config,
        ) { _, _, _ ->
          object : RedisOperations by NoopRedisOperations() {
            override suspend fun ping(): Boolean =
                throw io.lettuce.core.RedisException("ping failed")
          }
        }
    try {
      manager.initialize()
      kotlin.test.fail("expected GuardRedisError")
    } catch (e: GuardRedisError) {
      assertNull(manager.redisOrNull())
    }
    RedisManager.resetInstance()
  }

  @Test
  fun closeTwiceDoesNotRaise() = runTest {
    RedisManager.resetInstance()
    val manager = newHandler(securityConfigRedis())
    manager.initialize()

    manager.close()
    manager.close()

    assertTrue(manager.isClosed())
    RedisManager.resetInstance()
  }

  @Test
  fun closeStaleClientFailureIsLoggedAndSwallowed() = runTest {
    RedisManager.resetInstance()
    val manager = newHandler(securityConfigRedis())

    val staleClient =
        object : RedisOperations by NoopRedisOperations() {
          override fun close() = throw RuntimeException("Future attached to a different loop")
        }
    manager.setRedisForTests(staleClient)

    captureLogs("guard_core.handlers.redis") { capture ->
      manager.close()
      assertTrue(capture.messages(java.util.logging.Level.WARNING).isNotEmpty())
    }
    assertNull(manager.redisOrNull())
    assertTrue(manager.isClosed())
    RedisManager.resetInstance()
  }

  @Test
  fun initializeTwiceAgainstRealRedisDoesNotWarn() = runTest {
    val handler = newHandler()

    captureLogs("global") { _ ->
      handler.initialize()
      handler.initialize()
      handler.close()
    }
  }

  /** resilience ports (test_redis_resilience.py). */
  @Test
  fun resilienceInitializeWithRetryOptionsSucceeds() = runTest {
    val config = SecurityConfigBuilderForTest().build()
    val handler = newHandler(config)
    handler.initialize()
    assertTrue(handler.redisOrNull()!!.ping())
    handler.close()
  }

  @Test
  fun resilienceConnectionKwargsFloors() {
    val handler = newHandler(securityConfigRedis())
    val kwargs = handler.connectionKwargs()
    assertTrue(kwargs.containsKey("socket_connect_timeout"))
    assertTrue(kwargs.containsKey("socket_timeout"))
    assertTrue(kwargs.containsKey("health_check_interval"))
  }

  @Test
  fun resilienceOperationAfterClientReconnectSucceeds() = runTest {
    val handler = newHandler()
    handler.initialize()
    handler.setKey("resilience", "k", "v")
    assertEquals("v", handler.getKey("resilience", "k"))
    handler.close()
  }
}

/** Minimal RedisOperations delegator base for partial fakes. */
public open class NoopRedisOperations : RedisOperations {
  override suspend fun get(key: String): String? = null

  override suspend fun set(key: String, value: String): Boolean = true

  override suspend fun setEx(key: String, value: String, ttlSeconds: Long): Boolean = true

  override suspend fun pSetEx(key: String, value: String, ttlMillis: Long): Boolean = true

  override suspend fun del(vararg keys: String): Long = 0

  override suspend fun exists(key: String): Long = 0

  override suspend fun keys(pattern: String): List<String> = emptyList()

  override suspend fun incr(key: String): Long = 0

  override suspend fun expire(key: String, seconds: Long): Boolean = true

  override suspend fun pTtl(key: String): Long = -2

  override suspend fun zadd(key: String, score: Double, member: String): Long = 0

  override suspend fun zremRangeByScore(key: String, min: String, max: String): Long = 0

  override suspend fun zcard(key: String): Long = 0

  override suspend fun zrangeWithScores(key: String): List<Pair<String, String>> = emptyList()

  override suspend fun evalSha(sha: String, keys: List<String>, argv: List<String>): Long = 0

  override suspend fun scriptLoad(script: String): String? = null

  override suspend fun ping(): Boolean = true

  override suspend fun transaction(ops: suspend (QueuedRedisOperations) -> Unit): List<Any?> {
    ops(NoopQueuedRedisOperations)
    return emptyList()
  }

  override suspend fun scan(match: String): List<String> = emptyList()

  override fun close() {}
}

/** The no-op queued view used by [NoopRedisOperations]. */
public object NoopQueuedRedisOperations : QueuedRedisOperations {
  override suspend fun incr(key: String) {}

  override suspend fun expire(key: String, seconds: Long) {}

  override suspend fun zadd(key: String, score: Double, member: String) {}

  override suspend fun zremRangeByScore(key: String, min: String, max: String) {}

  override suspend fun zcard(key: String) {}

  override suspend fun get(key: String) {}

  override suspend fun pTtl(key: String) {}

  override suspend fun setEx(key: String, value: String, ttlSeconds: Long) {}

  override suspend fun del(vararg keys: String) {}

  override fun close() {}
}

/** redis_retries config for the resilience ports. */
private class SecurityConfigBuilderForTest {
  fun build(): com.guardcore.config.SecurityConfig =
      com.guardcore.config
          .SecurityConfigBuilder()
          .apply {
            redisUrl = TEST_REDIS_URL
            redisPrefix = uniqueRedisPrefix()
            redisRetries = 2
            enableRedis = true
          }
          .build()
}
