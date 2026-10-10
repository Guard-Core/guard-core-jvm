package com.guardcore.handlers

import com.guardcore.protocols.GuardRedisConnection
import com.guardcore.protocols.RedisHandlerProtocol
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Ports of tests/test_ipban_legacy_key_migration.py (9 tests, live Redis). */
class IpBanLegacyKeyMigrationTest {
  init {
    IpBanManager.resetInstance()
  }

  private suspend fun newRedis(): RedisManager {
    val redis = RedisManager.getInstance(securityConfigRedis())
    redis.initialize()
    return redis
  }

  private suspend fun seedLegacyBan(redis: RedisManager, duration: Int = 60) {
    val manager = IpBanManager.getInstance()
    manager.initializeBanRedis(redis)
    manager.banExactIp(LEGACY_MAPPED_FORM, duration, "test_legacy_ban")
    manager.bannedIps.clear()
  }

  @Test
  fun migrationBlocksCanonicalRequestAfterRestart() = runTest {
    val redis = newRedis()
    try {
      seedLegacyBan(redis)

      val manager = IpBanManager.getInstance()
      manager.bannedIps.clear()
      IpBanManager.getInstance().initializeBanRedis(redis)
      manager.bannedIps.clear()

      assertEquals(true, manager.isIpBanned(CANONICAL_FORM))
    } finally {
      val manager = IpBanManager.getInstance()
      manager.unbanIp(CANONICAL_FORM)
      manager.redisHandler = null
      redis.close()
    }
  }

  @Test
  fun migrationPreservesRemainingTtlWithinOneSecond() = runTest {
    val redis = newRedis()
    try {
      seedLegacyBan(redis, duration = 60)

      IpBanManager.getInstance().initializeBanRedis(redis)

      val prefix = redis.config.redisPrefix
      val pttl = redis.operations()!!.pTtl("${prefix}banned_ips:$CANONICAL_FORM")
      assertTrue(pttl in (60_000 - 1_000)..(60_000 + 1_000), "pttl was $pttl")
    } finally {
      val manager = IpBanManager.getInstance()
      manager.unbanIp(CANONICAL_FORM)
      manager.redisHandler = null
      redis.close()
    }
  }

  @Test
  fun migrationDeletesTheLegacyKey() = runTest {
    val redis = newRedis()
    try {
      seedLegacyBan(redis)

      IpBanManager.getInstance().initializeBanRedis(redis)

      assertNull(redis.getKey("banned_ips", LEGACY_MAPPED_FORM))
    } finally {
      val manager = IpBanManager.getInstance()
      manager.unbanIp(CANONICAL_FORM)
      manager.redisHandler = null
      redis.close()
    }
  }

  @Test
  fun migrationSecondStartIsIdempotent() = runTest {
    val redis = newRedis()
    try {
      seedLegacyBan(redis)

      IpBanManager.getInstance().initializeBanRedis(redis)

      val prefix = redis.config.redisPrefix
      val canonicalKey = "${prefix}banned_ips:$CANONICAL_FORM"
      val ops = redis.operations()!!
      val valueBefore = ops.get(canonicalKey)
      val pttlBefore = ops.pTtl(canonicalKey)

      IpBanManager.getInstance().initializeBanRedis(redis)

      val valueAfter = ops.get(canonicalKey)
      val pttlAfter = ops.pTtl(canonicalKey)

      assertEquals(valueBefore, valueAfter)
      assertTrue(kotlin.math.abs(pttlAfter - pttlBefore) <= 1_000)
      assertEquals(true, IpBanManager.getInstance().isIpBanned(CANONICAL_FORM))
    } finally {
      val manager = IpBanManager.getInstance()
      manager.unbanIp(CANONICAL_FORM)
      manager.redisHandler = null
      redis.close()
    }
  }

  @Test
  fun rateLimitKeysStayUnmigratedSelfExpireWithin60s() = runTest {
    val redis = newRedis()
    try {
      redis.setKey("rate_limit", "rate:$LEGACY_MAPPED_FORM", "1", ttl = 60)

      IpBanManager.getInstance().initializeBanRedis(redis)

      assertEquals("1", redis.getKey("rate_limit", "rate:$LEGACY_MAPPED_FORM"))
      assertNull(redis.getKey("rate_limit", "rate:$CANONICAL_FORM"))
    } finally {
      redis.delete("rate_limit", "rate:$LEGACY_MAPPED_FORM")
      IpBanManager.getInstance().redisHandler = null
      redis.close()
    }
  }

  @Test
  fun migrationSkippedWhenRedisHandlerIsNone() = runTest {
    val manager = IpBanManager.getInstance()
    IpBanManager.getInstance().initializeBanRedis(null)

    assertNull(manager.redisHandler)
  }

  @Test
  fun migrationWarnsAndContinuesWhenConnectionFails() = runTest {
    val redis = newRedis()
    redis.close()

    captureLogs("guard_core.handlers.ipban", java.util.logging.Level.WARNING) { capture ->
      IpBanManager.getInstance().initializeBanRedis(redis)

      assertTrue(
          capture.messages(java.util.logging.Level.WARNING).any {
            it.contains("Legacy ban-key migration skipped")
          },
      )
    }
    IpBanManager.getInstance().redisHandler = null
  }

  @Test
  fun migrationDeletesAPersistentLegacyKeyWithoutTtl() = runTest {
    val redis = newRedis()
    try {
      val prefix = redis.config.redisPrefix
      val legacyKey = "${prefix}banned_ips:$LEGACY_MAPPED_FORM"
      redis.operations()!!.set(legacyKey, "123456789.0")

      IpBanManager.getInstance().initializeBanRedis(redis)

      assertEquals(0L, redis.operations()!!.exists(legacyKey))
      assertEquals(false, IpBanManager.getInstance().isIpBanned(CANONICAL_FORM))
    } finally {
      IpBanManager.getInstance().redisHandler = null
      redis.close()
    }
  }

  @Test
  fun migrationKeepsTheLongerExpiryWhenCanonicalKeyAlreadyExists() = runTest {
    val redis = newRedis()
    try {
      val manager = IpBanManager.getInstance()
      IpBanManager.getInstance().initializeBanRedis(redis)
      manager.banIp(CANONICAL_FORM, 120, "test_long_canonical_ban")
      manager.banExactIp(LEGACY_MAPPED_FORM, 60, "test_short_legacy_ban")
      manager.bannedIps.clear()

      val prefix = redis.config.redisPrefix
      val canonicalKey = "${prefix}banned_ips:$CANONICAL_FORM"
      val legacyKey = "${prefix}banned_ips:$LEGACY_MAPPED_FORM"
      val ops = redis.operations()!!
      val pttlBefore = ops.pTtl(canonicalKey)

      IpBanManager.getInstance().initializeBanRedis(redis)

      val pttlAfter = ops.pTtl(canonicalKey)
      val legacyExists = ops.exists(legacyKey)

      assertTrue(kotlin.math.abs(pttlAfter - pttlBefore) <= 1_000)
      assertTrue(pttlAfter > 100_000)
      assertEquals(0L, legacyExists)
    } finally {
      val manager = IpBanManager.getInstance()
      manager.unbanIp(CANONICAL_FORM)
      manager.redisHandler = null
      redis.close()
    }
  }

  /** The duck-typed bad-handler halves (python `_BadScanRedisHandler` shape). */
  @Test
  fun migrationClosesAndSkipsNonIterableScanResult() = runTest {
    val handler =
        object : RedisHandlerProtocol {
          var closed = false
            private set

          override suspend fun getKey(namespace: String, key: String): Any? = null

          override suspend fun setKey(
              namespace: String,
              key: String,
              value: Any?,
              ttl: Int?,
          ): Boolean? = true

          override suspend fun delete(namespace: String, key: String): Int? = 0

          override suspend fun keys(pattern: String): List<String>? = emptyList()

          override suspend fun initialize() {}

          override fun getConnection(): GuardRedisConnection =
              object : GuardRedisConnection {
                // python: a scan_iter without __aiter__ -> close + skip. The JVM analog is an
                // operations handle of the wrong type.
                override val client: Any? = "not-redis-operations"

                override fun close() {
                  closed = true
                }
              }

          fun forceClose() {
            closed = true
          }

          val redisPrefix: String = "test:bad-scan:"
        }

    captureLogs("guard_core.handlers.ipban", java.util.logging.Level.WARNING) { capture ->
      IpBanManager.getInstance().initializeBanRedis(handler)
      assertTrue(handler.closed)
      assertTrue(
          capture.messages(java.util.logging.Level.WARNING).any {
            it.contains("Legacy ban-key migration skipped")
          },
      )
    }
    IpBanManager.getInstance().redisHandler = null
  }

  @Test
  fun migrationClosesAndSkipsNonContextManagerConnection() = runTest {
    val handler =
        object : RedisHandlerProtocol {
          var closed = false
            private set

          override suspend fun getKey(namespace: String, key: String): Any? = null

          override suspend fun setKey(
              namespace: String,
              key: String,
              value: Any?,
              ttl: Int?,
          ): Boolean? = true

          override suspend fun delete(namespace: String, key: String): Int? = 0

          override suspend fun keys(pattern: String): List<String>? = emptyList()

          override suspend fun initialize() {}

          // python: get_connection() result without __aenter__ -> close + skip. The JVM analog
          // is a connection whose client is not an operations handle.
          override fun getConnection(): GuardRedisConnection =
              object : GuardRedisConnection {
                override val client: Any? = null

                override fun close() {
                  closed = true
                }
              }

          val redisPrefix: String = "test:bad-connection:"
        }

    captureLogs("guard_core.handlers.ipban", java.util.logging.Level.WARNING) { capture ->
      IpBanManager.getInstance().initializeBanRedis(handler)
      assertTrue(handler.closed)
      assertTrue(
          capture.messages(java.util.logging.Level.WARNING).any {
            it.contains("Legacy ban-key migration skipped")
          },
      )
    }
    IpBanManager.getInstance().redisHandler = null
  }
}

/** tests/test_ipban_legacy_key_migration.py constants. */
public const val LEGACY_MAPPED_FORM: String = "::ffff:203.0.113.5"
public const val CANONICAL_FORM: String = "203.0.113.5"
