package com.guardcore.handlers

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Shared constants of tests/test_ipban_loopback_guard.py. */
public const val TRUSTED_PROXY_EXACT: String = "203.0.113.10"
public const val TRUSTED_PROXY_CIDR: String = "198.51.100.0/24"
public const val TRUSTED_PROXY_MEMBER: String = "198.51.100.42"

/** Ports of tests/test_ipban_loopback_guard.py (19 tests). */
class IpBanLoopbackGuardTest {
  init {
    IpBanManager.resetInstance()
  }

  @Test
  fun banLoopbackIpv4IsRefused() = runTest {
    val manager = ipBanManagerWithConfig()

    captureLogs("guard_core.handlers.ipban", java.util.logging.Level.WARNING) { capture ->
      val result = manager.banIp("127.0.0.1", duration = 300, reason = "threshold_exceeded")

      assertEquals(false, result)
      assertFalse(manager.bannedIps.containsKey("127.0.0.1"))
      assertEquals(false, manager.isIpBanned("127.0.0.1"))
      assertTrue(capture.messages(java.util.logging.Level.WARNING).any { it.contains("127.0.0.1") })
    }
  }

  @Test
  fun banLoopbackIpv6IsRefused() = runTest {
    val manager = ipBanManagerWithConfig()

    captureLogs("guard_core.handlers.ipban", java.util.logging.Level.WARNING) { capture ->
      manager.banIp("::1", duration = 300, reason = "threshold_exceeded")

      assertFalse(manager.bannedIps.containsKey("::1"))
      assertEquals(false, manager.isIpBanned("::1"))
      assertTrue(capture.messages(java.util.logging.Level.WARNING).any { it.contains("::1") })
    }
  }

  @Test
  fun banTrustedProxyMemberIsRefused() = runTest {
    val manager = ipBanManagerWithConfig()

    captureLogs("guard_core.handlers.ipban", java.util.logging.Level.WARNING) { capture ->
      manager.banIp(TRUSTED_PROXY_EXACT, duration = 300, reason = "threshold_exceeded")

      assertFalse(manager.bannedIps.containsKey(TRUSTED_PROXY_EXACT))
      assertEquals(false, manager.isIpBanned(TRUSTED_PROXY_EXACT))
      assertTrue(
          capture.messages(java.util.logging.Level.WARNING).any {
            it.contains(TRUSTED_PROXY_EXACT)
          },
      )
    }
  }

  @Test
  fun banTrustedProxyCidrMemberIsRefused() = runTest {
    val manager = ipBanManagerWithConfig()

    captureLogs("guard_core.handlers.ipban", java.util.logging.Level.WARNING) { capture ->
      manager.banIp(TRUSTED_PROXY_MEMBER, duration = 300, reason = "threshold_exceeded")

      assertFalse(manager.bannedIps.containsKey(TRUSTED_PROXY_MEMBER))
      assertEquals(false, manager.isIpBanned(TRUSTED_PROXY_MEMBER))
      assertTrue(
          capture.messages(java.util.logging.Level.WARNING).any {
            it.contains(TRUSTED_PROXY_MEMBER)
          },
      )
    }
  }

  @Test
  fun banCidrOverlappingLoopbackIsRefused() = runTest {
    val manager = ipBanManagerWithConfig()

    captureLogs("guard_core.handlers.ipban", java.util.logging.Level.WARNING) { capture ->
      val result = manager.banIp("127.0.0.0/8", duration = 300, reason = "threshold_exceeded")

      assertEquals(false, result)
      assertEquals(emptyList(), manager.bannedNetworks)
      assertEquals(false, manager.isIpBanned("127.0.0.5"))
      assertTrue(
          capture.messages(java.util.logging.Level.WARNING).any { it.contains("127.0.0.0/8") },
      )
    }
  }

  @Test
  fun banCidrOverlappingTrustedProxyIsRefused() = runTest {
    val manager = ipBanManagerWithConfig()

    captureLogs("guard_core.handlers.ipban", java.util.logging.Level.WARNING) { capture ->
      manager.banIp(TRUSTED_PROXY_CIDR, duration = 300, reason = "threshold_exceeded")

      assertEquals(emptyList(), manager.bannedNetworks)
      assertEquals(false, manager.isIpBanned(TRUSTED_PROXY_MEMBER))
      assertTrue(
          capture.messages(java.util.logging.Level.WARNING).any { it.contains(TRUSTED_PROXY_CIDR) },
      )
    }
  }

  @Test
  fun banCidrPartiallyOverlappingTrustedProxyIsRefused() = runTest {
    val manager = ipBanManagerWithConfig()

    manager.banIp("198.51.100.128/25", duration = 300, reason = "threshold_exceeded")

    assertEquals(emptyList(), manager.bannedNetworks)
    assertEquals(false, manager.isIpBanned("198.51.100.200"))
  }

  @Test
  fun banLoopbackWithoutAnyConfigIsStillRefused() = runTest {
    val manager = IpBanManager.getInstance()
    manager.redisHandler = null

    manager.banIp("127.0.0.1", duration = 300, reason = "threshold_exceeded")

    assertFalse(manager.bannedIps.containsKey("127.0.0.1"))
    assertEquals(false, manager.isIpBanned("127.0.0.1"))
  }

  @Test
  fun banRefusedTargetNeverReachesRedis() = runTest {
    val manager = IpBanManager.getInstance()
    manager.config = ipbanTestConfig()
    val redis = RecordingRedis()
    manager.redisHandler = redis

    manager.banIp("127.0.0.1", duration = 300, reason = "threshold_exceeded")

    assertEquals(emptyList(), redis.setKeyCalls)
  }

  @Test
  fun banWithMalformedTrustedProxiesEntryDoesNotRaise() = runTest {
    val manager = IpBanManager.getInstance()
    manager.redisHandler = null
    // python uses SimpleNamespace(trusted_proxies=[...]) to bypass model validation; the JVM
    // idiom is the model_copy raw setter (SecurityConfig.__dict__ update).
    val config =
        com.guardcore.config
            .SecurityConfigBuilder()
            .apply {
              trustedProxies = listOf("8.8.8.8")
            }
            .build()
    config.setRawTrustedProxies(listOf("not-an-ip-or-cidr"))
    manager.config = config

    manager.banIp("8.8.8.8", duration = 300, reason = "threshold_exceeded")

    assertEquals(true, manager.isIpBanned("8.8.8.8"))
  }

  @Test
  fun banPublicIpWithConfigStillSucceeds() = runTest {
    val manager = ipBanManagerWithConfig()

    val result = manager.banIp("8.8.8.8", duration = 300, reason = "threshold_exceeded")

    assertEquals(true, result)
    assertEquals(true, manager.isIpBanned("8.8.8.8"))
  }

  @Test
  fun banPublicCidrWithConfigStillSucceeds() = runTest {
    val manager = ipBanManagerWithConfig()

    val result = manager.banIp("8.8.8.0/24", duration = 300, reason = "threshold_exceeded")

    assertEquals(true, result)
    assertEquals(true, manager.isIpBanned("8.8.8.5"))
  }

  @Test
  fun banLoopbackOverCapDurationIsRefusedNotClamped() = runTest {
    val manager = IpBanManager.getInstance()
    manager.redisHandler = null

    captureLogs("guard_core.handlers.ipban", java.util.logging.Level.WARNING) { capture ->
      manager.banIp(
          "127.0.0.1",
          duration = IpBanManager.LOCAL_CACHE_TTL_CAP_SECONDS + 3600,
          reason = "threshold_exceeded",
      )

      assertFalse(manager.bannedIps.containsKey("127.0.0.1"))
      assertEquals(false, manager.isIpBanned("127.0.0.1"))

      val warnings = capture.messages(java.util.logging.Level.WARNING)
      assertEquals(1, warnings.size)
      val message = warnings[0]
      assertTrue(message.contains("loopback"))
      assertFalse(message.contains("clamped"))
      assertFalse(message.contains("shortened"))
    }
  }

  @Test
  fun banPrivateIpv4WarnsButStillBans() = runTest {
    val manager = ipBanManagerWithConfig()

    captureLogs("guard_core.handlers.ipban", java.util.logging.Level.WARNING) { capture ->
      manager.banIp("10.0.0.5", duration = 300, reason = "threshold_exceeded")

      assertEquals(true, manager.isIpBanned("10.0.0.5"))
      assertTrue(
          capture.messages(java.util.logging.Level.WARNING).any {
            it.contains("Banning private IP range") && it.contains("10.0.0.5")
          },
      )
    }
  }

  @Test
  fun banPrivateCidrWarnsButStillBans() = runTest {
    val manager = ipBanManagerWithConfig()

    captureLogs("guard_core.handlers.ipban", java.util.logging.Level.WARNING) { capture ->
      manager.banIp("192.168.0.0/24", duration = 300, reason = "threshold_exceeded")

      assertEquals(true, manager.isIpBanned("192.168.0.10"))
      assertTrue(
          capture.messages(java.util.logging.Level.WARNING).any {
            it.contains("Banning private IP range") && it.contains("192.168.0.0/24")
          },
      )
    }
  }

  @Test
  fun banPrivateIpv6UlaWarnsButStillBans() = runTest {
    val manager = ipBanManagerWithConfig()

    captureLogs("guard_core.handlers.ipban", java.util.logging.Level.WARNING) { capture ->
      manager.banIp("fd00::1", duration = 300, reason = "threshold_exceeded")

      assertEquals(true, manager.isIpBanned("fd00::1"))
      assertTrue(
          capture.messages(java.util.logging.Level.WARNING).any {
            it.contains("Banning private IP range") && it.contains("fd00::1")
          },
      )
    }
  }

  @Test
  fun banPublicIpEmitsNoPrivateWarning() = runTest {
    val manager = ipBanManagerWithConfig()

    captureLogs("guard_core.handlers.ipban", java.util.logging.Level.WARNING) { capture ->
      manager.banIp("8.8.8.8", duration = 300, reason = "threshold_exceeded")

      assertEquals(true, manager.isIpBanned("8.8.8.8"))
      assertFalse(capture.records.any { it.message.contains("Banning private IP range") })
    }
  }

  @Test
  fun banLoopbackDoesNotEmitPrivateWarning() = runTest {
    val manager = ipBanManagerWithConfig()

    captureLogs("guard_core.handlers.ipban", java.util.logging.Level.WARNING) { capture ->
      manager.banIp("127.0.0.1", duration = 300, reason = "threshold_exceeded")

      assertEquals(false, manager.isIpBanned("127.0.0.1"))
      assertTrue(capture.messages(java.util.logging.Level.WARNING).any { it.contains("127.0.0.1") })
      assertFalse(capture.records.any { it.message.contains("Banning private IP range") })
    }
  }

  @Test
  fun banInvalidIpEmitsNoPrivateWarning() = runTest {
    val manager = ipBanManagerWithConfig()

    captureLogs("guard_core.handlers.ipban", java.util.logging.Level.WARNING) { capture ->
      assertFailsWithMessage<IllegalArgumentException> {
        manager.banIp("not-an-ip", duration = 300, reason = "threshold_exceeded")
      }
      assertFalse(capture.records.any { it.message.contains("Banning private IP range") })
    }
  }
}

/**
 * Ports of tests/test_ipban_expiry_race.py (5 tests): the cachetools boundary-timer semantics over
 * the injectable TtlCache clock.
 */
class IpBanExpiryRaceTest {
  init {
    IpBanManager.resetInstance()
  }

  /** Python `_BoundaryTimer` (test_ipban_expiry_race.py:37). */
  private class BoundaryTimer(readings: List<Double>) {
    private val readings = readings.toMutableList()
    public var calls: Int = 0
      private set

    operator fun invoke(): Double {
      val reading = readings[minOf(calls, readings.size - 1)]
      calls += 1
      return reading
    }
  }

  private class RecordingRedisHandler {
    public val getKeyCalls: MutableList<Pair<String, String>> = mutableListOf()
    public val deleteCalls: MutableList<Pair<String, String>> = mutableListOf()
    public val expiries: MutableMap<String, String> = mutableMapOf()

    suspend fun getKey(namespace: String, key: String): String? {
      getKeyCalls.add(namespace to key)
      return expiries[key]
    }

    suspend fun delete(namespace: String, key: String) {
      deleteCalls.add(namespace to key)
    }
  }

  @Test
  fun isIpBannedLiveEntryDecidedWithOneCacheClockRead() = runTest {
    val manager = IpBanManager.getInstance()
    val timer = BoundaryTimer(listOf(0.0, 0.0, 300.0))
    manager.bannedIps = TtlCache(maxsize = 10, ttlSeconds = 300.0, clock = { timer() })
    val redis = RecordingRedisHandler()
    val adapter =
        object : com.guardcore.protocols.RedisHandlerProtocol {
          override suspend fun getKey(namespace: String, key: String): Any? =
              redis.getKey(namespace, key)

          override suspend fun setKey(
              namespace: String,
              key: String,
              value: Any?,
              ttl: Int?,
          ): Boolean? = true

          override suspend fun delete(namespace: String, key: String): Int? {
            redis.delete(namespace, key)
            return 1
          }

          override suspend fun keys(pattern: String): List<String>? = emptyList()

          override suspend fun initialize() {}

          override fun getConnection(): com.guardcore.protocols.GuardRedisConnection =
              object : com.guardcore.protocols.GuardRedisConnection {
                override val client: Any? = null

                override fun close() {}
              }
        }
    manager.redisHandler = adapter

    manager.bannedIps["172.16.10.1"] = nowSeconds() + 60

    assertEquals(true, manager.isIpBanned("172.16.10.1"))
    assertEquals(emptyList(), redis.getKeyCalls)
    assertEquals(2, timer.calls)
  }

  @Test
  fun isIpBannedExpiredAtReadReturnsFalseWithoutRaising() = runTest {
    val manager = IpBanManager.getInstance()
    val timer = BoundaryTimer(listOf(0.0, 300.0))
    manager.bannedIps = TtlCache(maxsize = 10, ttlSeconds = 300.0, clock = { timer() })
    val redis = RecordingRedisHandler()
    val adapter =
        object : com.guardcore.protocols.RedisHandlerProtocol {
          override suspend fun getKey(namespace: String, key: String): Any? =
              redis.getKey(namespace, key)

          override suspend fun setKey(
              namespace: String,
              key: String,
              value: Any?,
              ttl: Int?,
          ): Boolean? = true

          override suspend fun delete(namespace: String, key: String): Int? {
            redis.delete(namespace, key)
            return 1
          }

          override suspend fun keys(pattern: String): List<String>? = emptyList()

          override suspend fun initialize() {}

          override fun getConnection(): com.guardcore.protocols.GuardRedisConnection =
              object : com.guardcore.protocols.GuardRedisConnection {
                override val client: Any? = null

                override fun close() {}
              }
        }
    manager.redisHandler = adapter

    manager.bannedIps["172.16.10.2"] = nowSeconds() + 300

    assertEquals(false, manager.isIpBanned("172.16.10.2"))
    assertEquals(listOf("banned_ips" to "172.16.10.2"), redis.getKeyCalls)
  }

  @Test
  fun isIpBannedStaleEntryPurgedAndReturnsFalse() = runTest {
    val manager = IpBanManager.getInstance()
    manager.redisHandler = null

    manager.bannedIps["172.16.10.3"] = nowSeconds() - 5

    assertEquals(false, manager.isIpBanned("172.16.10.3"))
    assertFalse(manager.bannedIps.containsKey("172.16.10.3"))
  }

  @Test
  fun unbanSurvivesExpiryBetweenMembershipCheckAndDelete() = runTest {
    val manager = IpBanManager.getInstance()
    val timer = BoundaryTimer(listOf(0.0, 0.0, 300.0))
    manager.bannedIps = TtlCache(maxsize = 10, ttlSeconds = 300.0, clock = { timer() })
    val redis = RecordingRedisHandler()
    val adapter =
        object : com.guardcore.protocols.RedisHandlerProtocol {
          override suspend fun getKey(namespace: String, key: String): Any? =
              redis.getKey(namespace, key)

          override suspend fun setKey(
              namespace: String,
              key: String,
              value: Any?,
              ttl: Int?,
          ): Boolean? = true

          override suspend fun delete(namespace: String, key: String): Int? {
            redis.delete(namespace, key)
            return 1
          }

          override suspend fun keys(pattern: String): List<String>? = emptyList()

          override suspend fun initialize() {}

          override fun getConnection(): com.guardcore.protocols.GuardRedisConnection =
              object : com.guardcore.protocols.GuardRedisConnection {
                override val client: Any? = null

                override fun close() {}
              }
        }
    manager.redisHandler = adapter
    val agent = RecordingAgent()
    manager.agentHandler = agent

    manager.bannedIps["172.16.10.4"] = nowSeconds() + 300

    manager.unbanIp("172.16.10.4")

    assertEquals(listOf("banned_ips" to "172.16.10.4"), redis.deleteCalls)
    assertEquals(1, agent.events.size)
  }

  @Test
  fun unbanExpiredEntryIsNoopAndSideEffectsStillRun() = runTest {
    val manager = IpBanManager.getInstance()
    val timer = BoundaryTimer(listOf(0.0, 300.0))
    manager.bannedIps = TtlCache(maxsize = 10, ttlSeconds = 300.0, clock = { timer() })
    val redis = RecordingRedisHandler()
    val adapter =
        object : com.guardcore.protocols.RedisHandlerProtocol {
          override suspend fun getKey(namespace: String, key: String): Any? =
              redis.getKey(namespace, key)

          override suspend fun setKey(
              namespace: String,
              key: String,
              value: Any?,
              ttl: Int?,
          ): Boolean? = true

          override suspend fun delete(namespace: String, key: String): Int? {
            redis.delete(namespace, key)
            return 1
          }

          override suspend fun keys(pattern: String): List<String>? = emptyList()

          override suspend fun initialize() {}

          override fun getConnection(): com.guardcore.protocols.GuardRedisConnection =
              object : com.guardcore.protocols.GuardRedisConnection {
                override val client: Any? = null

                override fun close() {}
              }
        }
    manager.redisHandler = adapter
    val agent = RecordingAgent()
    manager.agentHandler = agent

    manager.bannedIps["172.16.10.5"] = nowSeconds() + 300

    manager.unbanIp("172.16.10.5")

    assertFalse(manager.bannedIps.containsKey("172.16.10.5"))
    assertEquals(listOf("banned_ips" to "172.16.10.5"), redis.deleteCalls)
    assertEquals(1, agent.events.size)
  }
}
