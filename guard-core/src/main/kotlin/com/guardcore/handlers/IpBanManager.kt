package com.guardcore.handlers

import com.guardcore.config.SecurityConfig
import com.guardcore.protocols.RedisHandlerProtocol
import com.guardcore.util.py.IpNetwork
import java.util.logging.Logger

/**
 * Port of `guard_core/handlers/ipban_handler.py` (IPBanManager): the singleton IP ban state over a
 * local TTL cache plus the Redis `banned_ips` namespace.
 *
 * The Python class composes `IpBanMigrationMixin` (mixin file -> [com.guardcore.handlers]
 * ipbanMigrationExtensions), `IpBanOperationsMixin` (ipbanBansExtensions) and `IpBanQueryMixin`
 * (ipbanQueriesExtensions); the JVM port keeps one class with those method groups ported
 * file-for-file in their respective Kotlin files as extensions over this manager.
 */
public class IpBanManager private constructor() {
  public companion object {
    /** Port of `LOCAL_CACHE_TTL_CAP_SECONDS` (ipban_handler.py:30). */
    public const val LOCAL_CACHE_TTL_CAP_SECONDS: Int = 3600

    /** Port of `_EVICTION_LOG_EVERY` (ipban_handler.py:31). */
    public const val EVICTION_LOG_EVERY: Int = 100

    @Volatile private var instance: IpBanManager? = null

    /** Python `IPBanManager()` singleton dispatch (ipban_handler.py:42). */
    public fun getInstance(): IpBanManager {
      val existing = instance
      if (existing != null) return existing
      synchronized(this) {
        val again = instance
        if (again != null) return again
        val created = IpBanManager()
        instance = created
        return created
      }
    }

    /** Test seam mirroring `IPBanManager._instance = None`. */
    public fun resetInstance() {
      synchronized(this) { instance = null }
    }
  }

  public val logger: Logger = Logger.getLogger("guard_core.handlers.ipban")

  /** Port of `banned_ips` (ipban_handler.py:34): ip -> wall-clock expiry. */
  public var bannedIps: TtlCache<String, Double> =
      TtlCache(
          maxsize = 10000,
          ttlSeconds = LOCAL_CACHE_TTL_CAP_SECONDS.toDouble(),
          onEvict = { onEviction() },
      )

  /** Port of `banned_networks` (ipban_handler.py:35): (network, expiry) pairs. */
  public var bannedNetworks: MutableList<Pair<IpNetwork, Double>> = mutableListOf()

  public var evictionsCount: Int = 0
    private set

  public var config: SecurityConfig? = null

  @Volatile public var redisHandler: RedisHandlerProtocol? = null

  @Volatile public var agentHandler: HandlerAgentSink? = null

  /**
   * Test seam mirroring the python harness's `ip_ban_manager.ban_ip = _raising_ban`
   * method-assign fault injection (events_harness.py:383-387); production never sets it.
   */
  @Volatile
  public var banIpOverride: (suspend (ip: String, duration: Int, reason: String) -> Boolean)? =
      null

  /** Port of `_on_eviction` (ipban_handler.py:57). */
  public fun onEviction() {
    evictionsCount += 1
    if (evictionsCount % EVICTION_LOG_EVERY == 0) {
      logger.warning(
          "IP ban cache full; $evictionsCount entries evicted (silent overflow)",
      )
    }
  }

  /** Swap the local cache (test seam mirroring `manager.banned_ips = _ObservableTTLCache(...)`). */
  public fun swapBannedIpsCache(
      maxsize: Int,
      ttlSeconds: Double = LOCAL_CACHE_TTL_CAP_SECONDS.toDouble(),
  ) {
    bannedIps = TtlCache(maxsize = maxsize, ttlSeconds = ttlSeconds, onEvict = { onEviction() })
  }

  internal fun resetEvictions() {
    evictionsCount = 0
  }
}

/**
 * Port of `reset_global_state` (ipban_handler.py:69): clears the singleton state and swaps in a
 * fresh manager reference.
 */
public suspend fun resetIpBanGlobalState() {
  val manager = IpBanManager.getInstance()
  manager.bannedIps.clear()
  manager.bannedNetworks = mutableListOf()
  manager.resetEvictions()
  manager.redisHandler = null
  manager.agentHandler = null
}
