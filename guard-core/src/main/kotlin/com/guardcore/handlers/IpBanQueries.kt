package com.guardcore.handlers

import com.guardcore.util.IpExtraction
import com.guardcore.util.py.IpAddress
import com.guardcore.util.py.parseAddress

/**
 * Port of `guard_core/handlers/_ipban_queries.py` (IpBanQueryMixin) as extensions over
 * [IpBanManager].
 */

/** Port of `_check_network_cache` (_ipban_queries.py:17): prune expired, keep active order. */
public fun IpBanManager.checkNetworkCache(addr: IpAddress, now: Double): Boolean {
  val active = mutableListOf<Pair<com.guardcore.util.py.IpNetwork, Double>>()
  var hit = false
  for ((network, expiry) in bannedNetworks) {
    if (expiry <= now) continue
    active.add(network to expiry)
    if (!hit && addr.version == network.version && network.contains(addr)) {
      hit = true
    }
  }
  bannedNetworks = active
  return hit
}

/** Port of `_check_redis_exact` (_ipban_queries.py:31). */
public suspend fun IpBanManager.checkRedisExact(ip: String, currentTime: Double): Boolean {
  val redis = redisHandler ?: return false
  val expiry = redis.getKey("banned_ips", ip)
  if (expiry == null || expiry == false) {
    return false
  }
  val expiryTime = (expiry as? Number)?.toDouble() ?: expiry.toString().toDouble()
  if (currentTime <= expiryTime) {
    bannedIps[ip] = expiryTime
    return true
  }
  redis.delete("banned_ips", ip)
  return false
}

/** Port of `_purge_banned_ip` (_ipban_queries.py:42). */
public fun IpBanManager.purgeBannedIp(ip: String) {
  bannedIps.remove(ip)
}

/** Port of `is_ip_banned` (_ipban_queries.py:48). */
public suspend fun IpBanManager.isIpBanned(ip: String): Boolean {
  val canonical = IpExtraction.canonicalizeIp(ip)
  val currentTime = nowSeconds()

  val expiry = bannedIps.get(canonical)
  if (expiry != null) {
    if (currentTime > expiry) {
      purgeBannedIp(canonical)
      return false
    }
    return true
  }

  val addr =
      try {
        parseAddress(canonical)
      } catch (e: Exception) {
        return false
      }

  if (checkNetworkCache(addr, currentTime)) {
    return true
  }

  if (redisHandler != null) {
    return checkRedisExact(canonical, currentTime)
  }

  return false
}

/** Port of `unban_ip` (_ipban_queries.py:72). */
public suspend fun IpBanManager.unbanIp(ip: String) {
  val canonical = IpExtraction.canonicalizeIp(ip)
  purgeBannedIp(canonical)

  redisHandler?.delete("banned_ips", canonical)

  if (agentHandler != null) {
    sendUnbanEvent(canonical)
  }
}

/** Port of `reset` (_ipban_queries.py:82). */
public suspend fun IpBanManager.reset() {
  bannedIps.clear()
  bannedNetworks.clear()
  val redis = redisHandler
  if (redis != null) {
    // python uses the raw connection here (conn.keys with the embedded prefix).
    val keys =
        (redis.getConnection().client as? RedisOperations)?.keys(
            "${redisPrefixOf(redis)}banned_ips:*",
        )
    if (!keys.isNullOrEmpty()) {
      (redis.getConnection().client as? RedisOperations)?.del(*keys.toTypedArray())
    }
  }
}

/**
 * Python accesses `redis_handler.config.redis_prefix` duck-typed at the reset call sites
 * (_ipban_queries.py:88, _security_headers_cache.py:122). The JVM port resolves it from
 * [RedisManager] or an explicit [RedisPrefixProvider]; the default is the reference prefix.
 */
public fun redisPrefixOf(redis: com.guardcore.protocols.RedisHandlerProtocol): String =
    when (redis) {
      is RedisManager -> redis.config.redisPrefix
      is RedisPrefixProvider -> redis.redisPrefix
      else -> "guard_core:"
    }

/** Duck-type hook for test fakes that carry a config prefix. */
public interface RedisPrefixProvider {
  public val redisPrefix: String
}
