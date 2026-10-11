package com.guardcore.handlers

import com.guardcore.config.EventTypes
import com.guardcore.util.IpExtraction
import com.guardcore.util.py.IPv4Address
import com.guardcore.util.py.IPv6Address
import com.guardcore.util.py.IpNetwork
import com.guardcore.util.py.parseAddress

/**
 * Port of `guard_core/handlers/_ipban_events.py` (IpBanEventMixin) as extensions over
 * [IpBanManager].
 */

/** Python `_IP_BAN_HANDLER_NAME` (_ipban_events.py:5). */
public const val IP_BAN_HANDLER_NAME: String = "ip_ban"

/** Port of `initialize_agent` (_ipban_events.py:12). */
public suspend fun IpBanManager.initializeBanAgent(agentHandler: HandlerAgentSink?) {
  this.agentHandler = agentHandler
}

/** Port of `_send_ban_event` (_ipban_events.py:15). */
public suspend fun IpBanManager.sendBanEvent(ip: String, duration: Int, reason: String) {
  try {
    agentHandler?.sendEvent(
        com.guardcore.core.events.securityEventEnvelope(
            eventType = EventTypes.EVENT_IP_BANNED,
            ipAddress = ip,
            actionTaken = "banned",
            reason = reason,
            handlerName = IP_BAN_HANDLER_NAME,
            metadata = mapOf("duration" to duration),
        ),
    )
  } catch (e: Exception) {
    logger.severe("Failed to send ban event to agent: $e")
  }
}

/** Port of `_send_unban_event` (_ipban_events.py:36). */
public suspend fun IpBanManager.sendUnbanEvent(ip: String) {
  try {
    agentHandler?.sendEvent(
        com.guardcore.core.events.securityEventEnvelope(
            eventType = EventTypes.EVENT_IP_UNBANNED,
            ipAddress = ip,
            actionTaken = "unbanned",
            reason = "dynamic_rule_whitelist",
            handlerName = IP_BAN_HANDLER_NAME,
            metadata = mapOf("action" to "unban"),
        ),
    )
  } catch (e: Exception) {
    logger.severe("Failed to send unban event to agent: $e")
  }
}

/** Python `_LOOPBACK_NETWORKS` (_ipban_bans.py:12): 127.0.0.0/8 and ::1/128. */
public val LOOPBACK_NETWORKS: List<IpNetwork> =
    listOf(IpNetwork.parse("127.0.0.0/8"), IpNetwork.parse("::1/128"))

/** `ipaddress.ip_network(a, strict=False).overlaps(b)` for the guard checks. */
public fun networksOverlap(a: IpNetwork, b: IpNetwork): Boolean {
  if (a.version != b.version) return false
  return networkContainsNetwork(a, b) || networkContainsNetwork(b, a)
}

private fun networkContainsNetwork(outer: IpNetwork, inner: IpNetwork): Boolean =
    when (outer.version) {
      4 -> {
        val netAddr = IPv4Address(inner.networkLow)
        outer.contains(netAddr)
      }
      else -> {
        val netAddr = IPv6Address(inner.networkHigh, inner.networkLow, null)
        outer.contains(netAddr)
      }
    }

/** Port of `IpBanOperationsMixin` (_ipban_bans.py:18) as extensions over [IpBanManager]. */

/** Port of `_assert_positive_duration` (_ipban_bans.py:26). */
public fun IpBanManager.assertPositiveDuration(duration: Int) {
  if (duration <= 0) {
    throw IllegalArgumentException("ban duration must be positive, got $duration")
  }
}

/** Port of `_clamp_to_local_cap` (_ipban_bans.py:30). */
public fun IpBanManager.clampToLocalCap(duration: Int, cause: String): Int {
  if (duration <= IpBanManager.LOCAL_CACHE_TTL_CAP_SECONDS) {
    return duration
  }
  logger.warning(
      "Redis unavailable ($cause): ban shortened from ${duration}s to " +
          "${IpBanManager.LOCAL_CACHE_TTL_CAP_SECONDS}s so protection still applies",
  )
  return IpBanManager.LOCAL_CACHE_TTL_CAP_SECONDS
}

/** Port of `_ban_cidr` (_ipban_bans.py:42). */
public suspend fun IpBanManager.banCidr(ip: String, duration: Int) {
  val network =
      try {
        IpNetwork.parse(ip)
      } catch (e: Exception) {
        throw IllegalArgumentException("Invalid CIDR network '$ip': ${e.message}")
      }

  val redis = redisHandler
  if (redis == null) {
    val clamped = clampToLocalCap(duration, "not configured")
    bannedNetworks.add(network to nowSeconds() + clamped)
    return
  }

  try {
    redis.setKey(
        "banned_networks",
        network.text,
        PyTimeStr.of(nowSeconds() + duration),
        ttl = duration,
    )
  } catch (e: Exception) {
    val clamped = clampToLocalCap(duration, "request failed")
    bannedNetworks.add(network to nowSeconds() + clamped)
  }
}

/** Port of `_ban_exact_ip` (_ipban_bans.py:64). */
public suspend fun IpBanManager.banExactIp(ip: String, duration: Int, reason: String) {
  try {
    parseAddress(ip)
  } catch (e: Exception) {
    throw IllegalArgumentException("Invalid IP address '$ip': ${e.message}")
  }

  var effectiveDuration = duration
  if (redisHandler == null) {
    effectiveDuration = clampToLocalCap(duration, "not configured")
  }

  val expiry = nowSeconds() + effectiveDuration
  bannedIps[ip] = expiry

  val redis = redisHandler
  if (redis != null) {
    try {
      redis.setKey("banned_ips", ip, PyTimeStr.of(expiry), ttl = effectiveDuration)
    } catch (e: Exception) {
      val clamped = clampToLocalCap(effectiveDuration, "request failed")
      bannedIps[ip] = nowSeconds() + clamped
    }
  }

  if (agentHandler != null) {
    sendBanEvent(ip, effectiveDuration, reason)
  }
}

/** Port of `_target_network` (_ipban_bans.py:88). */
public fun IpBanManager.targetNetwork(ip: String): IpNetwork? =
    try {
      if (ip.contains("/")) {
        IpNetwork.parse(ip)
      } else {
        when (val addr = parseAddress(ip)) {
          is IPv4Address -> IpNetwork.parse(addr.text)
          is IPv6Address -> IpNetwork.parse(addr.text)
        }
      }
    } catch (e: Exception) {
      null
    }

/** Port of `_trusted_proxy_networks` (_ipban_bans.py:96). */
public fun IpBanManager.trustedProxyNetworks(): List<IpNetwork> {
  val trustedProxies = config?.trustedProxies ?: emptyList()
  val networks = mutableListOf<IpNetwork>()
  for (entry in trustedProxies) {
    try {
      networks.add(IpNetwork.parse(entry))
    } catch (e: Exception) {
      continue
    }
  }
  return networks
}

/** Port of `_self_dos_refusal_reason` (_ipban_bans.py:106). */
public fun IpBanManager.selfDosRefusalReason(ip: String): String? {
  val target = targetNetwork(ip) ?: return null
  if (LOOPBACK_NETWORKS.any { target.version == it.version && networksOverlap(target, it) }) {
    return "loopback"
  }
  if (trustedProxyNetworks().any { target.version == it.version && networksOverlap(target, it) }) {
    return "trusted_proxy"
  }
  return null
}

/** Port of `_log_refused_ban` (_ipban_bans.py:122). */
public fun IpBanManager.logRefusedBan(ip: String, reason: String) {
  val space = if (reason == "loopback") "loopback" else "a configured trusted proxy"
  logger.warning(
      "Refused to ban $ip: overlaps $space space and would self-DoS this " +
          "deployment. If unexpected, trusted_proxies is likely unset " +
          "behind a reverse proxy; see docs/configuration/security-config.md",
  )
}

/** Port of `_warn_if_private_target` (_ipban_bans.py:132). */
public fun IpBanManager.warnIfPrivateTarget(ip: String) {
  val target = targetNetwork(ip) ?: return
  val isPrivate =
      when (target.version) {
        4 -> IPv4Address(target.networkLow).isPrivate
        else -> IPv6Address(target.networkHigh, target.networkLow, null).isPrivate
      }
  if (!isPrivate) return
  logger.warning(
      "Banning private IP range $ip: if requests reach this service through " +
          "a reverse proxy, this IP may be the proxy and the ban will block ALL " +
          "users. Verify config.trusted_proxies lists the proxy IP(s); see " +
          "docs/configuration/security-config.md",
  )
}

/**
 * Port of `ban_ip` (_ipban_bans.py:146): canonicalize, validate, self-DoS guard, then route to the
 * CIDR or exact path.
 */
public suspend fun IpBanManager.banIp(
    ip: String,
    duration: Int,
    reason: String = "threshold_exceeded",
): Boolean {
  // Test seam mirroring the python harness's `ip_ban_manager.ban_ip = _raising_ban`
  // method-assign fault injection (events_harness.py:383-387); production never sets it.
  banIpOverride?.let { return it(ip, duration, reason) }
  val canonical = IpExtraction.canonicalizeIp(ip)
  assertPositiveDuration(duration)
  val refusal = selfDosRefusalReason(canonical)
  if (refusal != null) {
    logRefusedBan(canonical, refusal)
    return false
  }
  warnIfPrivateTarget(canonical)
  if (canonical.contains("/")) {
    banCidr(canonical, duration)
  } else {
    banExactIp(canonical, duration, reason)
  }
  return true
}

internal fun nowSeconds(): Double = System.currentTimeMillis() / 1000.0

/** Python `str(time.time() + duration)` (float repr) for Redis ban values. */
public object PyTimeStr {
  public fun of(value: Double): String = com.guardcore.util.py.PyJson.floatRepr(value)
}
