package com.guardcore.protocols

/**
 * Port of `guard_core/protocols/geo_ip_protocol.py` (geo_ip_protocol.py:6): resolver that maps an
 * IP address to a country for geo-based rules.
 */
public interface GeoIPHandler {
  /** Python property `is_initialized` (geo_ip_protocol.py:20). */
  public val isInitialized: Boolean

  /** Python async `initialize` (geo_ip_protocol.py:23). */
  public suspend fun initialize()

  /** Python async `initialize_redis` (geo_ip_protocol.py:26). */
  public suspend fun initializeRedis(redisHandler: RedisHandlerProtocol)

  /** Python async `initialize_agent` (geo_ip_protocol.py:29). */
  public suspend fun initializeAgent(agentHandler: AgentHandlerProtocol)

  /** Python sync `get_country` (geo_ip_protocol.py:32). */
  public fun getCountry(ip: String): String?

  /** Python async `refresh` (geo_ip_protocol.py:35). */
  public suspend fun refresh()

  /** Python sync `close` (geo_ip_protocol.py:38). */
  public fun close()
}
