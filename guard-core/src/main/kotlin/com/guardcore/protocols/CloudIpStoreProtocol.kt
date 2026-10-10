package com.guardcore.protocols

/**
 * Port of `guard_core/protocols/cloud_ip_store_protocol.py` (cloud_ip_store_protocol.py:9): cache
 * of cloud-provider IP ranges consulted by the cloud-IP check.
 */
public interface CloudIpStoreProtocol {
  /** Python async `get` (cloud_ip_store_protocol.py:21). */
  public suspend fun get(provider: String): Set<String>?

  /** Python async `set` (cloud_ip_store_protocol.py:24). */
  public suspend fun set(provider: String, ranges: Set<String>, ttl: Int? = null)

  /** Python async `clear` (cloud_ip_store_protocol.py:28). */
  public suspend fun clear()
}

/**
 * Port of the `CloudIpStoreFactory` alias (cloud_ip_store_protocol.py:31): a callable taking the
 * Redis handler and returning a store.
 */
public typealias CloudIpStoreFactory = (RedisHandlerProtocol) -> CloudIpStoreProtocol
