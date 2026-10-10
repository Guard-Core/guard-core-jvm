package com.guardcore.handlers

import com.guardcore.protocols.RedisHandlerProtocol

/** Port of `guard_core/handlers/cloud_ip_stores.py`. */

/** The CloudIpStore protocol shape (cloud_handler.py store pair + cloud_ip_stores.py). */
public interface CloudIpStore {
  public suspend fun get(provider: String): Set<String>?

  public suspend fun set(provider: String, ranges: Set<String>, ttl: Int? = null)

  public suspend fun clear()
}

/** Port of `InMemoryCloudIpStore` (cloud_ip_stores.py:8). */
public class InMemoryCloudIpStore : CloudIpStore {
  private val data = linkedMapOf<String, Set<String>>()
  private val expiresAt = linkedMapOf<String, Double>()

  override suspend fun get(provider: String): Set<String>? {
    val expiry = expiresAt[provider]
    if (expiry != null && monotonicSeconds() >= expiry) {
      data.remove(provider)
      expiresAt.remove(provider)
      return null
    }
    val ranges = data[provider] ?: return null
    return ranges.toSet()
  }

  override suspend fun set(provider: String, ranges: Set<String>, ttl: Int?) {
    data[provider] = ranges.toSet()
    if (ttl == null) {
      expiresAt.remove(provider)
    } else {
      expiresAt[provider] = monotonicSeconds() + ttl
    }
  }

  override suspend fun clear() {
    data.clear()
    expiresAt.clear()
  }

  private fun monotonicSeconds(): Double = System.nanoTime() / 1_000_000_000.0
}

/**
 * Port of `RedisCloudIpStore` (cloud_ip_stores.py:38): JSON-blob persistence under the
 * `cloud_ip_v2` namespace (key `{prefix}cloud_ip_v2:{provider}`, sorted-range JSON array).
 */
public class RedisCloudIpStore(
    private val redis: RedisHandlerProtocol,
    private val prefix: String = "cloud_ip_v2",
) : CloudIpStore {
  override suspend fun get(provider: String): Set<String>? {
    val raw = redis.getKey(prefix, provider) ?: return null
    val text = raw.toString()
    val decoded =
        try {
          CloudStoreJson.parseStringList(text)
        } catch (e: Exception) {
          return null
        }
    return decoded.toSet()
  }

  override suspend fun set(provider: String, ranges: Set<String>, ttl: Int?) {
    val payload = CloudStoreJson.dumpSortedStringList(ranges)
    redis.setKey(prefix, provider, payload, ttl = ttl)
  }

  override suspend fun clear() {
    val keys = redis.keys("$prefix:*") ?: return
    if (keys.isEmpty()) {
      return
    }
    for (key in keys) {
      val provider = key.substringAfter("$prefix:", "")
      if (provider.isNotEmpty()) {
        redis.delete(prefix, provider)
      }
    }
  }
}

internal object CloudStoreJson {
  private val json = kotlinx.serialization.json.Json

  /** python `json.dumps(sorted(ranges))` byte-exact (", " separator). */
  fun dumpSortedStringList(values: Set<String>): String =
      PyJsonDumps.dumps(
          kotlinx.serialization.json.JsonArray(
              values.sorted().map { kotlinx.serialization.json.JsonPrimitive(it) },
          ),
      )

  fun parseStringList(payload: String): List<String> {
    val parsed = json.parseToJsonElement(payload)
    if (parsed !is kotlinx.serialization.json.JsonArray) {
      throw IllegalArgumentException("not a json array")
    }
    return parsed.map { (it as kotlinx.serialization.json.JsonPrimitive).content }
  }
}
