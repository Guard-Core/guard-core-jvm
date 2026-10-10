package com.guardcore.handlers

/**
 * Port of the `cachetools.TTLCache` surface the handlers use (guard_core/handlers/_ipban_cache.py,
 * behavior_handler.py:66, security_headers_handler.py:50): bounded size, per-entry TTL, lazy purge
 * of expired entries on access, and eviction of the least-recently-inserted entry when inserting
 * past `maxsize` (cachetools pops the first entry in expiry order, which for the handler call sites
 * is the oldest entry).
 *
 * `clock` is the cachetools `timer` argument (monotonic by default); the boundary tests inject a
 * scripted reading sequence exactly like the python tests (`_BoundaryTimer`,
 * test_ipban_expiry_race.py:37).
 *
 * Eviction through [popItem] invokes [onEvict] when provided (`_ObservableTTLCache.popitem`,
 * _ipban_cache.py:20).
 */
public class TtlCache<K : Any, V : Any>(
    public val maxsize: Int,
    public val ttlSeconds: Double,
    private val onEvict: (() -> Unit)? = null,
    private val clock: (() -> Double)? = null,
) {
  private class Entry<V>(@JvmField var value: V, @JvmField var expiresAt: Double)

  // Insertion-ordered store, mirroring the cachetools underlying dict.
  private val store = LinkedHashMap<K, Entry<V>>()
  private var sequence: Long = 0

  @Synchronized
  public operator fun get(key: K): V? {
    purgeExpired()
    return store[key]?.value
  }

  @Synchronized
  public fun containsKey(key: K): Boolean {
    purgeExpired()
    return store.containsKey(key)
  }

  @Synchronized
  public operator fun set(key: K, value: V) {
    purgeExpired()
    val expiry = nowSeconds() + ttlSeconds
    if (!store.containsKey(key) && store.size >= maxsize) {
      popItem()
    }
    // Re-insert to move the key to insertion-order end (cachetools re-orders
    // on update through its expiry-keyed ordering).
    store.remove(key)
    store[key] = Entry(value, expiry)
    sequence += 1
  }

  @Synchronized
  public fun remove(key: K) {
    purgeExpired()
    store.remove(key)
  }

  /** Port of `TTLCache.popitem`: evicts the first entry in expiry order. */
  @Synchronized
  public fun popItem(): Pair<K, V>? {
    purgeExpired()
    if (store.isEmpty()) {
      throw KeyError("popitem(): dictionary is empty")
    }
    // cachetools orders by (expiry, insertion sequence); for the handler call
    // sites insertion order equals expiry order, so the first entry evicts.
    val first = store.entries.iterator().next()
    val result = first.key to first.value.value
    store.remove(first.key)
    onEvict?.invoke()
    return result
  }

  @Synchronized
  public fun clear() {
    store.clear()
  }

  public val size: Int
    @Synchronized
    get() {
      purgeExpired()
      return store.size
    }

  private fun purgeExpired() {
    if (store.isEmpty()) return
    val now = nowSeconds()
    val it = store.entries.iterator()
    while (it.hasNext()) {
      val entry = it.next()
      if (now >= entry.value.expiresAt) {
        it.remove()
      }
    }
  }

  private fun nowSeconds(): Double = clock?.invoke() ?: (System.nanoTime() / 1_000_000_000.0)
}

/** Python `KeyError` shape for empty-cache popitem. */
public class KeyError(message: String) : Exception(message)

/**
 * Port of `_ObservableTTLCache` (_ipban_cache.py:10): a TTLCache whose popitem evictions are
 * observable. The observability is baked into [TtlCache] via the eviction callback; this typealias
 * keeps the python name visible at call sites.
 */
public typealias ObservableTtlCache<K, V> = TtlCache<K, V>
