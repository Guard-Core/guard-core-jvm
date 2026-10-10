package com.guardcore.util

/**
 * Port of `guard_core/_utils/lru_store.py` (guard_core/_utils/lru_store.py:7): pop an existing
 * value for `key`, or evict the oldest entry (insertion order of the passed map) and create a fresh
 * value when at capacity.
 */
public object LruStore {
  /**
   * Port of `_lru_pop_or_create`. The store is a mutable insertion-ordered map (LinkedHashMap)
   * exactly like the Python MutableMapping call sites use.
   */
  public fun <V> lruPopOrCreate(
      store: MutableMap<String, V>,
      key: String,
      maxSize: Int,
      default: () -> V,
  ): V {
    val existing = store.remove(key)
    if (existing != null) return existing
    if (store.size >= maxSize) {
      val oldestKey = store.keys.iterator().next()
      store.remove(oldestKey)
    }
    return default()
  }
}
