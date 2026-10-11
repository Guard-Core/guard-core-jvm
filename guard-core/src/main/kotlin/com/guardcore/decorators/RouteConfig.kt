package com.guardcore.decorators

import com.guardcore.handlers.BehaviorRule
import com.guardcore.protocols.GuardRequest

/**
 * Port of `guard_core/decorators/route_config.py`: Principal/AuthVerifier aliases
 * (route_config.py:13-14), RouteConfigRevision (route_config.py:17), the revision-tracked
 * containers (_RevisionTrackedContainer family, route_config.py:25-223), the tracked-field
 * registries (route_config.py:226-238) and RouteConfig (route_config.py:241).
 */
public typealias RoutePrincipal = Any?

/** Python `AuthVerifier = Callable[[GuardRequest, str], Any]` (route_config.py:14). */
public fun interface RouteAuthVerifier {
  public fun invoke(request: GuardRequest, credential: String): Any?
}

/** Port of `RouteConfigRevision` (route_config.py:17). */
public class RouteConfigRevision {
  public var value: Int = 0

  public fun bump() {
    value += 1
  }
}

/** Port of `_RevisionTrackedContainer._bump` (route_config.py:28). */
private fun RouteConfigRevision?.bumpIfNotNull() {
  this?.bump()
}

/**
 * Port of `_TrackedList` (route_config.py:33): list mutations bump the owning revision. Only the
 * mutation methods the reference tracks are wrapped; reads go straight through.
 */
public class TrackedList<T>(
    items: Collection<T> = emptyList(),
    private val revision: RouteConfigRevision? = null,
) : MutableList<T> {
  private val backing: MutableList<T> = items.toMutableList()

  private fun bumped(): MutableList<T> {
    revision.bumpIfNotNull()
    return backing
  }

  override val size: Int
    get() = backing.size

  override fun get(index: Int): T = backing[index]

  override fun indexOf(element: T): Int = backing.indexOf(element)

  override fun lastIndexOf(element: T): Int = backing.lastIndexOf(element)

  override fun listIterator(): MutableListIterator<T> = backing.listIterator()

  override fun listIterator(index: Int): MutableListIterator<T> = backing.listIterator(index)

  override fun subList(fromIndex: Int, toIndex: Int): MutableList<T> =
      backing.subList(fromIndex, toIndex)

  override fun iterator(): MutableIterator<T> = backing.iterator()

  override fun contains(element: T): Boolean = backing.contains(element)

  override fun containsAll(elements: Collection<T>): Boolean = backing.containsAll(elements)

  override fun isEmpty(): Boolean = backing.isEmpty()

  override fun add(element: T): Boolean = bumped().add(element)

  override fun add(index: Int, element: T) = bumped().add(index, element)

  override fun addAll(elements: Collection<T>): Boolean = bumped().addAll(elements)

  override fun addAll(index: Int, elements: Collection<T>): Boolean =
      bumped().addAll(index, elements)

  override fun removeAt(index: Int): T = bumped().removeAt(index)

  override fun remove(element: T): Boolean = bumped().remove(element)

  override fun removeAll(elements: Collection<T>): Boolean = bumped().removeAll(elements)

  override fun retainAll(elements: Collection<T>): Boolean = bumped().retainAll(elements)

  override fun clear() = bumped().clear()

  override fun set(index: Int, element: T): T = bumped().set(index, element)
}

/** Port of `_TrackedDict` (route_config.py:100). */
public class TrackedMap<K, V>(
    entries: Map<K, V> = emptyMap(),
    private val revision: RouteConfigRevision? = null,
) : MutableMap<K, V> {
  private val backing: MutableMap<K, V> = entries.toMutableMap()

  private fun bumped(): MutableMap<K, V> {
    revision.bumpIfNotNull()
    return backing
  }

  override val size: Int
    get() = backing.size

  override val keys: MutableSet<K>
    get() = backing.keys

  override val values: MutableCollection<V>
    get() = backing.values

  override val entries: MutableSet<MutableMap.MutableEntry<K, V>>
    get() = backing.entries

  override fun isEmpty(): Boolean = backing.isEmpty()

  override fun containsKey(key: K): Boolean = backing.containsKey(key)

  override fun containsValue(value: V): Boolean = backing.containsValue(value)

  override fun get(key: K): V? = backing[key]

  override fun put(key: K, value: V): V? = bumped().put(key, value)

  override fun remove(key: K): V? = bumped().remove(key)

  override fun putAll(from: Map<out K, V>) = bumped().putAll(from)

  override fun clear() = bumped().clear()
}

/** Port of `_TrackedSet` (route_config.py:147). */
public class TrackedSet<T>(
    items: Collection<T> = emptyList(),
    private val revision: RouteConfigRevision? = null,
) : MutableSet<T> {
  private val backing: MutableSet<T> = items.toMutableSet()

  private fun bumped(): MutableSet<T> {
    revision.bumpIfNotNull()
    return backing
  }

  override val size: Int
    get() = backing.size

  override fun isEmpty(): Boolean = backing.isEmpty()

  override fun contains(element: T): Boolean = backing.contains(element)

  override fun containsAll(elements: Collection<T>): Boolean = backing.containsAll(elements)

  override fun iterator(): MutableIterator<T> = backing.iterator()

  override fun add(element: T): Boolean = bumped().add(element)

  override fun addAll(elements: Collection<T>): Boolean = bumped().addAll(elements)

  override fun remove(element: T): Boolean = bumped().remove(element)

  override fun removeAll(elements: Collection<T>): Boolean = bumped().removeAll(elements)

  override fun retainAll(elements: Collection<T>): Boolean = bumped().retainAll(elements)

  override fun clear() = bumped().clear()
}

/** Port of `_TRACKED_LIST_FIELDS` (route_config.py:226). */
public val TRACKED_LIST_FIELDS: Set<String> =
    setOf("custom_validators", "require_referrer", "allowed_content_types", "blocked_user_agents")

/** Port of `_TRACKED_DICT_FIELDS` (route_config.py:234). */
public val TRACKED_DICT_FIELDS: Set<String> =
    setOf("required_headers", "time_restrictions", "geo_rate_limits")

/** Port of `_TRACKED_SET_FIELDS` (route_config.py:237). */
public val TRACKED_SET_FIELDS: Set<String> = setOf("block_cloud_providers")

/**
 * Port of `RouteConfig` (route_config.py:241): the per-route security configuration with
 * revision-tracked mutation (route_config.py:280-291: every attribute assignment after
 * initialization bumps the revision; the tracked container fields wrap their payload).
 */
public class RouteConfig(public val revision: RouteConfigRevision? = null) {
  public var rateLimit: Int? = null
  public var rateLimitWindow: Int? = null
  public var ipWhitelist: List<String>? = null
  public var ipBlacklist: List<String>? = null
  public var blockedCountries: List<String>? = null
  public var whitelistCountries: List<String>? = null
  public var bypassedChecks: MutableSet<String> = mutableSetOf()
  public var requireHttps: Boolean = false
  public var authRequired: String? = null

  /**
   * The tracked container fields (route_config.py:283-286 init + :265-278 `__setattr__` wrap):
   * every [RouteConfig] holds its container payload in a revision-tracked container from
   * construction, so IN-PLACE mutation (append/put/add) bumps the revision exactly like the
   * reference; assignment wraps the new payload in a tracked container and bumps.
   */
  public var customValidators: MutableList<suspend (GuardRequest) -> Any?> =
      TrackedList(revision = revision)
      set(value) {
        revision.bumpIfNotNull()
        field = TrackedList(value, revision = revision)
      }
  public var blockedUserAgents: MutableList<String> = TrackedList(revision = revision)
      set(value) {
        revision.bumpIfNotNull()
        field = TrackedList(value, revision = revision)
      }
  public var requiredHeaders: MutableMap<String, String> = TrackedMap(revision = revision)
      set(value) {
        revision.bumpIfNotNull()
        field = TrackedMap(value, revision = revision)
      }
  public var behaviorRules: MutableList<BehaviorRule> = mutableListOf()
  public var blockCloudProviders: MutableSet<String> = TrackedSet(revision = revision)
      set(value) {
        revision.bumpIfNotNull()
        field = TrackedSet(value, revision = revision)
      }
  public var maxRequestSize: Int? = null
  public var allowedContentTypes: List<String>? = null
      set(value) {
        revision.bumpIfNotNull()
        field = value?.let { TrackedList(it, revision = revision) }
      }
  public var timeRestrictions: Map<String, String>? = null
      set(value) {
        revision.bumpIfNotNull()
        field = value?.let { TrackedMap(value, revision = revision) }
      }
  public var enableSuspiciousDetection: Boolean = true
  public var requireReferrer: List<String>? = null
      set(value) {
        revision.bumpIfNotNull()
        field = value?.let { TrackedList(it, revision = revision) }
      }
  public var apiKeyRequired: Boolean = false
  public var authVerifier: RouteAuthVerifier? = null
  public var apiKeyVerifier: RouteAuthVerifier? = null
  public var apiKeyHeader: String? = null
  public var authorizationHeaderRequired: String? = null
  public var geoRateLimits: Map<String, Pair<Int, Int>>? = null
      set(value) {
        revision.bumpIfNotNull()
        field = value?.let { TrackedMap(value, revision = revision) }
      }
  public var excludedDetectionHeaders: Set<String>? = null
  public var excludedDetectionParams: Set<String>? = null
  public var excludedDetectionBodyFields: Set<String>? = null
  public var enabledDetectionCategories: Set<String>? = null
  public var detectionScanBody: Boolean? = null

  private var initialized: Boolean = false

  init {
    initialized = true
  }

  /**
   * Port of the `__setattr__` revision bump (route_config.py:288-291): attribute writes after
   * initialization bump the revision. Kotlin callers go through [touch] after direct field
   * assignment; the tracked containers bump themselves.
   */
  public fun touch() {
    if (initialized) revision.bumpIfNotNull()
  }
}
