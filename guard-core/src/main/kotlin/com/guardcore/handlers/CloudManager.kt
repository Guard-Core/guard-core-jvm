package com.guardcore.handlers

import com.guardcore.config.EventTypes
import com.guardcore.util.py.IpNetwork
import com.guardcore.util.py.parseAddress
import java.time.Instant
import java.util.logging.Logger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Port of `guard_core/handlers/cloud_handler.py` (CloudManager): the cloud-provider IP range cache
 * with in-memory / Redis stores and background single-flight refresh.
 */
public open class CloudManager {
  public companion object {
    /** Python `_CLOUD_HANDLER_NAME` (cloud_handler.py:103). */
    public const val CLOUD_HANDLER_NAME: String = "cloud"

    /** Python `_EMPTY_RANGES_WARNING_COOLDOWN` (cloud_handler.py:119). */
    public const val EMPTY_RANGES_WARNING_COOLDOWN: Double = 300.0

    @Volatile private var instance: CloudManager? = null

    /** Python `CloudManager()` singleton dispatch (cloud_handler.py:121). */
    public fun getInstance(): CloudManager {
      instance?.let {
        return it
      }
      synchronized(this) {
        instance?.let {
          return it
        }
        val created = CloudManager()
        instance = created
        return created
      }
    }

    /** Test seam mirroring `CloudManager._instance = None`. */
    public fun resetInstance() {
      synchronized(this) { instance = null }
    }
  }

  private val logger: Logger = Logger.getLogger("guard_core.handlers.cloud")

  /** Port of `ip_ranges` (cloud_handler.py:108). */
  public val ipRanges: MutableMap<String, Set<IpNetwork>> =
      linkedMapOf(
          "AWS" to linkedSetOf(),
          "GCP" to linkedSetOf(),
          "Azure" to linkedSetOf(),
          "DigitalOcean" to linkedSetOf(),
          "Linode" to linkedSetOf(),
          "Vultr" to linkedSetOf(),
      )

  /** Port of `network_regions` (cloud_handler.py:109). */
  public val networkRegions: MutableMap<String, Map<String, String>> =
      linkedMapOf<String, Map<String, String>>().apply {
        for (provider in ALL_PROVIDERS) this[provider] = linkedMapOf()
      }

  /** Port of `last_updated` (cloud_handler.py:113). */
  public val lastUpdated: MutableMap<String, Instant?> =
      linkedMapOf<String, Instant?>().apply {
        for (provider in ALL_PROVIDERS) this[provider] = null
      }

  @Volatile public var redisHandler: RedisManager? = null

  @Volatile public var agentHandler: HandlerAgentSink? = null

  public var store: CloudIpStore? = InMemoryCloudIpStore()

  private var refreshTask: kotlinx.coroutines.Job? = null

  @Volatile private var refreshInFlight: Boolean = false

  private val refreshLock = Mutex()

  private val emptyRangesWarnedAt = linkedMapOf<String, Double>()

  // python `set_store` (cloud_handler.py:146) is the `store` property setter here.

  /** Port of `schedule_refresh` (cloud_handler.py:149): single-flight background refresh. */
  public suspend fun scheduleRefresh(
      providers: Set<String> = ALL_PROVIDERS,
      ttl: Int = 3600,
      refresh: (suspend () -> Unit)? = null,
  ): Boolean {
    val scope = CoroutineScope(Dispatchers.Default)

    suspend fun runRefresh() {
      try {
        if (refresh == null) {
          refreshAsync(providers, ttl = ttl)
        } else {
          refresh()
        }
      } catch (e: Exception) {
        logger.severe("Background cloud IP refresh failed: $e")
      } finally {
        refreshInFlight = false
      }
    }

    return refreshLock.withLock {
      if (refreshInFlight) {
        return@withLock false
      }
      refreshInFlight = true
      try {
        refreshTask = scope.launch { runRefresh() }
      } catch (e: Exception) {
        logger.severe("Could not schedule cloud IP refresh: $e")
        refreshInFlight = false
        return@withLock false
      }
      true
    }
  }

  /** Port of `_log_range_changes` (cloud_handler.py:191). */
  private fun logRangeChanges(
      provider: String,
      oldRanges: Set<IpNetwork>,
      newRanges: Set<IpNetwork>,
  ) {
    if (oldRanges == newRanges) {
      return
    }
    val added = newRanges - oldRanges
    val removed = oldRanges - newRanges
    logger.info(
        "Cloud IP range update for $provider: +${added.size} added, -${removed.size} removed",
    )
  }

  /**
   * The per-provider fetch step as an open member: the redis_interop harness overrides it with
   * pinned fetched ranges (the python harness patches the fetchers the same way).
   */
  public open suspend fun fetchRanges(
      provider: String,
  ): Pair<Set<IpNetwork>, Map<String, String>> = fetchProviderRanges(provider)

  /** Port of `_refresh_providers` (cloud_handler.py:206). */
  public suspend fun refreshProviders(providers: Collection<String> = ALL_PROVIDERS) {
    for (provider in bareProviderNames(providers)) {
      try {
        val (ranges, regions) = fetchRanges(provider)
        if (ranges.isNotEmpty()) {
          val oldRanges = ipRanges[provider] ?: linkedSetOf()
          logRangeChanges(provider, oldRanges, ranges)
          ipRanges[provider] = ranges
          networkRegions[provider] = regions
          lastUpdated[provider] = Instant.now()
        }
      } catch (e: Exception) {
        logger.severe("Failed to fetch $provider IP ranges: $e")
        ipRanges[provider] = linkedSetOf()
        networkRegions[provider] = linkedMapOf()
      }
    }
  }

  /** Port of `initialize_redis` (cloud_handler.py:223). */
  public suspend fun initializeCloudRedis(
      redisHandler: RedisManager,
      providers: Collection<String> = ALL_PROVIDERS,
      ttl: Int = 3600,
  ) {
    this.redisHandler = redisHandler
    if (store is InMemoryCloudIpStore) {
      store = RedisCloudIpStore(redisHandler)
    }
    refreshAsync(providers, ttl = ttl)
  }

  /** Port of `initialize_agent` (cloud_handler.py:236). */
  public suspend fun initializeCloudAgent(agentHandler: HandlerAgentSink?) {
    this.agentHandler = agentHandler
  }

  /** Port of `refresh` (cloud_handler.py:239). */
  public suspend fun refresh(providers: Collection<String> = ALL_PROVIDERS) {
    if (redisHandler != null) {
      throw IllegalStateException("Use refresh_async() when Redis is enabled")
    }
    refreshProviders(providers)
  }

  /** Port of `refresh_async` (cloud_handler.py:244). */
  public suspend fun refreshAsync(
      providers: Collection<String> = ALL_PROVIDERS,
      ttl: Int = 3600,
  ) {
    if (store == null) {
      refreshProvidersViaRedisHandler(providers, ttl = ttl)
      return
    }

    for (provider in bareProviderNames(providers)) {
      try {
        val storeImpl = store
        if (storeImpl == null) {
          refreshProvidersViaRedisHandler(listOf(provider), ttl = ttl)
          continue
        }
        val cached = storeImpl.get(provider)
        if (cached != null) {
          val (nets, regions) = decodeCached(cached)
          ipRanges[provider] = nets
          networkRegions[provider] = regions
          continue
        }

        val (ranges, regions) = fetchRanges(provider)
        if (ranges.isNotEmpty()) {
          storeImpl.set(provider, encodeCached(ranges, regions), ttl = ttl)
          val oldRanges = ipRanges[provider] ?: linkedSetOf()
          logRangeChanges(provider, oldRanges, ranges)
          ipRanges[provider] = ranges
          networkRegions[provider] = regions
          lastUpdated[provider] = Instant.now()
        }
      } catch (e: Exception) {
        logger.severe("Failed to refresh $provider IP ranges: $e")
        if (provider !in ipRanges) {
          ipRanges[provider] = linkedSetOf()
        }
      }
    }
  }

  /** Port of `_refresh_providers_via_redis_handler` (cloud_handler.py:277). */
  private suspend fun refreshProvidersViaRedisHandler(
      providers: Collection<String>,
      ttl: Int = 3600,
  ) {
    val redis = redisHandler
    if (redis == null) {
      refreshProviders(providers)
      return
    }

    for (provider in bareProviderNames(providers)) {
      try {
        val cachedText = redis.getKey("cloud_ranges_v2", provider)?.toString()
        if (!cachedText.isNullOrEmpty()) {
          val (nets, regions) = decodeCached(cachedText.split(",").toSet())
          ipRanges[provider] = nets
          networkRegions[provider] = regions
          continue
        }

        val (ranges, regions) = fetchRanges(provider)
        if (ranges.isNotEmpty()) {
          redis.setKey(
              "cloud_ranges_v2",
              provider,
              encodeCached(ranges, regions).sorted().joinToString(","),
              ttl = ttl,
          )
          val oldRanges = ipRanges[provider] ?: linkedSetOf()
          logRangeChanges(provider, oldRanges, ranges)
          ipRanges[provider] = ranges
          networkRegions[provider] = regions
          lastUpdated[provider] = Instant.now()
        }
      } catch (e: Exception) {
        logger.severe("Failed to refresh $provider IP ranges: $e")
        if (provider !in ipRanges) {
          ipRanges[provider] = linkedSetOf()
        }
      }
    }
  }

  /** Port of `_warn_empty_ranges` (cloud_handler.py:311). */
  private fun warnEmptyRanges(provider: String) {
    val now = monotonicSeconds()
    val warnedAt = emptyRangesWarnedAt[provider]
    if (warnedAt != null && now - warnedAt < EMPTY_RANGES_WARNING_COOLDOWN) {
      return
    }
    emptyRangesWarnedAt[provider] = now
    logger.warning(
        "Cloud IP ranges for $provider are not populated yet; is_cloud_ip is " +
            "returning not-blocked for every $provider IP until the initial fetch " +
            "completes.",
    )
  }

  /** Port of `is_cloud_ip` (cloud_handler.py:328). */
  public fun isCloudIp(ip: String, providers: Set<String> = ALL_PROVIDERS): Boolean {
    return try {
      val ipObj = parseAddress(ip)
      val (blocked, carveouts) = parseCloudSelectors(providers)
      for (provider in blocked) {
        val ranges = ipRanges[provider] ?: continue
        if (ranges.isEmpty()) {
          warnEmptyRanges(provider)
        }
        val allowedRegions = carveouts[provider]
        val providerRegions = networkRegions[provider] ?: emptyMap()
        for (network in ranges) {
          if (network.contains(ipObj)) {
            if (allowedRegions != null && providerRegions[network.text] in allowedRegions) {
              continue
            }
            return true
          }
        }
      }
      false
    } catch (e: Exception) {
      logger.severe("Invalid IP address: $ip")
      false
    }
  }

  /** Port of `get_status` (cloud_handler.py:351). */
  public fun getStatus(): Map<String, Map<String, Any?>> = ALL_PROVIDERS.associateWith { provider ->
    linkedMapOf(
        "ready" to (ipRanges[provider]?.isNotEmpty() == true),
        "last_refreshed" to lastUpdated[provider],
        "entries" to (ipRanges[provider]?.size ?: 0),
    )
  }

  /** Port of `get_cloud_provider_details` (cloud_handler.py:361). */
  public fun getCloudProviderDetails(
      ip: String,
      providers: Set<String> = ALL_PROVIDERS,
  ): Pair<String, String>? {
    return try {
      val ipObj = parseAddress(ip)
      for (provider in bareProviderNames(providers)) {
        val ranges = ipRanges[provider] ?: continue
        for (network in ranges) {
          if (network.contains(ipObj)) {
            return provider to network.text
          }
        }
      }
      null
    } catch (e: Exception) {
      logger.severe("Invalid IP address: $ip")
      null
    }
  }

  /** Port of `send_cloud_detection_event` (cloud_handler.py:376). */
  public suspend fun sendCloudDetectionEvent(
      ip: String,
      provider: String,
      network: String,
      actionTaken: String = "request_blocked",
  ) {
    if (agentHandler == null) {
      return
    }
    sendCloudEvent(
        eventType = EventTypes.EVENT_CLOUD_BLOCKED,
        ipAddress = ip,
        actionTaken = actionTaken,
        reason = "IP belongs to blocked cloud provider: $provider",
        metadata =
            mapOf(
                "cloud_provider" to provider,
                "network" to network,
            ),
    )
  }

  /** Port of `_send_cloud_event` (cloud_handler.py:397). */
  public suspend fun sendCloudEvent(
      eventType: String,
      ipAddress: String,
      actionTaken: String,
      reason: String,
      metadata: Map<String, Any?> = emptyMap(),
  ) {
    val handler = agentHandler ?: return
    try {
      handler.sendEvent(
          com.guardcore.core.events.securityEventEnvelope(
              eventType = eventType,
              ipAddress = ipAddress,
              actionTaken = actionTaken,
              reason = reason,
              handlerName = CLOUD_HANDLER_NAME,
              metadata = metadata,
          ),
      )
    } catch (e: Exception) {
      logger.severe("Failed to send cloud event to agent: $e")
    }
  }
}

/**
 * Port of `_fetch_provider_ranges` (cloud_handler.py:86): normalizes set-returning fetchers to
 * (ranges, regions) pairs.
 */
public suspend fun fetchProviderRanges(
    provider: String,
): Pair<Set<IpNetwork>, Map<String, String>> {
  val result: Any =
      when (provider) {
        "AWS" -> CloudFetchers.fetchAwsIpRanges()
        "GCP" -> CloudFetchers.fetchGcpIpRanges()
        "Azure" -> CloudAzureFetch.fetchAzureIpRanges()
        "DigitalOcean" -> CloudFetchers.fetchDigitalOceanIpRanges()
        "Linode" -> CloudFetchers.fetchLinodeIpRanges()
        "Vultr" -> CloudFetchers.fetchVultrIpRanges()
        else -> throw IllegalArgumentException("unknown cloud provider $provider")
      }
  return when (result) {
    is Pair<*, *> -> {
      @Suppress("UNCHECKED_CAST")
      (result.first as Set<IpNetwork>) to (result.second as Map<String, String>)
    }
    else -> {
      @Suppress("UNCHECKED_CAST")
      (result as Set<IpNetwork>) to linkedMapOf()
    }
  }
}

/** The CloudIpStore protocol shape lives in CloudIpStores.kt. */
internal fun monotonicSeconds(): Double = System.nanoTime() / 1_000_000_000.0
