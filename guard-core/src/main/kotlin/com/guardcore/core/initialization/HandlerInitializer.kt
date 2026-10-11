package com.guardcore.core.initialization

import com.guardcore.config.SecurityConfig
import com.guardcore.core.events.AgentTelemetryMember
import com.guardcore.core.events.CompositeAgentHandler
import com.guardcore.core.events.EnrichmentContext
import com.guardcore.core.events.EventEnricher
import com.guardcore.core.events.EventFilter
import com.guardcore.core.events.MetricsCollector
import com.guardcore.core.events.SecurityEventBus
import com.guardcore.core.events.SinkTelemetryMember
import com.guardcore.errors.GuardRedisError
import com.guardcore.handlers.BehaviorTracker
import com.guardcore.handlers.CloudIpStore
import com.guardcore.handlers.CloudManager
import com.guardcore.handlers.DynamicRuleManager
import com.guardcore.handlers.HandlerAgentSink
import com.guardcore.handlers.IpBanManager
import com.guardcore.handlers.RateLimitManager
import com.guardcore.handlers.RedisManager
import com.guardcore.handlers.SecurityHeadersManager
import com.guardcore.handlers.SusPatternsRegistry
import com.guardcore.handlers.initializeBanAgent
import com.guardcore.handlers.initializeBanRedis
import com.guardcore.protocols.GeoIPHandler
import java.util.logging.Logger

/**
 * Port of `guard_core/core/initialization/_handler_initializer_steps.py`
 * (_handler_initializer_steps.py:12) plus `handler_initializer.py:15`: HandlerInitializer wires the
 * handlers to redis/agent and builds the event-filter/bus/metrics trio.
 *
 * W4b events port: [buildEnricher] constructs the real `EventEnricher` (handler_initializer.py:58)
 * and [buildCompositeHandler] composes the real member-handler ports (otel/logfire; the python
 * factory appends OtelHandler/LogfireHandler at handler_initializer.py:93-100). The W4a explicit
 * raise is kept: opentelemetry/logfire are not part of guard-core's dependency set, so requesting
 * them through the default composition raises NamingW4bContractError-style IllegalStateException
 * naming the missing packages instead of silently skipping; a host that provides the SDK surface
 * registers a [compositeMemberFactory] (or installs the `core.events` surface seams) and the real
 * member handlers compose.
 */
public class HandlerInitializer(
    public val config: SecurityConfig,
    public val redisHandler: Any? = null,
    public val agentHandler: Any? = null,
    public val geoIpHandler: Any? = null,
    public val rateLimitHandler: Any? = null,
    public val guardDecorator: Any? = null,
) {
  public var compositeHandler: CompositeAgentHandler? = null
  public var eventFilter: EventFilter? = null
  public var enricher: EventEnricher? = null
  public var behaviorTracker: BehaviorTracker? = null
  public var lazyInitTask: java.util.concurrent.CompletableFuture<Void>? = null
  public val logger: Logger = Logger.getLogger("guard_core.core.initialization")

  /**
   * The composite member factory (handler_initializer.py:93-100): given the composed members and
   * the config, returns the additional member handlers. The default returns otel/logfire members
   * when requested and raises explicitly while their SDKs are absent from the dependency set
   * (the W4a contract, kept); hosts that provide the `core.events` SDK surfaces register their own
   * factory composing the real [OtelHandler]/[LogfireHandler] members.
   */
  public var compositeMemberFactory:
      ((
          members: List<AgentTelemetryMember>,
          config: SecurityConfig,
      ) -> List<AgentTelemetryMember>)? =
      null

  /** Python `get_initialization_status` (handler_initializer.py:38). */
  public fun getInitializationStatus(): Map<String, Any?> {
    val geoStatus: Map<String, Any?>? =
        when (val geo = geoIpHandler) {
          null -> null
          is GeoIPHandler ->
              mapOf(
                  "ready" to geo.isInitialized,
                  "last_refreshed" to null,
                  "entries" to 0,
              )
          else -> runCatching {
                @Suppress("UNCHECKED_CAST")
                geo.javaClass.getMethod("getStatus").invoke(geo) as Map<String, Any?>
              }
                  .getOrNull()
        }
    return linkedMapOf(
        "cloud_providers" to CloudManager.getInstance().getStatus(),
        "geo_ip" to geoStatus,
    )
  }

  /** Python `build_enricher` (handler_initializer.py:58): the real EventEnricher construction. */
  public fun buildEnricher(): EventEnricher? {
    if (!config.enableEnrichment) {
      return null
    }
    var dynamicRuleHandler: com.guardcore.handlers.DynamicRuleManager? = null
    if (config.enableDynamicRules) {
      dynamicRuleHandler = com.guardcore.handlers.DynamicRuleManager(config)
    }
    var tracker = (guardDecorator as? com.guardcore.decorators.BaseSecurityDecorator)?.behaviorTracker
    if (tracker == null) {
      tracker = BehaviorTracker(config)
    }
    behaviorTracker = tracker
    return EventEnricher(
        EnrichmentContext(
            config = config,
            agentHandler = agentHandler,
            dynamicRuleHandler = dynamicRuleHandler,
            behaviorTracker = tracker,
        ),
    )
  }

  /** Python `build_composite_handler` (handler_initializer.py:87). */
  public fun buildCompositeHandler(): CompositeAgentHandler {
    val members = mutableListOf<AgentTelemetryMember>()
    (agentHandler as? HandlerAgentSink)?.let { members.add(SinkTelemetryMember(it)) }
    if (config.enableOtel || config.enableLogfire) {
      // The python factory appends OtelHandler/LogfireHandler (handler_initializer.py:93-100);
      // the JVM mirrors the construction through the factory seam. The default raises explicitly
      // while the otel/logfire SDKs are absent (the W4a contract, kept); a host providing the
      // `core.events` SDK surfaces registers a factory composing the real member handlers.
      val extra =
          compositeMemberFactory?.invoke(members.toList(), config)
              ?: throw IllegalStateException(
                  "enable_otel/enable_logfire requested but the opentelemetry-sdk/logfire " +
                      "packages are not part of guard-core's dependency set; install the SDK " +
                      "surface and register a compositeMemberFactory (KNOWN_GAPS G-11/W4b contract)",
              )
      members.addAll(extra)
    }
    eventFilter = buildEventFilter()
    enricher = buildEnricher()
    return CompositeAgentHandler(members, eventFilter = eventFilter!!, enricher = enricher)
  }

  /** Python `build_event_filter` (handler_initializer.py:107). */
  public fun buildEventFilter(): EventFilter =
      EventFilter(
          mutedEventTypes = config.mutedEventTypes.toSet(),
          mutedMetricTypes = config.mutedMetricTypes.toSet(),
      )

  /** Python `build_event_bus` (handler_initializer.py:115). */
  public fun buildEventBus(geoIpHandler: Any? = null): SecurityEventBus {
    if (compositeHandler == null || eventFilter == null) {
      throw IllegalStateException("Call initializeAgentIntegrations() before buildEventBus().")
    }
    return SecurityEventBus(
        agentHandler = agentHandler as? HandlerAgentSink ?: compositeSink(),
        config = config,
        geoIpHandler = (geoIpHandler ?: this.geoIpHandler) as? GeoIPHandler,
        eventFilter = eventFilter!!,
    )
  }

  /** Python `build_metrics_collector` (handler_initializer.py:129). */
  public fun buildMetricsCollector(): MetricsCollector {
    if (compositeHandler == null || eventFilter == null) {
      throw IllegalStateException(
          "Call initializeAgentIntegrations() before buildMetricsCollector().",
      )
    }
    return MetricsCollector(
        agentHandler = agentHandler as? HandlerAgentSink ?: compositeSink(),
        config = config,
        eventFilter = eventFilter!!,
    )
  }

  private fun compositeSink(): HandlerAgentSink? {
    val composite = compositeHandler ?: return null
    return object : HandlerAgentSink {
      override suspend fun sendEvent(event: Map<String, Any?>) {
        composite.sendEvent(event)
      }
    }
  }

  /** The composite handler as the agent protocol (python passes the composite as agent_handler). */
  private fun compositeSinkAgentProtocol(): com.guardcore.protocols.AgentHandlerProtocol? {
    val composite = compositeHandler ?: return null
    return object : com.guardcore.protocols.AgentHandlerProtocol {
      override suspend fun initializeRedis(
          redisHandler: com.guardcore.protocols.RedisHandlerProtocol,
      ) {
        composite.initializeRedis(redisHandler)
      }

      override suspend fun sendEvent(event: Any?) {
        @Suppress("UNCHECKED_CAST")
        composite.sendEvent((event as? Map<String, Any?>) ?: mapOf<String, Any?>())
      }

      override suspend fun sendMetric(metric: Any?) {
        @Suppress("UNCHECKED_CAST")
        composite.sendMetric((metric as? Map<String, Any?>) ?: mapOf<String, Any?>())
      }

      override suspend fun start() {
        composite.start()
      }

      override suspend fun stop() {
        composite.stop()
      }

      override suspend fun flushBuffer() {
        composite.flushBuffer()
      }

      override suspend fun getDynamicRules(): Any? = composite.getDynamicRules()

      override suspend fun healthCheck(): Boolean = composite.healthCheck()
    }
  }

  // ---- _handler_initializer_steps.py surface ----

  /** Python async `_run_lazy_init` (steps:28). */
  public suspend fun runLazyInit() {
    val cloud = CloudManager.getInstance()
    if (config.blockCloudProviders?.isNotEmpty() == true) {
      try {
        cloud.initializeCloudRedis(
            redisHandler as? RedisManager ?: return,
            config.blockCloudProviders!!,
            ttl = config.cloudIpRefreshInterval,
        )
      } catch (e: Exception) {
        logger.warning("Lazy cloud-IP initialization failed: $e")
      }
    }

    val geo = geoIpHandler as? GeoIPHandler
    if (geo != null) {
      try {
        geo.initializeRedis(redisHandler as? com.guardcore.protocols.RedisHandlerProtocol ?: return)
      } catch (e: Exception) {
        logger.warning("Lazy geo-IP initialization failed: $e")
      }
    }
  }

  /** Python `_resolve_cloud_ip_store` (steps:51): invoke callables, pass stores through. */
  private fun resolveCloudIpStore(): CloudIpStore? {
    val store = config.cloudIpStore ?: return null
    if (store is CloudIpStore) {
      return store
    }
    if (store is Function1<*, *>) {
      @Suppress("UNCHECKED_CAST") val factory = store as (Any?) -> CloudIpStore
      return factory(redisHandler)
    }
    return null
  }

  /** Python `_configure_detection` (steps:61). */
  private fun configureDetection() {
    IpBanManager.getInstance()
    com.guardcore.util.PenetrationDetection.configureDetection(config)
  }

  /** Python `_warn_if_lazy_init_is_inert` (steps:68). */
  private fun warnIfLazyInitIsInert() {
    if (!(config.blockCloudProviders?.isNotEmpty() == true || geoIpHandler != null)) {
      return
    }
    logger.warning(
        "lazy_init has no effect without Redis (enable_redis=True and a redis_handler); " +
            "cloud-IP ranges and the geo-IP database will initialize through their own " +
            "on-demand paths regardless of lazy_init's value.",
    )
  }

  /** Python async `_load_cloud_and_geo_without_redis` (steps:78). */
  public suspend fun loadCloudAndGeoWithoutRedis() {
    val cloud = CloudManager.getInstance()
    if (config.cloudIpStore != null) {
      cloud.store = resolveCloudIpStore()
    }
    if (config.blockCloudProviders?.isNotEmpty() == true) {
      cloud.refresh(config.blockCloudProviders!!)
    }
    (geoIpHandler as? GeoIPHandler)?.initialize()
  }

  /** Python async `_connect_redis` (steps:88). */
  private suspend fun connectRedis(): Boolean {
    val redis = redisHandler as? com.guardcore.protocols.RedisHandlerProtocol
    return try {
      redis?.initialize()
      true
    } catch (e: GuardRedisError) {
      logger.severe("Redis unavailable during initialization: $e")
      if (!config.redisFailOpen) {
        throw e
      }
      false
    }
  }

  /** Python `_guard_decorator_has_behavior_rules` (steps:100). */
  private fun guardDecoratorHasBehaviorRules(): Boolean {
    val decorator = guardDecorator as? com.guardcore.decorators.RouteConfigProvider ?: return false
    return decorator.getRouteConfigs().values.any { it.behaviorRules.isNotEmpty() }
  }

  /** Python async `_initialize_cloud_and_geo_redis` (steps:108). */
  private suspend fun initializeCloudAndGeoRedis() {
    val cloud = CloudManager.getInstance()
    if (config.lazyInit) {
      lazyInitTask =
          java.util.concurrent.CompletableFuture.runAsync {
            kotlinx.coroutines.runBlocking { runLazyInit() }
          }
      return
    }
    if (config.blockCloudProviders?.isNotEmpty() == true) {
      cloud.initializeCloudRedis(
          redisHandler as? RedisManager ?: return,
          config.blockCloudProviders!!,
          ttl = config.cloudIpRefreshInterval,
      )
    }
    (geoIpHandler as? GeoIPHandler)?.initializeRedis(
        redisHandler as? com.guardcore.protocols.RedisHandlerProtocol ?: return,
    )
  }

  /** Python async `_initialize_connected_redis_handlers` (steps:123). */
  private suspend fun initializeConnectedRedisHandlers() {
    val cloud = CloudManager.getInstance()
    if (config.cloudIpStore != null) {
      cloud.store = resolveCloudIpStore()
    }

    initializeCloudAndGeoRedis()
    IpBanManager.getInstance()
        .initializeBanRedis(redisHandler as? com.guardcore.protocols.RedisHandlerProtocol)

    (rateLimitHandler as? RateLimitManager)?.initializeRedis(
        redisHandler as? com.guardcore.protocols.RedisHandlerProtocol,
    )
    SusPatternsRegistry.initializeRedis(
        redisHandler as? com.guardcore.protocols.RedisHandlerProtocol,
    )

    if (guardDecoratorHasBehaviorRules()) {
      (guardDecorator as? com.guardcore.decorators.BaseSecurityDecorator)
          ?.initializeBehaviorTracking(redisHandler)
    }
  }

  /** Python async `initialize_redis_handlers` (steps:141). */
  public suspend fun initializeRedisHandlers() {
    configureDetection()

    if (!(config.enableRedis && redisHandler != null)) {
      if (config.lazyInit) {
        warnIfLazyInitIsInert()
        return
      }
      loadCloudAndGeoWithoutRedis()
      return
    }

    if (!connectRedis()) {
      loadCloudAndGeoWithoutRedis()
      return
    }

    initializeConnectedRedisHandlers()
  }

  /** Python async `initialize_agent_for_handlers` (steps:157). */
  public suspend fun initializeAgentForHandlers() {
    val sink: HandlerAgentSink =
        when (val telemetry = compositeHandler ?: agentHandler) {
          null -> return
          is HandlerAgentSink -> telemetry
          is CompositeAgentHandler ->
              object : HandlerAgentSink {
                override suspend fun sendEvent(event: Map<String, Any?>) {
                  telemetry.sendEvent(event)
                }
              }
          else -> return
        }

    IpBanManager.getInstance().initializeBanAgent(sink)
    (rateLimitHandler as? RateLimitManager)?.initializeAgent(sink)
    SusPatternsRegistry.agentHandler = sink
    SecurityHeadersManager.getInstance().initializeHeadersAgent(sink)

    if (config.blockCloudProviders?.isNotEmpty() == true) {
      CloudManager.getInstance().initializeCloudAgent(sink)
    }

    // AgentHandlerProtocol adapter over the sink (python passes the telemetry handler through).
    val agentProtocol =
        object : com.guardcore.protocols.AgentHandlerProtocol {
          override suspend fun initializeRedis(
              redisHandler: com.guardcore.protocols.RedisHandlerProtocol,
          ) {}

          override suspend fun sendEvent(event: Any?) {
            @Suppress("UNCHECKED_CAST")
            sink.sendEvent((event as? Map<String, Any?>) ?: mapOf<String, Any?>())
          }

          override suspend fun sendMetric(metric: Any?) {
            @Suppress("UNCHECKED_CAST")
            sink.sendEvent((metric as? Map<String, Any?>) ?: mapOf<String, Any?>())
          }

          override suspend fun start() {}

          override suspend fun stop() {}

          override suspend fun flushBuffer() {}

          override suspend fun getDynamicRules(): Any? = null

          override suspend fun healthCheck(): Boolean = true
        }
    (geoIpHandler as? GeoIPHandler)?.initializeAgent(agentProtocol)
  }

  /** Python async `initialize_dynamic_rule_manager` (steps:181). */
  public suspend fun initializeDynamicRuleManager() {
    if (!config.enableDynamicRules) {
      return
    }
    if (agentHandler == null) {
      logger.warning(
          "Dynamic rules enabled but agent unavailable; falling back to static config. " +
              "Dashboard rule updates will not propagate until agent connectivity is restored.",
      )
      return
    }

    val dynamicRuleManager = DynamicRuleManager(config)
    val telemetry = compositeHandler ?: agentHandler

    if (redisHandler != null) {
      dynamicRuleManager.initializeDynamicRuleRedis(redisHandler as? RedisManager)
    }

    dynamicRuleManager.initializeAgent(
        when (telemetry) {
          is HandlerAgentSink ->
              object : DynamicRuleManager.AgentDynamicRulesSource {
                override suspend fun getDynamicRules(): com.guardcore.handlers.DynamicRules? = null

                override suspend fun sendEvent(event: Map<String, Any?>) {
                  telemetry.sendEvent(event)
                }
              }
          is CompositeAgentHandler ->
              object : DynamicRuleManager.AgentDynamicRulesSource {
                override suspend fun getDynamicRules(): com.guardcore.handlers.DynamicRules? =
                    telemetry.getDynamicRules() as? com.guardcore.handlers.DynamicRules

                override suspend fun sendEvent(event: Map<String, Any?>) {
                  telemetry.sendEvent(event)
                }
              }
          else -> null
        },
    )
  }

  /** Python async `initialize_agent_integrations` (steps:202). */
  public suspend fun initializeAgentIntegrations() {
    if (
        agentHandler == null &&
            !config.enableOtel &&
            !config.enableLogfire &&
            !config.enableEnrichment
    ) {
      return
    }

    compositeHandler = buildCompositeHandler()
    eventFilter = buildEventFilter()

    compositeHandler!!.start()

    val redis = redisHandler as? com.guardcore.protocols.RedisHandlerProtocol
    if (redis != null) {
      (compositeHandler as? CompositeAgentHandler)?.initializeRedis(redis)
      (redisHandler as? RedisManager)?.initializeAgent(compositeSink())
    }

    initializeAgentForHandlers()

    (guardDecorator as? com.guardcore.decorators.BaseSecurityDecorator)?.initializeAgent(
        compositeHandler ?: agentHandler,
    )

    initializeDynamicRuleManager()
  }

  /** Python async `shutdown_agent_integrations` (steps:234). */
  public suspend fun shutdownAgentIntegrations() {
    if (compositeHandler == null) {
      return
    }
    compositeHandler!!.stop()
    compositeHandler = null
    eventFilter = null
    enricher = null
  }
}
