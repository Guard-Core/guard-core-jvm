package com.guardcore.decorators

import com.guardcore.config.SecurityConfig
import com.guardcore.core.events.EventTypes
import com.guardcore.core.events.SecurityEventBus
import com.guardcore.handlers.BehaviorTracker
import com.guardcore.handlers.HandlerAgentSink
import com.guardcore.protocols.GeoIPHandler
import com.guardcore.protocols.GuardRequest

/**
 * Port of `guard_core/decorators/base.py` (base.py:61): BaseSecurityDecorator, the shared base the
 * framework decorators subclass. Route-id generation (base.py:84-105) keys on a JVM route key
 * (module/qualname analog) supplied by the caller; the id-reuse owner chain tracks the same key.
 */
public open class BaseSecurityDecorator(
    public val config: SecurityConfig,
) : RouteConfigProvider {
  public val routeConfigMap: MutableMap<String, RouteConfig> = linkedMapOf()

  /**
   * Python `_route_id_owner` (base.py:71): id -> owner key of the function the id was derived from.
   */
  private val routeIdOwner: MutableMap<String, Any> = mutableMapOf()

  private val routeConfigRevisionToken: RouteConfigRevision = RouteConfigRevision()

  public val behaviorTracker: BehaviorTracker = BehaviorTracker(config)

  public var agentHandler: Any? = null

  public var geoIpHandler: Any? = null

  /** Python `route_config_revision` property (base.py:77). */
  public val routeConfigRevision: Int
    get() = routeConfigRevisionToken.value

  /** RouteConfigProvider seam used by the pipeline factory. */
  override fun getRouteConfigs(): Map<String, RouteConfig> = routeConfigMap

  override fun getRevisionValue(): Int = routeConfigRevisionToken.value

  /** Python `get_route_config` (base.py:81). */
  public fun getRouteConfig(routeId: String): RouteConfig? = routeConfigMap[routeId]

  /**
   * Python `_get_route_id` (base.py:84): reuse a stamped id only when THIS instance assigned it to
   * THIS route key; otherwise allocate `key#2`, `key#3`, ... The Python `__wrapped__` owner chain
   * collapses to the single JVM route key (method identity is naturally strong).
   */
  protected fun getRouteId(routeKey: Any): String {
    val routeId = (routeKey as? StampedRoute)?.stampedRouteId
    val ownerChain: MutableList<Any> = mutableListOf(routeKey)
    if (routeId != null && routeId in routeConfigMap && routeIdOwner[routeId] in ownerChain) {
      return routeId
    }
    var candidate = baseRouteKey(routeKey)
    var suffix = 1
    while (candidate in routeConfigMap) {
      suffix += 1
      candidate = "${baseRouteKey(routeKey)}#$suffix"
    }
    return candidate
  }

  private fun baseRouteKey(routeKey: Any): String =
      when (routeKey) {
        is String -> routeKey
        is StampedRoute -> routeKey.routeKey
        else -> routeKey::class.java.name
      }

  /** Python `_ensure_route_config` (base.py:107). */
  public fun ensureRouteConfig(routeKey: Any): RouteConfig {
    val routeId = getRouteId(routeKey)
    var config = routeConfigMap[routeId]
    if (config == null) {
      config = RouteConfig(routeConfigRevisionToken)
      config.enableSuspiciousDetection = this.config.enablePenetrationDetection
      routeConfigMap[routeId] = config
      routeConfigRevisionToken.bump()
    }
    routeIdOwner.putIfAbsent(routeId, routeKey)
    if (routeKey is StampedRoute) {
      routeKey.stampedRouteId = routeId
    }
    return routeConfigMap[routeId]!!
  }

  /** Python `_apply_route_config` (base.py:120). */
  public fun applyRouteConfig(routeKey: Any) {
    val routeId = getRouteId(routeKey)
    if (routeKey is StampedRoute) {
      routeKey.stampedRouteId = routeId
    }
  }

  /** Python async `initialize_behavior_tracking` (base.py:125). */
  public open suspend fun initializeBehaviorTracking(redisHandler: Any? = null) {
    if (redisHandler != null) {
      behaviorTracker.initializeBehaviorRedis(
          redisHandler as com.guardcore.protocols.RedisHandlerProtocol,
      )
    }
  }

  /** Python async `initialize_agent` (base.py:129). */
  public open suspend fun initializeAgent(agentHandler: Any?, geoIpHandler: Any? = null) {
    this.agentHandler = agentHandler
    this.geoIpHandler = geoIpHandler
    behaviorTracker.initializeAgent(agentHandler as? HandlerAgentSink)
  }

  /** Python async `send_decorator_event` (base.py:136): the agent-gated bus re-send. */
  public open suspend fun sendDecoratorEvent(
      eventType: String,
      request: GuardRequest,
      actionTaken: String,
      reason: String,
      decoratorType: String,
      metadata: Map<String, Any?> = emptyMap(),
  ) {
    val handler = agentHandler ?: return

    val eventBus =
        SecurityEventBus(
            agentHandler = handler as? HandlerAgentSink,
            config = config,
            geoIpHandler = geoIpHandler as? GeoIPHandler,
        )
    // Python passes decorator_type as a send_middleware_event kwarg, so it lands in the
    // forwarded metadata (and the model's decorator_type field reads it back out).
    eventBus.sendMiddlewareEvent(
        eventType,
        request,
        actionTaken,
        reason,
        LinkedHashMap(metadata).also { it["decorator_type"] = decoratorType },
    )
  }

  /** Python async `send_access_denied_event` (base.py:164). */
  public open suspend fun sendAccessDeniedEvent(
      request: GuardRequest,
      reason: String,
      decoratorType: String,
      metadata: Map<String, Any?> = emptyMap(),
  ) {
    sendDecoratorEvent(
        EventTypes.EVENT_ACCESS_DENIED,
        request,
        "blocked",
        reason,
        decoratorType,
        metadata,
    )
  }

  /** Python async `send_authentication_failed_event` (base.py:182). */
  public open suspend fun sendAuthenticationFailedEvent(
      request: GuardRequest,
      reason: String,
      authType: String,
      metadata: Map<String, Any?> = emptyMap(),
  ) {
    sendDecoratorEvent(
        EventTypes.EVENT_AUTHENTICATION_FAILED,
        request,
        "blocked",
        reason,
        "authentication",
        LinkedHashMap(metadata).also { it["auth_type"] = authType },
    )
  }

  /** Python async `send_rate_limit_event` (base.py:201). */
  public open suspend fun sendRateLimitEvent(
      request: GuardRequest,
      limit: Int,
      window: Int,
      metadata: Map<String, Any?> = emptyMap(),
  ) {
    sendDecoratorEvent(
        EventTypes.EVENT_RATE_LIMITED,
        request,
        "blocked",
        "Rate limit exceeded: $limit requests per ${window}s",
        "rate_limiting",
        LinkedHashMap(metadata).also {
          it["limit"] = limit
          it["window"] = window
        },
    )
  }

  /** Python async `send_decorator_violation_event` (base.py:221). */
  public open suspend fun sendDecoratorViolationEvent(
      request: GuardRequest,
      violationType: String,
      reason: String,
      metadata: Map<String, Any?> = emptyMap(),
  ) {
    sendDecoratorEvent(
        EventTypes.EVENT_DECORATOR_VIOLATION,
        request,
        "blocked",
        reason,
        violationType,
        metadata,
    )
  }
}

/** JVM idiom for the Python stamped-function surface: a callable carrying `_guard_route_id`. */
public interface StampedRoute {
  public val routeKey: String

  public var stampedRouteId: String?
}

/** Python `get_route_decorator_config` (base.py:240). */
public fun getRouteDecoratorConfig(
    request: GuardRequest,
    decoratorHandler: BaseSecurityDecorator,
): RouteConfig? {
  val routeId = request.state.getAttr("guard_route_id") as? String
  if (routeId != null && routeId.isNotEmpty()) {
    return decoratorHandler.getRouteConfig(routeId)
  }
  return null
}
