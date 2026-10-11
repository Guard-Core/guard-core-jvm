package com.guardcore.core.checks.implementations

import com.guardcore.config.SecurityConfig
import com.guardcore.core.checks.CheckCompanion
import com.guardcore.core.checks.ChecksHelpers
import com.guardcore.core.checks.SecurityCheck
import com.guardcore.core.events.EventTypes
import com.guardcore.decorators.RouteConfig
import com.guardcore.handlers.RateLimitManager
import com.guardcore.protocols.GuardMiddlewareProtocol
import com.guardcore.protocols.GuardRequest
import com.guardcore.protocols.GuardResponse
import com.guardcore.util.RequestLogging

/** Python `_route_rate_limit_configured` (rate_limit.py:26). */
private fun routeRateLimitConfigured(routeConfig: RouteConfig): Boolean =
    routeConfig.rateLimit != null || !routeConfig.geoRateLimits.isNullOrEmpty()

/** Python `_rate_limit_applies` (rate_limit.py:30). */
private fun rateLimitApplies(
    config: SecurityConfig,
    routeConfigs: Collection<RouteConfig>?,
): Boolean =
    config.enableRateLimiting ||
        config.endpointRateLimits.isNotEmpty() ||
        ChecksHelpers.routeConfigApplies(routeConfigs) { routeRateLimitConfigured(it) } ||
        config.enableDynamicRules

/**
 * Port of `guard_core/core/checks/implementations/rate_limit.py`: RateLimitCheck
 * (rate_limit.py:42).
 */
public class RateLimitCheck(
    middleware: GuardMiddlewareProtocol,
) : SecurityCheck(middleware) {
  override val containerFields: List<String> = listOf("endpoint_rate_limits")

  override val enforcedOnExcludedPaths: Boolean = true

  /** Python `__init__` (rate_limit.py:46). */
  private val ipBanManager: com.guardcore.handlers.IpBanManager =
      com.guardcore.handlers.IpBanManager.getInstance()

  override val checkName: String = "rate_limit"

  private val rateLimitHandler: RateLimitManager
    get() = middleware.rateLimitHandler as RateLimitManager

  /** Python async `_send_rate_limit_event` (rate_limit.py:64). */
  private suspend fun sendRateLimitEvent(
      request: GuardRequest,
      eventType: String,
      eventKwargs: Map<String, Any?>,
  ) {
    val decoratorType = eventKwargs["decorator_type"] as? String
    val reason = eventKwargs["reason"] as? String ?: ""

    if (decoratorType == "rate_limiting") {
      ChecksHelpers.emitRateLimitEvent(
          middleware,
          request,
          eventType = eventType,
          limit = eventKwargs["rate_limit"] as Int,
          window = eventKwargs["window"] as Int,
          reason = reason,
          passiveMode = config.passiveMode,
      )
      return
    }

    if (decoratorType == "geo_rate_limiting") {
      val metadata = eventKwargs.filterKeys { it != "reason" && it != "decorator_type" }
      ChecksHelpers.emitDecoratorEvent(
          middleware,
          request,
          eventType = eventType,
          actionTaken = if (!config.passiveMode) "request_blocked" else "logged_only",
          reason = reason,
          decoratorType = decoratorType,
          metadata,
      )
      return
    }

    middleware.eventBus?.sendMiddlewareEvent(
        eventType,
        request,
        if (!config.passiveMode) "request_blocked" else "logged_only",
        reason,
        eventKwargs,
    )
  }

  /** Python async `_record_rate_limit_autoban` (rate_limit.py:113). */
  private suspend fun recordRateLimitAutoban(
      request: GuardRequest,
      clientIp: String,
      triggerInfo: String,
  ) {
    if (!config.enableRateLimitAutoBan) {
      return
    }
    ChecksHelpers.incrementSuspiciousCounts(middleware, clientIp, "rate_limit")
    ChecksHelpers.tryThresholdBan(
        request,
        config,
        ipBanManager,
        middleware,
        clientIp,
        triggerInfo,
        logger,
        checkName,
        config.mutedCheckLogs,
        listOf("rate_limit"),
        reason = "rate_limit_exceeded",
    )
  }

  /** Python async `_apply_rate_limit_check` (rate_limit.py:133). */
  private suspend fun applyRateLimitCheck(
      request: GuardRequest,
      clientIp: String,
      rateLimit: Int,
      window: Int,
      eventType: String,
      eventKwargs: Map<String, Any?>,
      endpointPath: String = "",
  ): GuardResponse? {
    val result =
        rateLimitHandler.checkRateLimit(
            request,
            clientIp,
            { statusCode, defaultMessage ->
              middleware.createErrorResponse(statusCode, defaultMessage)
            },
            endpointPath = endpointPath,
            rateLimit = rateLimit,
            rateLimitWindow = window,
            config = config,
        )

    if (result != null) {
      sendRateLimitEvent(request, eventType, eventKwargs)
      if (config.passiveMode) {
        return null
      }
      recordRateLimitAutoban(request, clientIp, eventKwargs["reason"] as? String ?: "")
    }

    return result
  }

  /** Python async `_check_endpoint_rate_limit` (rate_limit.py:165). */
  private suspend fun checkEndpointRateLimit(
      request: GuardRequest,
      clientIp: String,
      endpointPath: String,
  ): GuardResponse? {
    val limitWindow = config.endpointRateLimits[endpointPath] ?: return null

    val (rateLimit, window) = limitWindow
    val safeEndpoint =
        RequestLogging.redactEndpointForDisplay(
            endpointPath,
            config.logSensitiveParams,
            config.logSensitiveBodyFields,
            config.logSensitiveHeaders,
        )
    return applyRateLimitCheck(
        request,
        clientIp,
        rateLimit,
        window,
        EventTypes.EVENT_DYNAMIC_RULE_VIOLATION,
        linkedMapOf(
            "reason" to
                "Endpoint-specific rate limit exceeded: $rateLimit requests per ${window}s " +
                    "for $safeEndpoint",
            "rule_type" to "endpoint_rate_limit",
            "endpoint" to safeEndpoint,
            "rate_limit" to rateLimit,
            "window" to window,
        ),
        endpointPath = endpointPath,
    )
  }

  /** Python async `_check_route_rate_limit` (rate_limit.py:197). */
  private suspend fun checkRouteRateLimit(
      request: GuardRequest,
      clientIp: String,
      routeConfig: RouteConfig?,
  ): GuardResponse? {
    val routeLimit = routeConfig?.rateLimit ?: return null

    val window = routeConfig.rateLimitWindow ?: 60
    return applyRateLimitCheck(
        request,
        clientIp,
        routeLimit,
        window,
        EventTypes.EVENT_DECORATOR_VIOLATION,
        linkedMapOf(
            "reason" to "Route-specific rate limit exceeded: $routeLimit requests per ${window}s",
            "decorator_type" to "rate_limiting",
            "violation_type" to "rate_limit",
            "rate_limit" to routeLimit,
            "window" to window,
        ),
        endpointPath = request.urlPath,
    )
  }

  /** Python async `_check_geo_rate_limit` (rate_limit.py:223). */
  private suspend fun checkGeoRateLimit(
      request: GuardRequest,
      clientIp: String,
      routeConfig: RouteConfig?,
  ): GuardResponse? {
    val geoRateLimits = routeConfig?.geoRateLimits
    if (routeConfig == null || geoRateLimits.isNullOrEmpty()) {
      return null
    }

    val geoHandler = config.geoIpHandler ?: return null

    val country = geoHandler.getCountry(clientIp)

    val limitWindow =
        if (country != null && country in geoRateLimits) {
          geoRateLimits[country]!!
        } else if ("*" in geoRateLimits) {
          geoRateLimits["*"]!!
        } else {
          return null
        }
    val (rateLimit, window) = limitWindow

    return applyRateLimitCheck(
        request,
        clientIp,
        rateLimit,
        window,
        EventTypes.EVENT_DECORATOR_VIOLATION,
        linkedMapOf(
            "reason" to
                "Geo rate limit exceeded for ${country ?: "unknown"}: $rateLimit requests per ${window}s",
            "decorator_type" to "geo_rate_limiting",
            "violation_type" to "geo_rate_limit",
            "rate_limit" to rateLimit,
            "window" to window,
        ),
        endpointPath = request.urlPath,
    )
  }

  /** Python async `_check_global_rate_limit` (rate_limit.py:262). */
  internal suspend fun checkGlobalRateLimit(
      request: GuardRequest,
      clientIp: String,
  ): GuardResponse? {
    val result =
        rateLimitHandler.checkRateLimit(
            request,
            clientIp,
            { statusCode, defaultMessage ->
              middleware.createErrorResponse(statusCode, defaultMessage)
            },
            rateLimit = config.rateLimit,
            rateLimitWindow = config.rateLimitWindow,
            config = config,
        )

    if (result == null) {
      return null
    }

    if (config.passiveMode) {
      return null
    }

    recordRateLimitAutoban(request, clientIp, "Global rate limit exceeded")
    return result
  }

  /** Python async `check` (rate_limit.py:287). */
  override suspend fun check(request: GuardRequest): GuardResponse? {
    if (
        request.state.getAttr("is_whitelisted") == true ||
            request.state.getAttr("is_exempt") == true
    ) {
      return null
    }

    val clientIp = request.state.getAttr("client_ip") as? String
    val routeConfig = request.state.getAttr("route_config") as? RouteConfig

    if (clientIp.isNullOrEmpty()) {
      return null
    }

    if (
        routeConfig != null &&
            middleware.routeResolver?.shouldBypassCheck("rate_limit", routeConfig) == true
    ) {
      return null
    }

    val endpointPath = request.urlPath

    checkEndpointRateLimit(request, clientIp, endpointPath)?.let {
      return it
    }

    checkRouteRateLimit(request, clientIp, routeConfig)?.let {
      return it
    }

    checkGeoRateLimit(request, clientIp, routeConfig)?.let {
      return it
    }

    return checkGlobalRateLimit(request, clientIp)
  }

  public companion object : CheckCompanion<RateLimitCheck>() {
    /** Python classmethod `applies_to` (rate_limit.py:56). */
    override fun appliesTo(
        config: SecurityConfig,
        routeConfigs: Collection<RouteConfig>?,
    ): Boolean = rateLimitApplies(config, routeConfigs)

    override val containerFields: List<String> = listOf("endpoint_rate_limits")

    override fun create(middleware: GuardMiddlewareProtocol): RateLimitCheck =
        RateLimitCheck(middleware)
  }
}
